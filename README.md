# Datadog IAST for Go

> [!NOTE]
> This project is under active development. The feature coverage is expected
> to significantly evolve, and performance characteristics of the engine are not
> stable yet.

This package provides Datadog-backed instrumentation for Interactive Application
Security Testing of Go applications. It uses `github.com/DataDog/dd-trace-go/v2`
and requires consumer applications to be compiled using
`github.com/DataDog/orchestrion`.

## Taint Tracking

Many of the functionality provided by this module relies on taint tracking:
- values (mostly `string`) obtained from untrusted _sources_ (e.g, HTTP request
  parameters) are _tainted_;
- the _taints_ are propagated as the values are combined or transformed through
  the processing of a request;
- _tainted_ values are _marked_ as they are passed through _sanitization_
  functions, as they can now be _trusted_ for certain specific operations;
- finally, when a _tainted_ value is fed into a dangerous _sink_ (e.g, an SQL
  query execution function), and no corresponding safety _mark_ has been placed,
  a _vulnerability_ is reported.

### Propagation coverage

Category | Supported operations
---|---
String windows | Every substring of a tracked value, with no instrumentation (for example the results of `Cut*`, `Split*`, `Fields*`, `Trim*`, `Lines`, and their sequence variants)
String copies and transforms | Every non-constant `+` concatenation (also `+=` and more than 16 operands), `string(b)`, `[]byte(a + b)`, `string(runes)`, and `[]rune(s)`, through runtime hooks (`iast/runtime`) in every package of the program; `Clone`, `Join`, `Repeat`, `Replace*`, case conversion, `Map`, and `ToValidUTF8`
Formatting and encoding | `fmt.Sprint*`, `net/url` escape and unescape functions, and `strconv` quote and unquote functions
Byte windows | Every subslice of a tracked value, with no instrumentation (for example two- and three-index `[]byte` slicing, `Cut*`, `Split*`, `Fields*`, and `Trim*`)
Byte copies and transforms | `[]byte(s)` through a runtime hook (see `DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED`); `Clone`, `Join`, `Repeat`, `Replace*`, case conversion, `Map`, and `ToValidUTF8`
Stateful writers | Direct `strings.Builder` and `bytes.Buffer` writes, `Grow`, `Reset`, `Truncate`, and `String`; exact current `bytes.Buffer` value copies
JSON decoding | Go 1.26 `json.Unmarshal` and `json.Decoder.Decode` string values in nested structs, arrays, slices, and typed map values, including named string types and `,string` fields

Migration note: the exported window wrappers of `iast/propagation`
(`StringsCut`, `StringsSplit*`, `StringsFields*`, `StringsTrim*`,
`StringsLines`, `BytesCut`, `BytesSplit*`, `BytesFields*`, `BytesTrim*`, and
the other wrappers that only returned a window of their input) are removed. A
direct caller must call the standard-library function on the tracked value
(for example `strings.Cut` in place of `propagation.StringsCut`). The taint
store finds the provenance of the returned windows with no wrapper. The
operator wrappers of `iast/propagation` (`Concat2` to `Concat16`,
`BytesToString`, `StringSlice*`, and `BytesSlice*`) are also removed: the
runtime hooks of `iast/runtime` and the taint store replace them. Use the Go
operators directly.

Propagation instrumentation applies to direct calls in the application root.
Calls through function or method values do not propagate input taint, except
for string and byte windows: the taint store finds the root of a window from
its data pointer. Native
`bytes.Buffer` hooks still invalidate tracked state for indirect mutations and
mutable exposure. `Bytes`, `AvailableBuffer`, and `Peek` results remain
untainted; accessing them invalidates tracked overlapping buffer views.
The runtime hooks of `iast/runtime` do not change the application source
code, so they do not change evaluation order or constant expressions. They
propagate through calls through function values and in dependencies too. When
IAST has no tainted value in the process, each hooked operation costs one
atomic load. Conversions that the Go compiler optimizes into an alias of their
input (map keys, comparisons, `switch`, ranges, and concatenation operands)
need no hook: the taint store finds the provenance of the alias from its data
pointer. `string(r)` of one rune value, one-byte conversion results, `append`,
`copy`, and direct byte index/slice assignment do not create new tainted
roots. `[]byte(s)` and `[]rune(s)` results are mutable: a later direct write is
not observed and can leave stale ranges. Supported byte-slice windows share the
parent managed root. Writes through mutable aliases retained before tracking,
or across later tracking, are not observed and can leave stale ranges. The
runtime hooks support Go 1.26 and Go 1.27; on a later Go release they stay off.
Tainted replacement terms supplied to
`strings.Replacer` are not tracked in this release. Builder value copies are not
supported.

Buffer value copies retain provenance when their backing, unread pointer,
length, and capacity match a tracked view. Before a supported direct mutation,
the existing writer entry moves to the copy without adding another entry or
byte charge. Divergent or historical views can lose provenance, as can the
original receiver after this transfer. Backing writes and mutable exposure
conservatively invalidate overlapping views, including views whose bytes the
operation does not ultimately change.

JSON string output uses coarse whole-value ranges while retaining the exact
intersecting source identity. Custom unmarshaler output, decoded byte slices,
interface values, typed map keys, and `map[string]any` keys are not propagated.
Decoder documents larger than 64 KiB safely drop provenance. Decoder tracking uses 64 process
slots with four-probe admission; excess or colliding concurrent decodes drop
provenance. Decoder state associations last only for the outer decode call and
are cleared on return or panic. Reentrant use of the same decoder can lose
outer-decode provenance.

Request body readers: `io.ReadAll` and `json.Decoder.Decode` give
request-body provenance to the bytes that they read only when the reader is
exclusive to one request. This is true for the request body, and for
`io.TeeReader`, `http.MaxBytesReader`, `io.LimitReader`,
`bufio.NewReader(Size)`, and `io.MultiReader` with 1 to 8 inputs, when all
their inputs are exclusive to the same request. `io.ReadAll` takes the owner
of its reader before the first read. `json.NewDecoder` takes the owner of its
reader when it makes the decoder, and each `Decode` checks that owner again
before it attributes a value. In the cases below, the bytes get no provenance (a
safe miss):

- `io.MultiReader` with an input that is not tracked, for example
  `io.MultiReader(strings.NewReader("prefix"), r.Body)`;
- `io.MultiReader` with more than 8 inputs;
- a reader that is not exclusive: a `bufio.Reader` of the manual helper
  `iast/bufio.Propagate`, a `bufio.Reader` or `io.LimitedReader` that got a
  new input after its construction (for example `Reset`), a wrapper that got
  no `Read` guard (more than 128 guarded wrappers at the same time), and a
  reader that a different request also tracked, also after that request
  finished;
- a reader that a concurrent operation locks while `io.ReadAll` or a
  `json.Decoder` checks it;
- a reader that gets its request binding (or a second request) after
  `io.ReadAll` started or after `json.NewDecoder` made the decoder;
- a `json.Decoder` that `json.NewDecoder` made while no request was active;
- all the values of a `json.Decoder` after one failed check (for example one
  locked check, or a retargeted input): the decoder never gives provenance
  again.

Before this release, the Go 1.26 `json.Decoder` gave provenance to each
request that tracked its reader at `Decode` time, also for a reader that was
not exclusive (for example `io.MultiReader(bodyA, bodyB)` of two requests, or
`io.MultiReader(bytes.NewReader(prefix), r.Body)`). These cases are now safe
misses. A decoder that is used again by a later request gives provenance only
to the request whose reader it read, while that request is active.

Known limit: do not copy a `bufio.Reader` by value. If code copies a
`bufio.Reader`, then resets and reads the copy, the two values share one
buffer. Then IAST can attribute the bytes of the new reader of the copy to the
request of the original reader.

Tracking a stateful writer uses a strong request-bounded receiver anchor. This
can make a stack receiver escape. Writer state is limited to eight receivers per
request owner, four owners per receiver, and 64 KiB of charged visible capacity.
The byte budget does not bound all memory retained through these anchors. A
buffer can refer to a short slice of a larger allocation, and a bound reader can
retain other readers and their data. The number of these references is bounded,
and they are released when the tracking owner ends. Their full retained size is
not known. This is an accepted trade-off to preserve useful taint propagation.

### Sink coverage

Category | Supported operations
---|---
SQL injection | Go 1.26 `database/sql` prepare, execute, query, prepared-statement, and delegated `QueryRow` operations on `DB`, `Conn`, `Tx`, and `Stmt`
Command injection | Process attempts made by `exec.Cmd.Start`, including `Run`, `Output`, and `CombinedOutput`

SQL parameters are not query evidence. Command construction alone does not
report a vulnerability; reporting occurs only after an `os.StartProcess`
attempt. Sink callback registration is injected into executable `main`
packages in the root module; plugin, library, and non-root executable builds do
not activate these request-scoped sinks. Sink evidence is limited to 32 KiB
before conservative redaction, and the encoded vulnerability event is limited
to 25,000 bytes.

When no traced span is available, each tainted report creates a separate orphan
event. In that case, `DD_IAST_VULNERABILITIES_PER_REQUEST` limits each event but
does not limit the total findings from one request.

### Request isolation

More than one request can share one value (for example, a cached string that
two requests use). A report contains the ranges, sources, and evidence of one
request only: the request of the sink context. When the sink context has no
request, one request is selected in a fixed order. The bytes of the other
requests (also bytes that are safe for the vulnerability type) are shown only
as redaction markers (`*`), also when redaction is disabled. Bytes that are in
a range of the reported request are not masked, also when a range of a
different request has the same bytes: these bytes come from a source value of
the reported request. An event gets the reports of one request only; when a
span event has the reports of a different request, the report goes to an
orphan event. Report deduplication (by vulnerability type and location) is
process-wide, so a report of one request can remove the same report of a
different request.

Known limit: a redaction marker has one `*` for each masked byte. Thus a report
shows that a different request has data in the value, and the length and
position of this data. It does not show the data.

Known limit: when a different request finishes before the report is made, its
taint is not tracked any more. Its bytes are then shown as untainted text, like
any other untainted text in the value (for example, a value read from a
database).

`taint.VisitString` and `taint.VisitBytes` take a `context.Context`. They visit
only the ranges of the request of this context, and return `false` when the
context has no active request analysis.

## Cost Control

Taint tracking has non-trivial associated cost; both in terms of memory and
time. This package makes all efforts possible to minimize the associated
overhead; and a Cost Control Engine is used to ensure the overall operating cost
of IAST in your applications can remain within acceptable parameters. In
particular, taint tracking is subject to a sampling decision.

## Runtime Configuration

Configuration is read from environment variables when the package is initialized.
Malformed values produce a warning and fall back to the documented default.
Integer values outside a documented range are clamped to that range.

Environment variable | Type | Default | Description
---|---|---:|---
`DD_IAST_ENABLED` | Boolean | `true` | Enables IAST.
`DD_IAST_REQUEST_SAMPLING` | Integer from `0` to `100` | `30` | Percentage of requests sampled for IAST analysis.
`DD_IAST_MAX_CONCURRENT_REQUESTS` | Integer from `0` to `64` | `2` | Maximum number of requests that IAST processes concurrently; `0` disables request analysis.
`DD_IAST_VULNERABILITIES_PER_REQUEST` | Integer greater than or equal to `1` | `2` | Maximum number of vulnerabilities reported for one request.
`DD_IAST_DEDUPLICATION_ENABLED` | Boolean | `true` | Enables vulnerability deduplication.
`DD_IAST_REDACTION_ENABLED` | Boolean | `true` | Enables sensitive data redaction.
`DD_IAST_REDACTION_NAME_PATTERN` | `regexp` regular expression | Sensible built-in pattern | Pattern used to identify source names that must be redacted. Falls back to the compatibility alias `DD_IAST_REDACTION_KEYS_REGEXP` when unset.
`DD_IAST_REDACTION_VALUE_PATTERN` | `regexp` regular expression | Sensible built-in pattern | Pattern used to identify source values that must be redacted. Falls back to the compatibility alias `DD_IAST_REDACTION_VALUES_REGEXP` when unset.
`DD_IAST_TRUNCATION_MAX_VALUE` | Non-negative integer | `250` | Maximum number of Unicode characters retained before truncating source values, vulnerability evidence, redacted patterns, and individual evidence value parts.
`DD_IAST_MAX_RANGE_COUNT` | Integer from `1` to `64` | `10` | Maximum number of taint ranges retained for one value.
`DD_IAST_TELEMETRY_VERBOSITY` | `OFF`, `MANDATORY`, `INFORMATION`, or `DEBUG` | `INFORMATION` | Sets IAST telemetry verbosity.
`DD_IAST_DB_ROWS_TO_TAINT` | Non-negative integer | `1` | Number of database rows tainted for each request.
`DD_IAST_STACK_TRACE_ENABLED` | Boolean | `true` | Includes stack traces in vulnerability reports.
`DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED` | Boolean | `true` | Propagates taint through `[]byte(s)` and `[]rune(s)` conversions. The results are mutable, so a later direct write can leave stale taint.

> [!NOTE]
> Boolean values are parsed using [`strconv.ParseBool`](https://pkg.go.dev/strconv#ParseBool),
> which accepts the following values:
> - Truthy: `1`, `t`, `T`, `TRUE`, `true`, `True`
> - Falsy: `0`, `f`, `F`, `FALSE`, `false`, `False`

## Vulnerability Types

Name | Severity | Implemented
---|---|:---:
Admin console active | Low | :x:
Code injection | High | :x:
Command injection | Critical | :white_check_mark: `github.com/DataDog/dd-iast-go/iast/os/exec`
Default application deployed | Low | :x:
Default HTML escape invalid | High | :x:
Directory listing leak | High | :x:
Email HTML injection | Medium | :x:
Hardcoded password | High | :x:
Hardcoded secrets | High | :x:
Header injection | High | :x:
HSTS header missing | Low | :x:
Insecure auth protocol | Medium | :x:
Insecure cookies | Low | :x:
Insecure JSP layout | Medium | :x:
LDAP injection | High | :x:
MongoDB injection | Critical | :x:
No `HttpOnly` cookie | Low | :x:
No `SameSite` cookie | Low | :x:
Path traversal | High | :x:
Reflection injection | Medium | :x:
Server-side request forgery | Critical | :x:
Session rewriting | Medium | :x:
Session timeout | Low | :x:
SQL injection | Critical | :white_check_mark: `github.com/DataDog/dd-iast-go/iast/database/sql`
Stacktrace leak | Medium | :x:
Template injection | High | :x:
Trust boundary violation | High | :x:
Untrusted deserialization | Medium | :x:
Un-validated redirect | High | :x:
Verb tampering | High | :x:
Weak cipher | Medium | :white_check_mark: `github.com/DataDog/dd-iast-go/iast/crypto/cipher`
Weak hash | Medium | :white_check_mark: `github.com/DataDog/dd-iast-go/iast/crypto/hash`
Weak randomness | Low | :x:
`X-Content-Type-Options` header missing | Low | :x:
`X-XSS-Protection` header disabled | Low | :x:
XPath injection | High | :x:
Cross-Site Scripting | High | :x:

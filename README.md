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
String windows | `Cut*`, `Split*`, `Fields*`, `Trim*`, `Lines`, and their sequence variants
String copies and transforms | `Clone`, `Join`, `Repeat`, `Replace*`, case conversion, `Map`, and `ToValidUTF8`
Formatting and encoding | `fmt.Sprint*`, `net/url` escape and unescape functions, and `strconv` quote and unquote functions
Byte windows | `Cut*`, `Split*`, `Fields*`, and `Trim*`
Byte copies and transforms | `Clone`, `Join`, `Repeat`, `Replace*`, case conversion, `Map`, and `ToValidUTF8`
Stateful writers | Direct `strings.Builder` and `bytes.Buffer` writes, `Grow`, `Reset`, `Truncate`, and `String`
JSON decoding | Go 1.26 `json.Unmarshal` and `json.Decoder.Decode` string values in nested structs, arrays, slices, and typed map values

Propagation instrumentation applies to direct calls in the application root.
Calls through function or method values are not supported. A later direct writer
call validates the current receiver shape and drops stale provenance. Mutable
`bytes.Buffer.Bytes` and `AvailableBuffer` results remain untainted; accessing
them invalidates tracked buffer state. Tainted replacement terms supplied to
`strings.Replacer` are not tracked in this release. Builder and buffer value
copies, and aliases that share backing memory without the same receiver, can
only lose provenance and never publish unchecked provenance.

JSON string output uses coarse whole-value ranges while retaining the exact
intersecting source identity. Custom unmarshaler output, decoded byte slices,
interface values, typed map keys, and `map[string]any` keys are not propagated. Decoder documents
larger than 64 KiB safely drop provenance. Decoder tracking uses 64 process
slots with four-probe admission; excess or colliding concurrent decodes drop
provenance. Reentrant use of the same decoder can lose outer-decode provenance.

Tracking a stateful writer uses a strong request-bounded receiver anchor. This
can make a stack receiver escape. Writer state is limited to eight receivers per
request owner, four owners per receiver, and 64 KiB of charged visible capacity.

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

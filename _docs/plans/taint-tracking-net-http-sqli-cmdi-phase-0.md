# Phase 0 results: Go taint tracking

## Status

- **Toolchain:** `GOTOOLCHAIN=go1.26.6`
- **Orchestrion:** 1.12.2
- **State:** Phase 0 checkpoint approved; Phase 1 range/source implementation is authorized
- **Related plan:** [taint-tracking-net-http-sqli-cmdi.md](./taint-tracking-net-http-sqli-cmdi.md)
- **Removal:** delete this file with the related plan after implementation is accepted

Phase 0 did not validate the complete original design. It found two blocking
issues:

1. runtime hooks cannot implement concat or conversion propagation with
   Orchestrion 1.12.2, and the source-expression prototypes do not meet the
   original percentage-only performance gates;
2. an exact `net/http.serverHandler` receiver match makes Orchestrion 1.12.2
   recursively inspect the package that it is compiling and does not complete.

The user approved the revised choices in
[Checkpoint decisions](#checkpoint-decisions). Production aspects remain gated
by their later phase-specific reviews and benchmarks.

## Result summary

| Area | Result | Decision or blocker |
|---|---|---|
| Pointer safety | Pass | Use managed strong roots. Never use data-pointer weak handles or cleanups. |
| Address reuse | Pass | A process-global `uintptr`-only identity map is unsound. |
| Bounded store shape | Conditional pass | Use lazy generation-based cleanup, after the reviewed counter and compaction corrections. |
| Byte provenance shape | Conditional pass | Store canonical ranges in root-relative coordinates and derive value windows. The first per-window prototype was rejected. |
| Runtime concat/conversion hooks | Fail | Result values are not observable with current advice; gates and allocations also fail. |
| Source-expression concat/conversion | Semantic pass, gate fail | Correct semantics and allocation count; original relative overhead gates fail. |
| Slicing source expression | Semantic pass, gate fail | No runtime alternative exists. The absolute overhead is about 1 ns, but the relative overhead is about 100% for a 1 ns microbenchmark. |
| HTTP lifecycle source inspection | Pass | All server paths converge as expected; no tracer aspect creates the server span first. |
| Exact HTTP lifecycle aspect | Fail | Exact receiver matching does not complete. A broad fixture proved ordering but is not the production matcher. |
| Reader provenance | Partial pass | Constructor bindings and `io.ReadAll` are viable. `bytes.Buffer.ReadFrom` needs a post-call allocation/escape benchmark. |
| SQL sink boundaries | Boundary confirmed | Proposed DB, Tx, Conn, and Stmt boundaries exist above retries. Report, redaction, and payload fixtures were not validated. |
| Command sink boundary | Boundary confirmed | `os.StartProcess` remains the post-validation boundary in `Cmd.Start`. Report and payload fixtures were not validated. |
| Redaction choice | Open | `go-sqllexer` is viable, but the shared corpus comparison is still required. |
| Payload limit | Open | Java evidence supports 25,000 UTF-8 bytes and `MAX_SIZE_EXCEEDED`; backend approval is not available in this environment. |

## 1. Runtime and pointer evidence

### 1.1 Confirmed facts

The probes confirmed these Go 1.26.6 properties:

- heap allocations can reuse the same numeric address after collection;
- non-escaping stack operations reuse stack addresses;
- equal one-byte literals share backing memory;
- small `strconv.Itoa` results use shared static backing;
- one-byte `[]byte` to string conversion uses `runtime.staticuint64s`;
- `unsafe.StringData("")` is nil;
- a zero-capacity non-nil slice can use a non-heap zero base;
- `weak.Make(unsafe.StringData(literal))` can cause the unrecoverable
  `getWeakHandle on invalid pointer` runtime throw;
- `runtime.AddCleanup` can panic for read-only static data;
- storing an interior `unsafe.Pointer` retained the complete 1 MiB parent;
- storing the same interior address as `uintptr` did not retain the parent.

The safe retention probe passed with the race detector and
`-gcflags=-d=checkptr=2`.

Phase 0 did not complete the separate positive measurement in which many
substrings retain and charge one bounded managed root. That measurement remains
a required Phase 2 store test.

### 1.2 Direct design consequences

- Do not track empty or one-byte values in the first version.
- Clone every source value before identity registration.
- Use `uintptr` only for comparison while a separately charged root anchor keeps
  the complete allocation alive.
- Never convert a stored `uintptr` back to a pointer.
- Never call `weak.Make` or `runtime.AddCleanup` on a pointer obtained from
  string data, slice data, reflection, an interface data word, or `uintptr`.
- Validate that every value window is inside its named root using checked
  arithmetic.

### 1.3 Reproduction

The retained-parent probe is preserved in the Phase 0 work area and used this
command:

```console
cd /tmp/p0probe
GOTOOLCHAIN=go1.26.6 go build -race -gcflags='-d=checkptr=2' -o interior_race .
./interior_race baseline
./interior_race uintptr
./interior_race ptr
```

Typical retained-heap deltas were about 10-20 KiB for baseline/`uintptr` and
about 1.06 MiB for the interior `unsafe.Pointer`.

## 2. Bounded store result

### 2.1 Selected lifecycle direction

The eager-handle prototype was rejected. It used 2 MiB of fixed owner handles
and took about 57 microseconds to finish a saturated 4,096-entry owner.

The selected direction is lazy cleanup:

1. A write takes an owner lifecycle `TryRLock`, validates the captured owner
   generation, then uses a shard `TryLock`.
2. `Finish` changes the exact owner generation to terminal state, takes the
   lifecycle write lock to drain writes, releases every strong root, reconciles
   bounded counters, and returns. It does not scan value slots.
3. Value slots contain no strong root. Lookups reject dead or stale owner/root
   generations under a shard `TryRLock`.
4. Later writes reclaim stale slots encountered within the fixed probe bound.
5. Foreign-owner counter transfer takes that owner's lifecycle `TryRLock` and
   rechecks state/generation. It skips reclamation under contention.
6. Bounded shard compaction builds a candidate layout first. It commits only if
   every live entry remains reachable within the 64-slot probe bound.
7. Compaction excludes only entries known dead at candidate-build time. This
   prevents freeing a range block that a concurrently finishing owner leaves in
   the candidate.

The corrected prototype passed:

```console
cd /tmp/taintstore-lazy
GOTOOLCHAIN=go1.26.6 go vet .
GOTOOLCHAIN=go1.26.6 go test -race -count=1 .
GOTOOLCHAIN=go1.26.6 go test -race -count=20 \
  -run 'Test(Review|Race|Lazy|ABA|RangePool|Process)' .
GOTOOLCHAIN=go1.26.6 go test -run '^TestChurn_SteadyState$' .
```

The added regression tests cover:

- range-block double-free during compaction;
- layouts that cannot preserve the probe bound;
- foreign reclamation racing with finish and owner reuse;
- concurrent root-header reads and in-place append updates;
- concurrent range-pool allocation;
- current-generation quota reset across more than 256 mutations.

### 2.2 Provisional hard bounds

| Limit | Proposed value |
|---|---:|
| Active owners | 64 |
| Shards | 256 |
| Slots per shard | 128 |
| Probe limit | 64 |
| Process value entries | 16,384 |
| Request value entries | 4,096 |
| Roots per owner | 512 |
| Values per root generation | 256 |
| One root | 64 KiB |
| Request charged roots | 2 MiB |
| Process charged roots | 8 MiB |
| Sources per request | 256 |
| Object bindings per request | 256 |
| Inline ranges per prototype value | 4 |
| Ranges guaranteed per admitted production value | 10 |
| Configured range default | 10 |
| Hard configured ranges per value/root | 64 |
| Prototype process-wide 64-range overflow blocks | 256 |

The current lazy prototype uses approximately 6.9 MiB of fixed value, owner, and
range storage and at most 8 MiB of charged root backing. Its calculated
subsystem bound is near 14.9 MiB plus allocator metadata. This number does
**not** include the source table, object-binding table, deduplication storage,
or the final root-relative range layout.

The prototype's 256-block pool lets only 256 values hold more than four ranges.
That prototype policy is rejected for production. Production must provide ten
ranges for every value admitted under the 16,384-entry process cap. Values may
use bounded best-effort overflow storage from range 11 through the hard
configured maximum of 64. On exhaustion, keep the earliest ranges in output
order, drop the tail, and increment telemetry.

With the prototype's 24-byte range representation, six additional ranges for
all 16,384 admitted values require about 2.25 MiB. Replacing the prototype pool
with a ten-range guaranteed pool plus a small best-effort overflow pool would
put the current subsystem estimate near 17.1 MiB. The final root-relative layout
can change this figure.

The approved whole-feature hard ceiling is 24 MiB. Phase 2 must calculate the
complete total from actual type sizes and measure retained heap and allocator
rounding before production aspects can be enabled.

A saturated finish is sub-microsecond when no writer is active. The final
benchmark must also report finish latency percentiles while writers hold the
lifecycle read lock.

### 2.3 Cross-language capacity comparison

Public tracer source was compared at these revisions:

- Java `DataDog/dd-trace-java@703558ce`: 33% sampling, four concurrent
  requests, two vulnerabilities per request, ten ranges per value, and a
  16,384-bucket per-request map with a ten-object bucket limit. A later
  collision replaces the bucket chain and loses older taint.
- .NET `DataDog/dd-trace-dotnet@40c7ba16`: 30% sampling, two concurrent
  requests, two vulnerabilities per request, ten ranges per value, and a
  16,384-bucket map that changes to overwrite mode after 8,192 entries.
- Python `DataDog/dd-trace-py@6ba985e2`: 30% sampling, two concurrent requests,
  two vulnerabilities per request, and 30 ranges per value. Request maps are
  native hash maps without an object-count cap found in public source; the
  native active-context array has a hard limit of 1,024.
- Public PHP and Ruby tracers do not implement IAST taint tracking.

Go already defaults to 30% sampling, two concurrent requests, two
vulnerabilities per request, ten ranges, 250-character evidence truncation, and
one database row to taint. This matches .NET and is close to Java. Go needs a
stronger explicit byte ceiling because it cannot safely use arbitrary weak
references and must retain managed cloned roots. The 24 MiB ceiling is therefore
a Go-specific hard bound, not a copied cross-language allocation target.

### 2.4 Required production changes

The prototype still contains placeholder byte mutation semantics. Production
must:

- keep canonical byte provenance in root-relative coordinates;
- use value entries as bounded `(root, offset, length, generation)` windows;
- reset the per-root quota on a generation change without decrementing it when
  an older generation is reclaimed;
- reserve all replacement slots/ranges before publishing a new root generation;
- on reservation or contention failure, invalidate and drop the affected taint
  instead of publishing partial or fabricated provenance;
- guarantee ten ranges for every admitted value and use bounded best-effort
  storage for configured limits from 11 through 64;
- clamp `DD_IAST_MAX_RANGE_COUNT` to `[1, 64]`; the current unbounded loader does
  not yet enforce the approved hard ceiling;
- keep process/request counters as bounded physical-slot counts until reclaim or
  finish;
- use a fixed or caller-owned snapshot buffer; no lookup allocation;
- count one-byte exclusions, contention, capacity, stale-owner races, and
  compaction aborts.

## 3. Range and byte-operation evidence

The first byte-range prototype was rejected after review. The important findings
are retained as Phase 1 requirements:

- source ID `0` is valid;
- overlap resolution is first input provenance, not earliest range start;
- tests must feed raw overlapping input independently to the oracle; they must
  not canonicalize with the implementation under test;
- append preserves destination ranges and shifts the actual appended source
  ranges by the old length;
- copy uses a pre-copy source snapshot, including overlapping self-copy;
- index assignment removes only the written byte's provenance; scalar byte
  provenance is not supported yet;
- root generation is only a staleness marker, never the provenance itself;
- mutation updates canonical root ranges once, then all sibling windows derive
  their ranges from root offsets;
- exact operations preserve secure marks; coarse operations intersect marks;
- invalid input drops the whole result and is distinct from deterministic tail
  dropping at the range cap;
- `Mark`, `UnsafeFor`, coarse propagation, slicing, and a greater-than-64-range
  oracle case are mandatory before Phase 1 exits.

The rejected prototype remains useful only for its verified Go `copy` overlap
semantics and as negative evidence. It must not be copied into production.

## 4. Operator propagation decision

### 4.1 Runtime hooks are rejected

An actual woven fixture targeted:

- `runtime.concatstrings`;
- `runtime.slicebytetostring`;
- `runtime.stringtoslicebyte`.

Orchestrion 1.12.2 can prepend an input callback, but it cannot observe these
functions' unnamed result values. It has no return-expression advice and cannot
rename return values. A proof fixture fails with:

```text
<generated>:3: undefined: result
```

The gate-only concat hook also made the small `[]string{...}` input to
`concatstring2` and `concatstring4` escape, adding an allocation even while the
gate was disabled. Runtime hooks are therefore rejected independently of the
result-capture blocker.

The fixture used plain shared gate loads, not atomic loads. Its overhead is a
lower bound and its concurrent gate update would race. This correction makes
runtime hooks less favorable; it does not change the rejection.

Reproduction:

```console
cd /tmp/p0work
GOTOOLCHAIN=go1.26.6 go test ./sigcheck ./early ./taintcb
GOTOOLCHAIN=go1.26.6 go tool orchestrion go test ./early ./taintcb ./sigcheck
# Result-capture blocker:
cd /tmp/p0blocker
GOTOOLCHAIN=go1.26.6 go tool orchestrion go build .
```

### 4.2 Source expressions preserve semantics but fail the original gates

The source IIFE shape evaluates operands once, preserves source order and panic
behavior, preserves defined result types, and has the same allocation count as
the original operation. It places active/no-entry checks before active
propagation.

The preserved fixture is `/tmp/taintprobe`; its `REPORT.md`, `bench.txt`, and
`bench2.txt` contain the complete samples. Reproduction:

```console
cd /tmp/taintprobe
GOTOOLCHAIN=go1.26.6 go build ./...
GOTOOLCHAIN=go1.26.6 go test ./shapes -run Test -v
GOTOOLCHAIN=go1.26.6 go test ./shapes -bench=Benchmark \
  -benchmem -count=10 -benchtime=300ms -run='^$'
GOTOOLCHAIN=go1.26.6 go build -gcflags='-m -m' ./shapes
```

The fixture measured these disabled-path medians:

| Operation | Original | Source IIFE | Delta | Original gate |
|---|---:|---:|---:|---|
| Concat 2 | 19.0 ns | 20.0 ns | 1.0 ns / 5.3% | Fail |
| Concat 4 | 27.0 ns | 30.5 ns | 3.5 ns / 13.0% | Fail |
| Concat 6 | 33.0 ns | 36.0 ns | 3.0 ns / 9.1% | Fail |
| String conversion | 9.0 ns | 11.0 ns | 2.0 ns / 22.2% | Fail |
| Slice | 1.0 ns | 2.0 ns | 1.0 ns / 100% | Fail |

The table reports the medians selected in `REPORT.md` from `bench2.txt`. The
independent `bench.txt` run reversed the apparent Concat 16 and defined-type
Concat 4 wins: Concat 16 changed from 76.5 to 85.0 ns, and defined-type Concat 4
changed from 26.0 to 29.0 ns. Concat 16 active-untainted also changed from 76.5
to 98.5 ns in that run. Machine noise is therefore larger than the candidate
gate for these forms, and the at-or-above-80-ns gate is not validated by this
prototype.

The added allocations remained zero for every tested form. The IIFE wrapper did
not inline for the failing small forms because its inline cost exceeded the
compiler budget. These results are prototype evidence, not a prediction that
every generated expression will have the same cost.

Slicing has no runtime success-path helper. Go 1.26.6 lowers slice and string
slice expressions directly to bounds checks plus `ssa.OpSliceMake` or
`ssa.OpStringMake` in `cmd/compile/internal/ssagen/ssa.go:3646-3679`. The
original slice disassembly has no success-path call. A source expression is the
only available callback mechanism.

### 4.3 Required Orchestrion work

Add these typed join points or equivalent transforms:

- built-in call, validated through `go/types.Info.Uses` and `*types.Builtin`;
- maximal string-concat chain;
- string/byte slice expression;
- string/byte conversion, excluding the `RangeStmt` temporary conversion.

The concat join point must expose a flattened operand list in source order so a
`wrap-expression` template can use `{{ range }}`. The slice and conversion
transforms must preserve defined destination types.

The current plan's percentage-only microbenchmark gate cannot be met for a
1 ns slice by any runtime active check. A revised gate needs an absolute clause
for very small operations while retaining allocation, end-to-end latency, and
soak limits.

## 5. HTTP lifecycle and reader provenance

### 5.1 Static lifecycle result

Go 1.26.6 source confirms:

- HTTP/1 calls `serverHandler.ServeHTTP` at `net/http/server.go:2067`;
- h2c delegates through `unencryptedHTTP2Request` at lines 2127 and 2174;
- TLS HTTP/2 delegates through `initALPNRequest` at lines 1945 and 3971;
- all paths reach `serverHandler.ServeHTTP` at line 3300;
- request context is installed at line 1034 before dispatch;
- the pinned tracer has no generic standard-library handler-body aspect that
  creates a span before this boundary.

The owner must therefore make the sampling/capacity decision before a span and
bind that same decision when `tracer.StartSpanFromContext` later runs.

### 5.2 Empirical ordering result

The exact `receiver: net/http.serverHandler` function matcher does not complete
when Orchestrion compiles `net/http`; its type resolver recursively invokes a
`go list`/compile of the package under compilation. The production aspect needs
a syntactic local-receiver matcher (or another non-recursive exact matcher)
before Phase 4.

A broader Phase 0 fixture matched `ServeHTTP` bodies in `net/http`, used a cheap
context reuse check, and separately instrumented `StartSpanFromContext`. It
proved this runtime order for HTTP/1, TLS HTTP/2, and h2c:

```text
OWNER-BEGIN
OWNER-REUSE for nested standard handlers
SPAN-BIND StartSpanFromContext
OWNER-REUSE for later nested handlers
OWNER-FINISH
```

It also proved:

- two nested tracing middlewares keep one owner and bind twice to that owner;
- panic unwinding runs owner finish;
- a direct application handler can create and finish a fallback owner;
- an h2c client can observe the response before the handler defer is visible to
  the test; closing the idle connection before the snapshot made finish
  observable.

The h2c observation does not prove that the owner lasts for the connection. The
exact source boundary is per request, but Phase 4 must test owner permit release
without depending on connection close. With only 64 permits, a connection-bound
owner would be a release blocker.

The probe exposed an advice-scoping requirement. `prepend-statements` places
advice in a generated block. This is wrong:

```go
req, owner := begin(req) // shadows req inside the generated block
```

Use this shape:

```go
managedReq, owner := begin(req)
req = managedReq
 defer finish(owner)
```

The fallback aspect must exclude all `dd-iast-go` callback packages. A fixture
that instrumented its own fallback callback recursed until stack overflow.

Reproduction used a copied checkout under `/tmp/p0dd`:

```console
cd /tmp/p0dd
GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -v \
  ./testbed/p0probe ./testbed/p0app
```

The broad fixture is evidence for ordering only. It is not the selected
production aspect because it instruments every standard-library `ServeHTTP`
body.

### 5.3 Reader matrix

| API | Phase 0 result |
|---|---|
| `io.LimitReader` | Bind returned `*io.LimitedReader` to input owners. |
| `io.TeeReader` | Bind returned reader to input owners; never bind the writer. |
| `io.MultiReader` | Snapshot the bounded union of input owners at construction. |
| `bufio.NewReader*` | Bind returned `*bufio.Reader`; direct caller-buffer reads remain unsupported. |
| `http.MaxBytesReader` | Bind returned read-closer to input owners. |
| `io.ReadAll` | Call-site wrapper can adopt the complete returned allocation and charge `cap(result)`. Indirect calls are not covered. |
| `bytes.Buffer.ReadFrom` | Feasible in principle, but not proved. A function-body defer can inspect private `b.buf`, `b.off`, old length, and final capacity. It must preserve existing ranges and taint only bytes read from the bound reader. |

`io.ReadAll` does not always return a right-sized slice. If it completes before
creating chunks, it returns its complete growth buffer. Adoption is still safe
because the result starts at that allocation's base; charge capacity, not only
length.

Buffer reuse after owner finish is not a persistent-taint blocker: finish
removes the owner roots and entries. The remaining blockers for
`bytes.Buffer.ReadFrom` are allocation escape, capacity charging, private-state
hooking, and range preservation. Defer it until those benchmarks pass; use
`io.ReadAll` for the first body vertical slice.

## 6. Sink and report evidence

### 6.1 SQL

Go 1.26.6 confirms all proposed exported boundaries:

- DB: `PrepareContext`, `ExecContext`, `QueryContext`;
- Tx: `PrepareContext`, `ExecContext`, `QueryContext`;
- Conn: `PrepareContext`, `ExecContext`, `QueryContext`;
- Stmt: `ExecContext`, `QueryContext`.

Non-context and row wrappers delegate to these methods. DB retry loops are
inside the exported methods, so a function-body check runs once per application
call. `Stmt.query` remains available inside `database/sql`.

### 6.2 Command

`(*exec.Cmd).Start` calls `os.StartProcess` at `os/exec/exec.go:733`, after
validation and path resolution. `Run`, `Output`, and `CombinedOutput` converge
there. The lexical call-site aspect remains the selected boundary.

### 6.3 Open report-format decisions

- `go-sqllexer` compiled and produced useful structural tokens, but it must not
  be selected until it matches the shared redaction corpus.
- The Go code has no 25,000-byte event guard today.
- Public Java evidence supports UTF-8 byte counting and
  `MAX_SIZE_EXCEEDED`, but the backend contract could not be confirmed.
- Internal Confluence and Drive searches were unavailable because MCP OAuth was
  not authorized in this session.
- Public Java, .NET, Python, PHP, and Ruby tracer source was compared after the
  local sibling checkouts proved unreadable in this sandbox.

## 7. Checkpoint decisions

The user approved these decisions:

1. **Operator performance:** source-generated operators below 80 ns may add at
   most 4 ns on disabled and active-untainted paths; operations at or above
   80 ns retain the 5% gate. Added allocations remain forbidden. The 2%
   unsampled end-to-end request gate and soak limits remain unchanged. This
   policy does not pre-approve generated aspects.
2. **HTTP lifecycle:** all standard HTTP/1, TLS HTTP/2, and h2c paths reach
   `net/http.serverHandler.ServeHTTP` once per request. Add an exact syntactic
   receiver matcher and use the outer-handler fallback only for direct/custom
   dispatch. The Orchestrion schema still needs its separate user review.
3. **Store capacity:** use a 24 MiB whole-feature ceiling and guarantee ten
   ranges for every admitted value. Use bounded best-effort overflow storage up
   to the hard configured limit of 64, then drop the range tail with telemetry.
4. **Phase 0 deferrals:** require `io.ReadAll` in the first body vertical slice;
   keep `bytes.Buffer.ReadFrom` conditional on its dedicated benchmark; move the
   many-substrings retained-heap proof to Phase 2; and move report, redaction,
   payload, backend, and cross-tracer compatibility validation to Phase 7a.

Phase 6 must measure generated operator forms with at least 20 samples and a
1-second benchmark time on an idle machine. It must report unrounded values,
allocations, `benchstat` 95% confidence intervals, and a paired-bootstrap 95%
upper bound for the absolute delta. Both the point estimate and upper bound must
meet the selected gate. The contradictory Concat 16 samples mean the
at-or-above-80-ns arm remains unvalidated.

## 8. Phase exit assessment

Phase 0 is approved. Phase 1 pure range/source work may start. This approval
does **not** authorize operator aspects, HTTP source aspects, Orchestrion schema
implementation, or sink/report implementation.

Carried-forward obligations are:

1. Phase 1 implements and reviews pure root-relative range algebra and the
   bounded source table under the approved memory/range policy.
2. The lazy store is rebuilt against that algebra and re-benchmarked before
   Phase 2 exits. Phase 2 must prove that many substrings charge and retain one
   managed root and that retained heap stays below the 24 MiB ceiling.
3. Orchestrion join-point schemas require the original plan's separate user
   checkpoint before upstream implementation.
4. Phase 4 must prove per-request h2c owner release without connection-close
   dependence.
5. Phase 7a must complete report, redaction, payload, backend, and cross-tracer
   compatibility validation before sink/report production code is enabled.

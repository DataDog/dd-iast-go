# Phase 0 results: Go taint tracking

## Status

- **Toolchain:** `GOTOOLCHAIN=go1.26.6`
- **Orchestrion:** 1.12.2
- **State:** evidence complete; implementation is paused at the required user checkpoint
- **Related plan:** [taint-tracking-net-http-sqli-cmdi.md](./taint-tracking-net-http-sqli-cmdi.md)
- **Removal:** delete this file with the related plan after implementation is accepted

Phase 0 did not validate the complete original design. It found two blocking
issues:

1. runtime hooks cannot implement concat or conversion propagation with
   Orchestrion 1.12.2, and the source-expression prototypes do not meet the
   original percentage-only performance gates;
2. an exact `net/http.serverHandler` receiver match makes Orchestrion 1.12.2
   recursively inspect the package that it is compiling and does not complete.

Implementation must not start until the user selects the revised choices in
[Decisions required](#decisions-required).

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
| Hard ranges per value/root | 64 |
| Process-wide 64-range overflow blocks | 256 |

The current lazy prototype uses approximately 6.9 MiB of fixed value, owner, and
range storage and at most 8 MiB of charged root backing. Its measured subsystem
total is near 14.9 MiB plus allocator metadata. This number does **not** include
the source table, object-binding table, deduplication storage, or the final
root-relative range layout.

Only 256 values process-wide can hold more than four ranges in the prototype.
When that pool is empty, the prototype keeps the first four accurate ranges and
drops later ranges. It increments a drop counter; it does not fabricate
provenance. Production must measure this precision cliff under concurrency and
must not add an unbounded sweep or allocation to avoid it.

The proposed whole-feature hard ceiling is 24 MiB, including the measured
14.9 MiB subsystem and 9.1 MiB of layout headroom. Phase 2 must calculate the
complete total from actual type sizes before production aspects can be enabled.

A saturated finish is sub-microsecond when no writer is active. The final
benchmark must also report finish latency percentiles while writers hold the
lifecycle read lock.

### 2.3 Required production changes

The prototype still contains placeholder byte mutation semantics. Production
must:

- keep canonical byte provenance in root-relative coordinates;
- use value entries as bounded `(root, offset, length, generation)` windows;
- reset the per-root quota on a generation change without decrementing it when
  an older generation is reclaimed;
- reserve all replacement slots/ranges before publishing a new root generation;
- on reservation or contention failure, invalidate and drop the affected taint
  instead of publishing partial or fabricated provenance;
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
- Cross-tracer source repositories were visible but not readable in this
  sandbox.

## 7. Decisions required

Each item below is an explicit checkpoint question. No recommendation is an
authorization to implement the related production aspect.

### 7.1 Operator performance gate

**Question:** which gate should replace the original percentage-only gate?

- **Recommended:** provisionally require zero added allocations and no more than
  4 ns absolute disabled and active-untainted overhead for source-generated
  operators below 80 ns; retain 5% for operations at or above 80 ns. Four
  nanoseconds covers the stable low-arity prototype deltas up to 3.5 ns, while
  the report's suggested 2 ns would reject Concat 4 and Concat 6. Retain the 2%
  unsampled end-to-end request gate and soak limits. This threshold does not
  pre-approve the generated aspects.
- Keep the original 5%/10% gates. This stops the required slicing and conversion
  aspects and most low-arity concat aspects unless the generated transform is
  materially faster than the fixture.
- Weave slicing/conversion only in an explicit IAST build configuration. This
  removes their runtime-disabled cost from builds without those aspects, but an
  instrumented binary cannot enable the missing propagation at runtime.
- Defer slicing and conversion from the first release. This reduces the promised
  propagation matrix and needs a documented compatibility decision.

Phase 6 must measure the generated forms with at least 20 samples and a 1-second
benchmark time on an idle machine. It must report unrounded values, allocations,
`benchstat` 95% confidence intervals, and a paired-bootstrap 95% upper bound for
the absolute delta. Both the point estimate and upper bound must meet the
selected gate. The contradictory Concat 16 samples mean the at-or-above-80-ns
arm is currently unvalidated.

### 7.2 HTTP matcher

**Question:** which exact HTTP lifecycle matcher may proceed to schema review?

- **Recommended:** design an Orchestrion syntactic receiver matcher that can
  match `serverHandler.ServeHTTP` inside its own package without recursive type
  resolution. Review its schema at the original plan's separate Orchestrion
  checkpoint before upstream implementation.
- Use the broad standard-library `ServeHTTP` matcher. This adds instrumentation
  to unrelated standard-library handlers and needs separate overhead and h2c
  lifetime approval.
- Stop standard-library lifecycle ownership. This removes automatic direct
  `net/http` coverage from the first release.

### 7.3 Store capacity

**Question:** which whole-feature memory and range-pressure policy should
Phase 1 and Phase 2 target?

- **Recommended:** approve a 24 MiB whole-feature ceiling and the provisional
  counts in section 2.2. On overflow-pool exhaustion, keep the first four
  accurate ranges, drop later ranges, and emit telemetry. This accepts bounded
  false negatives under saturation without fabricated provenance.
- Keep the 24 MiB ceiling but spend more of it on overflow blocks. Phase 1 must
  propose the new fixed block count and reduce another table if needed.
- Keep the 24 MiB ceiling but drop the complete value when no overflow block is
  available. This avoids partial provenance but causes larger false-negative
  gaps under saturation.
- Require a lower user-supplied ceiling. Phase 1 must redesign slot, root, and
  range counts before implementation.

The 14.9 MiB value/owner/range/root figure is a calculated hard bound, not a
retained-heap measurement. Phase 2 must measure retained heap and allocator
rounding before the 24 MiB ceiling is final.

### 7.4 Phase 0 exit and body boundary

**Question:** which incomplete Phase 0 items may move to later checkpoints?

- **Recommended:** require `io.ReadAll` in the first body vertical slice; make
  `bytes.Buffer.ReadFrom` conditional on its dedicated benchmark; move the
  many-substrings retained-heap proof to Phase 2; and move report, redaction,
  payload, backend, and cross-tracer validation to Phase 7a.
- Require every original Phase 0 item before Phase 1. This adds the buffer,
  retained-heap, backend, tokenizer, payload, and cross-tracer probes now.
- Require `bytes.Buffer.ReadFrom` now, but accept the Phase 2 and Phase 7a
  evidence moves.
- Accept the body API split, but require retained-heap and sink/report evidence
  before Phase 1.

### 7.5 Deferred backend contract

If the recommended Phase 0 exit is approved, the payload sentinel and tokenizer
remain unselected. Phase 7a must confirm payload shape, overflow semantics,
tokenizer behavior, backend acceptance, and cross-tracer compatibility before
sink/report production code is enabled.

## 8. Phase exit assessment

Phase 0 produced enough evidence to start pure range/source work only after the
user answers section 7. It does **not** authorize operator aspects, HTTP source
aspects, Orchestrion schema implementation, or sink/report implementation.

Carried-forward obligations are:

1. Phase 1 can implement and review pure root-relative range algebra and the
   bounded source table after the memory-ceiling decision.
2. The lazy store can be rebuilt against that algebra and re-benchmarked before
   Phase 2 exits. Phase 2 must prove that many substrings charge and retain one
   managed root.
3. Orchestrion join-point schemas require the original plan's separate user
   checkpoint before upstream implementation.
4. Phase 4 must prove per-request h2c owner release without connection-close
   dependence.
5. Phase 7a must complete report, redaction, payload, backend, and cross-tracer
   validation that Phase 0 could not complete.

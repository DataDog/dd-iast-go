# Phase 5 plan: named taint propagation

## Status

- **State:** approved implementation plan
- **Parent plan:** [taint-tracking-net-http-sqli-cmdi.md](./taint-tracking-net-http-sqli-cmdi.md)
- **Toolchain:** exact Go 1.26.6 and Orchestrion 1.12.2

## Decisions

1. Named operations use direct call-site replacement. Function-body callbacks are rejected because a useful callback dependency closure imports the woven standard-library packages and recreates the Phase 0 package-cycle and early-initialization risks.
2. Direct calls are supported. Calls through function values remain unchanged and are documented and tested as unsupported.
3. Aspects match root-application packages only and use narrow self-weaving exclusions for the wrapper package, `internal/**`, the public `taint` package, and tracer internals. Dedicated root-module `iast` integration fixtures remain woven. Standard-library and dependency packages are never made to import the wrapper package.
4. One result can be published independently to every contributing active owner, bounded by `store.MaxSnapshotOwners`. An audited complete result allocation is shared and charged by each owner; it is not cloned once per owner. Each publication reserves a separate owner root, so one 64-KiB logical output can consume up to four 64-KiB root charges. The existing 8-MiB process root budget remains the hard bound and causes later fanout publications to drop before the 24-MiB whole-feature ceiling can be exceeded. Successful earlier owner publications remain valid when a later owner drops; telemetry records the partial fanout.
5. `bytes.Buffer.Bytes` remains untainted because it returns a mutable interior slice. Cloning would change alias semantics, and adopting an unproven interior allocation would violate accounting.
6. Public source and inspection APIs in `taint` remain unchanged. Instrumentation wrappers live in `iast/propagation`; range and owner logic remains internal.
7. Aspects are not considered enabled for general availability until the Phase 5 benchmark checkpoint is approved.
8. The user explicitly accepts one additional allocation for stack `strings.Builder` and `bytes.Buffer` receivers so writer provenance can use strong ABA-safe identity. This overrides the general zero-added-allocation gate only for those writer operations; measured costs and retained-memory bounds still require review.

## Architecture

Add `internal/taint/propagation` for bounded owner-separated range transforms and publication. It uses the process store fast gate, `MayContain`, fixed `Snapshot` storage, `ranges` operations, generation-validated owner handles, and `Owner.Derive` or `Owner.AdoptString`/`AdoptBytes`.

For each contributing owner:

- lookup ranges remain owner-local, so source IDs never cross owners;
- aliasing substring or subslice outputs derive another window from the existing root;
- audited complete outputs are adopted without replacing the application result;
- operations whose output allocation cannot be proven complete clone only on a tainted path, and the wrapper returns that managed clone;
- invalid math, contention, owner finish, capacity pressure, or unsupported identity drops provenance without changing host results.

Add `func (e *Entry) Handle(s *Store) (Owner, bool)`, mirroring `OwnerRef.Handle`. It validates store, owner index, owner ID, owner generation, and active state and returns an `Owner` by value only after every check. A mismatch returns a disabled zero handle, so a stale snapshot cannot publish into a reused slot. Numeric addresses remain comparison keys and are never converted back to pointers.

A dependency-minimal call-site package is not required because aspects match root-application callers only. Standard-library and dependency packages are excluded, so they never import the wrapper and cannot form `fmt -> iast/propagation -> fmt`-style cycles. `iast/propagation` calls the original operation exactly once and then invokes the internal engine. Exact package filters prevent those calls from being rewritten recursively. Woven dependency-closure fixtures and `go list -deps` audits enforce this boundary.

Every string operation has an allocation audit. Aliasing outputs derive from the input root. Every non-aliasing tainted string output is cloned to an exact-length managed allocation before publication; this avoids hidden retained capacity and static backing. In particular, `strings.Repeat` count-one results derive, while static repeated-space/dash fast paths clone. `strings.Builder.String` would also require cloning if writer propagation passed its separate gate. Byte outputs expose capacity: audited fresh base allocations can be adopted and charged by capacity, while input aliases derive.

## Operation batches

### Batch 1: string windows and copies

- `strings.Clone`
- `strings.Cut`
- `strings.Split`, `SplitN`, `SplitAfter`, `SplitAfterN`
- `strings.Fields`, `FieldsFunc`
- `strings.Trim`, `TrimSpace`, `TrimLeft`, `TrimRight`, `TrimPrefix`, `TrimSuffix`
- `strings.TrimFunc`, `TrimLeftFunc`, `TrimRightFunc`

Substring results derive exact root-relative windows. Empty outputs remain untainted because store keys reject zero length. One-byte derived windows are allowed when the existing root safely owns them; new managed roots still require two bytes.

### Batch 2: allocating exact string operations

- `strings.Join`
- `strings.Repeat`
- `strings.Replace`, `ReplaceAll`

`Join`, `Repeat`, and bounded replacement use `ranges.Join`, `Repeat`, and `Compose`. Replacement mapping is exact for at most 32 copied/replacement segments, then falls back to coarse provenance. At most 16 input values are inspected per call; excess input is a bounded coverage drop.

### Batch 3: coarse string operations

- `strings.Replacer.Replace` (input-string provenance only; replacement-term provenance is an explicit unsupported case)
- `strings.ToLower`, `ToUpper`, `ToTitle`
- `strings.Map`, `ToValidUTF8`
- `fmt.Sprint`, `Sprintf`, `Sprintln`
- `net/url.QueryEscape`, `PathEscape`, `QueryUnescape`, `PathUnescape`
- `strconv.Quote`, `QuoteToASCII`, `QuoteToGraphic`, `Unquote`

A transform remains exact only when audited mapping proves byte positions unchanged. Otherwise `ranges.Coarse` uses the first contributing source and intersects secure marks. Formatting inspects at most 16 arguments. `fmt.Fprintf` is excluded.

### Batch 4: byte mirrors

The reviewable byte matrix is: `bytes.Clone`, `Join`, `Repeat`, `Cut`, `Split`, `SplitN`, `SplitAfter`, `SplitAfterN`, `Fields`, `FieldsFunc`, `Trim`, `TrimSpace`, `TrimLeft`, `TrimRight`, `TrimPrefix`, `TrimSuffix`, `TrimFunc`, `TrimLeftFunc`, `TrimRightFunc`, `Replace`, `ReplaceAll`, `ToLower`, `ToUpper`, `ToTitle`, `Map`, and `ToValidUTF8`. Windows derive exact ranges. Fresh complete outputs are adopted with their visible capacity charged. Replace uses the same 32-segment exact/coarse boundary as strings. Case, map, and valid-UTF-8 transforms are exact only after audited position mapping and otherwise coarse. Disable any byte aspect that adds an allocation to a previously allocation-free untainted path.

### Batch 5: builders and buffers

Implement a separate fixed writer-state table per owner, with at most eight writer objects and at most four contributing owners per object. Each entry strongly anchors the typed `*strings.Builder` or `*bytes.Buffer`, records its dynamic pointer only as a comparison key, stores a fixed `ranges.Set`, logical length, current content pointer, visible capacity, generation, and charged peak capacity. Writer capacity uses the same request/process charged-byte atomics as managed roots. Growth reserves the delta before provenance is accepted; reset/invalidation releases the writer charge and anchor; owner finish clears all writer anchors synchronously before reconciling the existing charge counters. Capacity above 64 KiB drops and invalidates writer provenance.

Call-site write wrappers call the original method exactly once, then update every existing writer-owner state and every newly contributing input owner. Existing owner states advance for untainted writes so offsets remain correct. `Write`/`WriteString` use the actual returned count; `WriteByte` and `WriteRune` advance untainted length. `strings.Builder.Reset` and `bytes.Buffer.Reset` clear state; `bytes.Buffer.Truncate` slices it. Before every update, wrappers validate the current content pointer, length, and backing-buffer capacity against recorded state and invalidate on mismatch. A failed `TryLock` during a writer update sets a lock-free table-dirty flag; the next successful lock clears all affected states and charges before doing work. Stale state is never resumed after an unrecorded mutation. Publication snapshots the fixed state: `strings.Builder.String` and `bytes.Buffer.String` clone a tainted result once into an exact-length managed string and publish that same audited allocation independently to each contributing owner. `bytes.Buffer.Bytes` remains unsupported, as approved, and `ReadFrom` remains deferred.

Direct call-site wrappers cover builder/buffer writes and reset, plus buffer truncate. A dependency-minimal numeric invalidation bridge is woven into every Go 1.26.6 `bytes.Buffer` operation that can change unread offset or content without reaching those wrappers: `Write`, `WriteString`, `WriteByte`, `WriteRune`, `Reset`, `Truncate`, `Read`, `Next`, `ReadByte`, `ReadRune`, `ReadBytes`, `ReadString`, and `WriteTo`, plus any standard-library internal reset path found in the pinned source. It receives only `uintptr(unsafe.Pointer(receiver))`, never converts it back, and clears matching writer states. Passing only a numeric key does not make an otherwise-stack receiver escape. `Buffer.String` also validates the buffer's current data pointer, unread length, and backing `cap(b.buf)` against recorded state and invalidates on mismatch. Function-body invalidation callbacks use a dependency-minimal atomic bridge and must pass cycle, early-init, recursion, and escape audits. Indirect `strings.Builder` writes or reset remain unsupported because no safe dependency-minimal function-body hook can inspect its private backing state; the next direct wrapper validates length/capacity and drops stale state rather than resuming it.

The strong writer anchor intentionally makes a stack receiver escape and adds one allocation; the user approved this writer-specific gate exception. Benchmarks must report the exact delta. Numeric-only shadow state without an anchor remains rejected as ABA-unsafe. Builder/buffer value copies and indirect write calls that bypass call-site wrappers are explicit unsupported cases; buffer indirect mutations are made safe by function-body invalidation and can only lose provenance.

## Bounded work and telemetry

- one cheap process-active gate before lookup;
- zero allocation on disabled, no-active, sampled-out, and active-untainted paths where the original operation allocates none;
- `TryLock`/`TryRLock` only;
- at most four owners, sixteen inspected inputs, thirty-two replacement segments, thirty-two published window outputs per call, eight writer states per owner, sixty-four ranges, and the existing 256-value per-root-generation quota;
- count propagation executions, coarse fallbacks, range truncation, unsupported allocation identity, fanout, contention, and capacity drops at the configured telemetry level.

## Aspect shape

Use Orchestrion `function-call` plus `replace-function` for free functions. Replacing only `CallExpr.Fun` preserves argument evaluation count/order, variadic ellipsis, panic behavior, and results. Every aspect also requires a root-application `package-filter`. If writer support ever passes its gate, use `method-call` plus `wrap-expression` because `replace-function` cannot supply the method receiver; every receiver and argument expression must appear exactly once.

Filters exclude:

- `github.com/DataDog/dd-iast-go/iast/propagation`;
- `github.com/DataDog/dd-iast-go/internal/**`;
- `github.com/DataDog/dd-iast-go/taint`;
- Datadog tracer internals.

The positive root-package filter is mandatory. When dd-iast-go itself is the root module, the negative exclusions are the primary self-weaving guard. Woven-output tests assert zero wrapper calls inside `internal/**`, `taint`, and `iast/propagation`. Compile fixtures prove that woven standard-library and dependency packages do not acquire an `iast/propagation` dependency. Build-time match telemetry must fail fixtures when an expected direct call records zero matches, including when root-module discovery silently returns false.

Tests prove local homonyms are not matched and woven output contains no recursive wrapper call.

## Validation

For every supported operation, test untainted, complete taint, partial ranges, multiple sources, multiple owners, exact/coarse behavior, output aliases, empty/one-byte results, UTF-8 and invalid UTF-8, contention, saturation, owner finish, and range limits. Empty outputs remain untainted; non-empty one-byte windows can derive from an existing managed root. Split and field results publish only the deterministic first 32 windows and count the omitted tail, preserving most of the 256-value root quota for later operations. Test indirect calls, tainted `Replacer` replacement terms, and all gated writer/buffer operations as explicit negative coverage.

Use external woven fixtures under a dedicated `iast` package. Add range-oracle and fuzz tests for join, replace, and window mapping. Run ordinary, woven, race, checklocks, vet, checkptr, retained-memory, and coverage checks.

Benchmark every enabled aspect with at least twenty one-second samples on an idle machine. Record unrounded values, use `benchstat` 95% intervals and a paired-bootstrap 95% upper bound, and require both the estimate and upper bound to pass. Required gates are the approved Phase 0 gates: under 80 ns, at most 4 ns added disabled/active-untainted overhead; at or above 80 ns, at most 5%; zero added local allocations; and at most 2% median sampled-out HTTP overhead. Include receiver-escape/allocation benchmarks for every writer prototype and each allocation-free byte operation. Record sampled-tainted costs. Present the complete results for the required user checkpoint before default enablement.

For every byte operation, run its escape/allocation benchmark before adding its aspect to `orchestrion.yml`; a failing operation is recorded as unsupported and never lands enabled. The writer-specific receiver allocation is the only user-approved exception and must remain exactly measured. Update `orchestrion.tool.go` only if a new integration package is required, publish the exact README matrix and limitations, assert exact build-time aspect-match telemetry, add accepted/debug propagation telemetry, enforce the parent coverage floors, and record the mutation-feasibility result for pure mapping logic.

The parent Phase 5 requirement for general function-body propagation callback audits is vacuous because named value propagation uses call-site wrappers. The numeric `bytes.Buffer` invalidation callback is the sole function-body callback and must pass the complete init, reentrancy, import-cycle, and escape audit. Call-site wrappers still receive recursion and dependency-closure tests.

## Implementation status and benchmark checkpoint

The named string, byte, formatting, URL, quoting, replacer, builder, and buffer
operations in this plan are implemented. The implementation uses 105 exact
Orchestrion aspect shapes. Runtime telemetry counts accepted propagation,
coarsening, and bounded drops. The README records the operation matrix and the
unsupported indirect-call, mutable-buffer, replacer-term, and shared-backing
cases.

Representative primitive-shape benchmarks used twenty one-second samples. All
local estimates and paired-bootstrap 95% upper bounds passed the four-nanosecond
local gate, with unchanged allocation counts:

Benchmark shape | Median delta | Paired-bootstrap 95% upper
---|---:|---:
String clone | +0.315 ns | +0.490 ns
String join | +0.545 ns | +1.445 ns
Formatting | +0.650 ns | +1.330 ns
Byte split | -0.080 ns | +1.955 ns
Active clean string windows | +0.445 ns | +1.620 ns
Active clean byte copy | -0.095 ns | +0.295 ns
Sequence window | -1.535 ns | -1.380 ns

A fifty-sample writer rerun also passed: `strings.Builder` measured +0.090 ns
with a +0.960 ns upper bound, and `bytes.Buffer` measured +1.700 ns with a
+2.955 ns upper bound. Both variants retained their baseline allocations. This
measurement includes the approved receiver-escape tradeoff; no additional
allocation delta was visible in the end operation benchmark.

The fifty-sample sampled-out HTTP run measured 95.54 microseconds for control
and 97.27 microseconds for IAST: a +1.81% median estimate, unchanged from a
statistical perspective (`p=0.176`). Its paired-bootstrap 95% upper bound was
+3.93%, which does **not** pass the strict +2% upper-bound gate. Bytes increased
from 33.81 KiB to 34.28 KiB (+1.39%), and allocations increased from 422 to 428
(+1.42%). Consequently, Checkpoint 7 remains unapproved and these propagation
aspects must not be treated as generally enabled until the user accepts the
measured sampled-out uncertainty or requests further overhead work.

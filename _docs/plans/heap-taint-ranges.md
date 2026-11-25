# Plan: heap taint ranges with origins (v4)

| Field | Value |
|---|---|
| PR title | `feat(taint): add heap taint ranges with origins` |
| Branch | `romain.marcadier/heap-taint-ranges` |
| Base branch | `romain.marcadier/fix-root-span-finish` (PR #95, head `930976e`) |
| Stack | GitHub native stack #94, position 4 (`#92 → #93 → #95 → this PR`) |
| Contract | `_docs/design/taint-tracking-v0.md` (PR #92, head `e63900b`), sections 1.2, 1.9, 1.10, 3.1, 3.2, 3.5, 3.6, 4.4, 4.5 |
| Criteria that this PR closes | AC-P4, AC-P5, AC-P6, AC-P7, AC-P8, AC-P11, AC-S4, AC-S7, AC-S10, AC-S13 |
| Review bar | High risk: Reviewer and Adversarial Reviewer cover Runtime internals, Concurrency, Host safety, Performance, Tool parity, and Test oracle after the feature PR opens |
| Size (estimate) | About 7 000 to 8 000 changed lines: runtime-side file 1 500 to 2 000, Go-side packages 1 700, tests 3 500, CI, helper programs and rule files 600 |

This plan file is the first commit of the PR (`wip(plan): add heap taint
ranges with origins`), after the critic and Romain approve it. The top PR of
the stack deletes it.

> **Rule for the code of this PR.** Code, comments, test names, test data,
> golden files, generated files, CI job and step names, the manifest and the
> sentinel never contain a criterion ID, a PR name of the stack, a decision
> number, a section number, or an ID of the earlier review. In this file,
> every reference to the design document is written as **[ref: …]**. A
> **[ref: …]** is for the reviewers only. Never copy it into code or comments.
> Write comments that describe the behavior instead.

## 0. Review history

### Spike decisions

Decision 28 selected option (b): remove js/wasm coverage and its spike
check. Keep the import-graph fix in 0.1 item A for both weaving tools.
The spike verified the runtime weaving primitives in PR #99. Apply these
adjustments to the feature PR:

- Normalize Windows path separators in `scripts/otelc-test.sh` before it
  matches `/internal/build/otelc.yml` against `go list` output.
- On Windows, run the "Feature off" tests only in
  `./internal/taint/heapranges/...`, with both tools and both Go versions.
  Keep macOS amd64 on stable Go only.
- For the init proof, use `GODEBUG=inittrace=1` and the `heapranges` init
  log and state. Check `Enabled() == true`, `MappedBytes() >= 1 MiB`, and
  in-process `OtherSys >= MappedBytes()`; do not compare separate processes.

### 0.0 Changes in v4 (answers to the third critic round)

| # | Objection | Answer in v4 | Where |
|---|---|---|---|
| G | Builds of the helper programs from inside the woven tests: otelc waits for the build lock of the outer otelc, and `-asan`, `-msan`, `-race` are not passed on | Every nested otelc command gets its own fresh `OTELC_WORK_DIR` (`t.TempDir()`). The nested `initprog` build gets the `-asan`, `-msan` and `-race` flags that `debug.ReadBuildInfo().Settings` of the test binary has. `initprog` prints its own flags, and the test checks that they are the same. New spike item 9. | 2.1 item 16; step 1 item 9; 4.1 AC-P5, AC-P7 |
| H | `jscpd` skips files of more than 1 000 lines or 100 KB, with no message | `--max-lines 1000000 --max-size 100mb`. The planted copy is inside a file of more than 1 000 lines (a copy of `runtime_inject.go` with the copy appended). The scan fails when `.statistics.total.sources` is not equal to the number of input files. | 4.4 |
| 1 | The probe object must not need a snapshot area | The probe object has the `Immutable` kind. | 2.1 item 12 |
| 2 | Probe mode and other `Set` calls | While probe mode is set, a `Set` outside the probe range returns false. The init-order argument is no longer needed. | 2.1 item 12 |
| 3 | `initprog` built in `TestMain` for every test run | Each `initprog` variant is built lazily, at most once (`sync.Once`), only by the tests that need it. | 2.1 item 16 |
| 4 | Shell details | The ID scan stops when the file list is empty. | 5 |

### 0.1 Changes in v3 (answers to the second critic round)

| # | Objection | Answer in v3 | Where |
|---|---|---|---|
| A | otelc import cycles: `internal/config → heapranges → internal/build` | No non-test file of `heapranges` imports `internal/build` ("not woven" = nil function variables). `internal/config` does **not** import `heapranges`. `heapranges` logs and registers its telemetry itself, in `report.go` (`//go:build !js && !wasip1`, imports `internal/instrumentation`), with a no-op `report_other.go` for js and wasip1. | 2.1 items 2, 11, 14; step 2; 5 |
| B | Cross-builds with `go tool <tool>` build the tool for the target | Get the host binary with `go tool -n <tool>` (no `GOOS`/`GOARCH` in that step), then run it with the target `GOOS`/`GOARCH`, on **one woven program** for each target: `_integration/otelc/cmd/sentinel` (linux/386, freebsd/amd64), `heaprangestest/internal/codegenprog` (the 3 ABIs). Never `./...`. | Step 1 item 4; 4.1 AC-P7; 4.2 |
| C | Clean-room scan finds nothing | `jscpd@4.3.0 --absolute --no-gitignore`; physical paths (`pwd -P`); a positive control (a planted copy must be found, then it is removed). | 4.4 |
| D | `GOMAXPROCS ≥ 64` makes init go Off | Init maps synchronously the slabs that the queues need plus the space for the self-test, within the budget (formula in 2.1 item 6). New subprocess cases: `GOMAXPROCS=128` (Live); `GOMAXPROCS=128` with a 1 MiB limit (16 queues, the other Ps count lost capacity). | 2.1 items 6, 12; AC-S4 |
| E | Shared counters in the sweep hook are retry loops on arm64 without LSE | One counter block for each P index (BSS, 1 024 entries), with one writer: a load and a store, no read-modify-write. The queue producer index is also a store. The Go side adds them up. The no-P case has its own word, written with a load and a store, which can lose a count when 2 Ms with no P race. This is documented. The case is expected to be rare: the sweep and `freegc` normally run on an M that has a P. A test counts how often the no-P word is used during the GC tests, and the spike reports it. | 2.1 items 6, 9 |
| F | AC-S10 needs more than 256 reclaimer rounds inside a 2 s pause | A test-only function runs one reclaimer round synchronously, on the same code path as the background goroutine (`knobs.ReclaimRound`). | 2.1 items 8, 15; AC-S10 |
| 1 | Missing transition `INLINE(e) → 0` by a writer | Added (`Cas64`, for `Clear` or a clean `Copy` on a 1-object span). | 2.1 item 3 |
| 2 | Probe mode scope; panic in the self-test | Probe mode applies only to the address range of the probe object. The self-test runs under `recover`, and a `defer` leaves probe mode. A panic gives Off. | 2.1 item 12 |
| 3 | `addReusableNoscan` hook: which span | `spanOfHeap(ptr)`, not `c.alloc[spc]`. | 2.1 item 9 |
| 4 | AC-P7 deny list, `nosplit` size limit, cost | Deny list adds `panicdivide*`, `panicshift`, `panicunsafe*`, `panicmem`, `throw`. Entry points stay small (the linker limit of a `nosplit` chain is about 800 bytes). The 3 fresh builds run only in one "Codegen check" job for each tool and Go version. | 2.1 item 13; 4.1; 4.2 |
| 5 | AC-S4 time bound and refiller pause | 100 ms bound, with the no-`mmap` check. "Refiller paused" is a Go-side flag (not a spin pause), because rounds 2 to 10 need a GC. | AC-S4 |
| 6 | Pause tests | The test sets `GOMAXPROCS` to at least 2 (before any pause) and calls `debug.SetMemoryLimit(math.MaxInt64)`. | 2.1 item 8 |
| 8 | ID scan | 2 commands: case-sensitive for IDs, case-insensitive only for `decision|section`; `--diff-filter=d`. | 5 |
| 9 | Spike: `-msan`; naming | Spike item 6 adds `-msan`. The spike branch and draft PR follow the naming rules. | Step 1 |
| 10 | Woven tests of `heapranges` will cycle when hook packages import it | All woven tests are in `internal/taint/heapranges/heaprangestest`, which nothing imports. `heapranges` test files never import `internal/build`. | 2.1 item 15; step 10 |

### 0.2 Changes in v2 (answers to the first critic round, still valid)

| # | Objection | Answer |
|---|---|---|
| 2 | otelc file location | Both injected files directly in `internal/taint/heapranges/`; both tools force the link and the `init`. |
| 3 | `mspan` state machine | Full table (2.1 item 3), with the struct reuse test. |
| 4 | Unpublished chains | To the retirement queue; bump allocation. |
| 5 | Pause deadlock | GC off, no stop-the-world, 2 s bound. |
| 6 | Probe failure | Probe mode before `CAS(0 → 1)`. |
| 7 | `nosplit` proof | Classifier alone, transitive check, fresh cache, deny list. |
| 8 | AC-S4, AC-S7 oracles | See 4.1. |
| 9–14 | `-v`; `atomic.Uint64`; ID scan; `'-run=^X$'`; `DD_IAST_ENABLED=false`; one woven run per OS | Applied. |

## 1. Goal

Add the storage that answers "is this heap byte tainted, and from which
origin?" (package `internal/taint/heapranges` and its runtime-side code), with
its memory lifetime, its budget, its gate word and circuit breaker, its two
env vars, and the CI that proves it on every supported and unsupported
platform. Taint tracking stays **off by default**. No source, sink or
propagation hook is in this PR: the tests taint values with the package API.

## 2. Approach

### 2.1 Chosen design

The design document is the contract. This section gives only the
implementation choices that the design does not fix. Each one is marked
**(choice)**; the critic and Romain can change it.

1. **Two parts.**
   - **Runtime-side code:** one Go source file, `package runtime`, with
     `//go:build ignore`. otelc copies it into `runtime` with `add_file`.
     `go generate` writes it into the Orchestrion `inject-declarations`
     template. It holds the gate word, the classifier, the `mspan` field
     logic, entry tables, records, the read and write operations, the
     announcement slots, the retirement queues, the per-P counter blocks, the
     free list, the slab descriptors and their bump indexes, and the 2 clear
     hooks.
   - **Go-side package** `internal/taint/heapranges`: env var reading, the
     slab allocator (`syscall.Mmap`, ordinary build constraints), the
     background goroutine (refiller and reclaimer), the self-test at init,
     the circuit breaker, counters, logging, and the exported API.

2. **How the Go side calls the runtime side (choice).** The runtime-side file
   exports each entry point with a one-argument `//go:linkname` (push). A
   second injected file (`//go:build ignore`, `package heapranges`) declares
   the matching body-less functions with `//go:linkname` and stores them in
   package-level function variables (in a variable initializer, so they are
   set before any `init`). In an unwoven build the variables stay nil:
   `Enabled()` is false and every operation returns "clean" or false. This
   is also how `heapranges` knows that it is not woven: it does **not**
   import `internal/build` in a non-test file. Thus an unwoven `go build`
   and `go test` of this module still link. The pointer arguments go through
   a `noescape` helper (the same trick as the runtime), so the indirect call
   does not make the value escape; an unwoven unit test checks the escape
   result (`-gcflags=-m`).

   The injected `heapranges` file also refers to one runtime symbol with a
   name that explains the problem, for example
   `runtime.ddiastHeapRangesNeedTheWovenRuntime`. When `heapranges` is woven
   but the runtime aspect was skipped, the link error names this symbol
   (spike item 7).

   ```go
   // Go side (sketch of the interface only).
   type Kind uint8   // Immutable, Private, Exposed
   type Origin uint64 // 40 bits generation, 6 bits slot, 8 bits source, 1 bit sensitive
   type Range struct { Off, Len uint32; Origin Origin; Marks uint8; Flags uint8 }

   func Enabled() bool
   func Set(p unsafe.Pointer, n uintptr, o Origin, k Kind) bool
   func Clear(p unsafe.Pointer, n uintptr)
   func MayHaveTaint(p unsafe.Pointer, n uintptr) bool
   func Any(p unsafe.Pointer, n uintptr) bool
   func Ranges(p unsafe.Pointer, n uintptr, buf []Range) []Range
   func Copy(dst, src unsafe.Pointer, n uintptr, k Kind) bool
   func Map(dst, src unsafe.Pointer, m []Segment) bool // Segment: DstOff, SrcOff, Len, Unknown flag
   ```

3. **The `mspan` field and its state machine (choice).** One added field,
   `ddTaint atomic.Uint64` (type from `internal/runtime/atomic`, so it is
   8-byte aligned on every platform). It is **not** a Go pointer, so no write
   barrier can run on it. 8 bytes per `mspan` struct [ref: design 3.6].
   `mspan` structs are reused and not zeroed (`h.spanalloc.zero = false`,
   `runtime/mheap.go:804`), and a struct can be reused for a span of any
   size class, with 1 object (for example size class 67, 32 KiB) or many.

   | Value | Meaning |
   |---|---|
   | `0` | No table, no inline entry. |
   | `SPAN_POISON` (a reserved small value) | No table. Every object of the span reads as poisoned. |
   | `INLINE(e)` (tag in the low bits, entry `e ≠ 0` in the high 32 bits) | No table. The entry of the only object. |
   | `TABLE(a)` (address `a` of a table, 64-byte aligned, from a slab) | A table is attached to this struct. Its header holds the base address of the span that uses it, or `0` (detached). |

   | From | To | Who | Atomic | Rule |
   |---|---|---|---|---|
   | `0` | `TABLE(a)` | Writer, any span with more than 1 object | `Cas64` | The new table has all entries 0 and the base of this span in its header. The loser of the CAS keeps its table units as "unused" (counted; they come back only when the process restarts, as for a slab tail). |
   | `0` | `INLINE(e)` | Writer, span with 1 object | `Cas64` | Inline only from `0`. |
   | `0` | `SPAN_POISON` | Writer, mandatory marker, span with more than 1 object, no table can be allocated | `Cas64` | When the CAS fails because a table was attached, use the table. |
   | `INLINE(e)` | `INLINE(e')` | Writer (copy-on-write publish) | `Cas64` | At most 4 tries. |
   | `INLINE(e)` | `0` | Writer: `Clear`, or a `Copy` from a clean source, on a 1-object span | `Cas64` | At most 4 tries; on failure, `INLINE(POISON)` by exchange (a real write) or drop (a `Clear` of a source label). Retire `e` when the CAS succeeds and `e` is a chain. |
   | `INLINE(e)` or `0` | `INLINE(POISON)` | Writer, failed real write, span with 1 object | `Xchg64` | Retire the returned entry only when it is a chain. Only writers of the same live object touch this field, so no `TABLE` can appear here. |
   | `INLINE(e)` | `0` | Sweep hook, object not marked; `addReusableNoscan` hook | `Xchg64` | Retire the returned value only when it is a chain. |
   | `SPAN_POISON` | `0` | Sweep hook, no slot marked | `Store64` (the sweeper owns the span) | – |
   | `TABLE(a)` | `TABLE(a)` | – | – | **Never removed.** A table stays on its struct for the life of the process. Every later span on this struct uses the table, also a span with 1 object (it uses entry 0). The table is never replaced by `INLINE` or `SPAN_POISON`. |
   | header base `0` | header base `s.base()` | Writer | `Cas64` on the header | A detached table has all entries 0. |
   | header base `s.base()` | header base `0` | Sweep hook, no slot marked | Exchange each entry to 0, then `Store64` of the base | The sweeper owns the span. |
   | header base `≠ s.base()`, `≠ 0` (stale) | – | Readers and writers: treat the span as clean, drop the write. Sweep hook: reset as above. | – | Should never happen; a test knob forces it. |

   **Invariant, checked by a test:** when the sweep frees a span, its field
   is `0` or a detached `TABLE(a)`. The number of tables is never more than
   the number of `mspan` structs that held a tainted object.

   No field is added to `runtime.heapArena`, and no field is added to
   `runtime.g` (later PRs add the `g` fields). Note: the "Off" row of the
   design table [ref: design 1.9] still says "8 bytes per arena and 1 byte
   per span" (text from an older version). This PR follows [ref: design 3.6].
   The PR description says so.

4. **Indexes and reserved values (choice).** Slab memory is cut in 64-byte
   units. A record (128 bytes) uses 2 units. A record index is 32 bits: the
   slab number (10 bits, 1 024 slab descriptors) and the unit number in the
   slab (1 MiB / 64 B = 16 384, 14 bits). An entry is `index + 1`, so `0`
   stays "not tainted". `POISON = 0xFFFFFFFF`, `PRIVATE = 0xFFFFFFFE`. The
   unknown origin is the origin with generation 0 (the registry of a later PR
   must start generations at 1). The conflict state is a range flag.

5. **Where memory comes from (choice).** One kind of slab (1 MiB), used for
   everything: records, tables (4 160 bytes, 65 units), retirement queues
   (16 KiB), snapshot areas (64 KiB). Each slab descriptor has a **bump
   index**: one atomic add takes the next units. When the current slab is
   full, the writer takes the next slab from the ready list with one CAS. So
   no writer pushes records to the free list.
   - **Records** come from the free list first (pop: at most 4 CAS tries, on
     a 64-bit head with a 32-bit index and a 32-bit tag), then from a bump.
     Writers pop **inside** their announced critical section. Only the
     reclaimer pushes. The tag and the epochs both prevent ABA.
   - **Tables, queues and snapshot areas** come only from a bump. Tables are
     never freed. Queues are never freed. Snapshot areas are retired with
     their owner and reused through their own free list (reclaimer only).
   - **The budget** is a number of slabs: `floor(DD_IAST_TAINT_MEMORY_LIMIT / 1 MiB)`.
     The mapped bytes are never more than the limit. Internal counters give,
     for each use, the units taken: records in use, records free, tables,
     queues, snapshot areas, units lost in a full slab tail or by a lost
     table CAS, and lost capacity.

6. **Retirement queues, counters and unpublished chains (choice).**
   - **Queue count:** `Q = min(GOMAXPROCS, 1 024, floor(limit / 4 / 16 KiB))`
     (at most one quarter of the budget; with the 1 MiB minimum, `Q = 16`).
   - **At init, before the self-test**, init maps synchronously
     `ceil((Q × 16 KiB + 64 KiB) / 1 MiB)` slabs (the queues, plus 64 KiB for
     the self-test: one table and its records). This is never more than the
     budget: `Q × 16 KiB ≤ limit / 4`, and the budget is at least 1 slab.
     Examples: 1 MiB limit → 1 slab; 64 MiB limit and `GOMAXPROCS=128` →
     3 slabs. Then it allocates the `Q` queues, for the P indexes `0` to
     `Q − 1`. Only then does the background goroutine start, and it keeps up
     to 2 more slabs ready.
   - The background goroutine checks on each period for a `GOMAXPROCS`
     change, and adds queues within the same cap. A P with no queue, and an
     operation with no P, count as lost capacity. The entry is still
     cleared. The sweep hook never allocates.
   - **The queue producer index is written with a store** (one producer: the
     P, with preemption disabled), not with an atomic add. An append is
     2 stores for the slot and 1 store of the index: no read-modify-write.
   - **Per-P counter blocks:** a BSS array of 1 024 blocks, one for each P
     index (cache-line padded). Each block has the counters that the clear
     hooks and the writers change: tainted slots cleared by the sweep hook,
     tainted slots cleared by the `addReusableNoscan` hook, lost capacity,
     drops by reason. One writer for each block (its P, with preemption
     disabled): a load and a store, no read-modify-write. The Go side adds
     them up for telemetry and tests. **No-P word:** an operation with no P
     uses one shared block, written with a load and a store. Two Ms with no
     P at the same time can lose one count. This is documented. The case
     is expected to be rare: the sweep and `freegc` normally run on an M
     that has a P. These counters are for telemetry and tests only; no
     decision depends on them. The GC tests report how often the no-P word
     was used.
   - **A chain that a writer built but did not publish** (its CAS failed
     4 times, or a record pop or bump failed in the middle of the chain) is
     appended to the retirement queue of the P, like a removed chain. It is
     never pushed to the free list by the writer. A full queue: lost
     capacity, counted.

7. **Snapshot areas in this PR (choice).** The request owner comes in a later
   PR. This PR adds only the mechanism: a table of 64 area descriptors (one
   per owner slot, with the generation), `AttachSnapshotArea(slot, gen)` and
   `RetireSnapshotArea(slot, gen)` (retired like a record chain), and the
   comparison of the requested slice in `Ranges` and `Copy`. The tests use a
   test owner slot and generation. The A/A or C/C switch is an internal
   variable of `heapranges` (default A/A), changed only by a test knob.

8. **Test knobs (choice).** One runtime-side `uint32` knob word, read only on
   slow paths (never on the `MayHaveTaint` fast path; the generated-code test
   checks this). The knobs and the test-only inspection functions (queue
   contents, free-list size, entry value, field value, table base address,
   bump counters, per-P counters) are function variables of the package
   `internal/taint/heapranges/internal/knobs` (only variables, no logic). The
   injected `heapranges` file sets them, so only the woven build has them,
   and only packages below `internal/taint/heapranges` can import them.
   **Rules for pause knobs:**
   - A paused operation spins with `procyield` and `osyield`. It holds
     `acquirem`, so it cannot be preempted, and a stop-the-world would wait
     for it.
   - **Before** the first pause, the test sets `GOMAXPROCS` to at least 2
     (a stop-the-world, so never while a pause is held), and calls
     `debug.SetGCPercent(-1)` and `debug.SetMemoryLimit(math.MaxInt64)`
     (a memory limit can start a GC even with the GC percent off). It
     restores them at the end.
   - While a pause is held, the test calls no `runtime.ReadMemStats`, no
     `runtime.GC`, no `debug.FreeOSMemory` and no `runtime.GOMAXPROCS`. A
     test helper enforces this: it fails the test (not the runtime) when one
     of these is called while a pause is held.
   - Each pause loop has a bound of 2 s (counted with `nanotime`). At the
     bound, it releases, and sets a "pause timed out" flag. Every test that
     uses a pause fails when this flag is set.
   - No test case needs a GC while a pause is held: retirements in these
     cases come from writers, and reclaimer rounds come from
     `knobs.ReclaimRound` (item 15), not from the sweep or the timer.

9. **Clear hooks.**
   - Prologue of `(*mspan).countAlloc`: reads `s.gcmarkBits` directly (never
     `markBitsForIndex`), clears each entry with no mark bit by one exchange,
     retires chain values only, handles the field states of item 3. Bounded:
     at most `nelems` (1 024) bits and entries.
   - Prologue of `(*mcache).addReusableNoscan`: does its work only when
     `runtimeFreegcEnabled` is true (the same constant as the function body),
     so it clears a slot only when the slot really becomes reusable. It finds
     the span with `spanOfHeap(ptr)`, not with `c.alloc[spc]` (`freegc` does
     not check that `ptr` is in `c.alloc[spc]`, `runtime/malloc.go:1990` in
     go1.27).
   - Both have `//go:nowritebarrierrec` and only `nosplit` callees (item 13).
   - Each counts the tainted slots that it cleared in the per-P block of
     item 6 (for the positive controls), and has a test knob that turns it
     off (for the negative controls).

10. **Where the rule files and injected files are (choice).** All in
    `internal/taint/heapranges/`:
    - `runtime_inject.go` (`//go:build ignore`, `package runtime`),
    - `heapranges_inject.go` (`//go:build ignore`, `package heapranges`),
    - `orchestrion.yml` (generated) and `otelc.yml`.

    The two injected files are next to the buildable files of the package,
    as `instrumentation/spans/otelc_decl_finish.go` is. The otelc
    `add_file` rules use `path: github.com/DataDog/dd-iast-go/internal/taint/heapranges`.
    - **otelc** blank-imports the `path` of each file rule into the
      `otelc.runtime.go` of each command-line package, `main` included
      (`tool/internal/setup/inject.go:19-38`, `add.go:42-61`). So
      `heapranges` is linked **and** its `init` runs.
    - **Orchestrion** `links:` on the runtime aspect writes a synthetic
      package with blank imports into `main`
      (`internal/toolexec/aspect/oncompile-main.go:30-33, 225-252`). So the
      `init` runs too.
    - Tool files: the root `orchestrion.tool.go` and the core otelc tool file
      `otel.instrumentation.go` import `heapranges` [ref: decision 14: every
      application gets the woven runtime].
    - The spike proves that the `init` runs with both tools, in a woven
      program that does not import `heapranges` (step 1 item 3).

11. **Env vars, read by `heapranges` itself (choice).**
    - **Import graph.** Non-test files of `heapranges` import only:
      `internal/config/loader`, `internal/config/parser`,
      `internal/instrumentation/telemetry`,
      `internal/taint/heapranges/internal/knobs`, and, in `report.go` only
      (`//go:build !js && !wasip1`), `internal/instrumentation` (which
      imports only dd-trace-go `instrumentation`). `report_other.go`
      (`//go:build js || wasip1`) has the same functions, with no effect. No
      non-test file imports `internal/build` or `internal/config`, and
      `internal/config` does not import `heapranges`. (The second critic
      round tested this graph with `scripts/otelc-test.sh`: no cycle, and
      `heapranges` remains outside both import cycles.)
    - **Rule for later PRs, written in the package doc:** a package that
      `heapranges` imports never gets woven tests. otelc blank-imports
      `heapranges` into every tested package, so a woven test of a package
      that `heapranges` imports is an import cycle.
    - `heapranges` reads `DD_IAST_ENABLED` (as `internal/config` does: same
      parser, same default), `DD_IAST_TAINT_TRACKING_ENABLED` (Boolean,
      default `false`) and `DD_IAST_TAINT_MEMORY_LIMIT` (integer bytes,
      default 64 MiB) at its init, with `loader` and an observer that keeps
      the warnings and the values in memory (bounded: at most 8 entries).
    - `0` turns taint tracking off. A nonzero value outside 1 MiB to 1 GiB is
      clamped, with a warning (the existing README rule: "Integer values
      outside a documented range are clamped to that range"). A negative
      value is not a valid unsigned integer: warning, and the default
      (64 MiB), as the existing parser does for all integer env vars.
    - `report.go`: at the end of the `heapranges` init, it registers the 2
      values in telemetry (with their origin), logs the kept warnings, and
      logs the init result (On, or Off with its reason, for example
      "probe: any"), with `instrumentation.Instance`. It is ready at that
      time: `heapranges` imports `internal/instrumentation`, so its `init`
      ran first.
    - Counters (drops by reason, lost capacity, live memory, trips) are read
      from the per-P blocks and from Go-side atomics, and exported through
      `internal/instrumentation/telemetry` (a leaf package). The existing
      heartbeat (`internal/instrumentation/heartbeat`) reports them.

12. **Init order of `heapranges` and the gate.** At init:
    1. Read the env vars (item 11).
    2. Go Off with `CAS(0 → 2)`, and keep the reason, when any of these is
       true: `DD_IAST_ENABLED=false`; `DD_IAST_TAINT_TRACKING_ENABLED` is
       false; the memory limit is 0; the runtime is not woven (nil function
       variables); the platform is not supported (GOOS, GOARCH,
       `asanenabled`, `msanenabled`); no allocator exists (`slab_other.go`);
       the init slabs cannot be mapped; the queues cannot be allocated.
    3. Else: map the init slabs and allocate the queues (item 6), then start
       the background goroutine.
    4. Run the self-test in **probe mode**, under a `recover`. Probe mode is
       a runtime-side pair of words: the base and the end of the probe
       object. While they are set, a `Set` **inside that range** succeeds
       without `CAS(0 → 1)`, and a `Set` on **any other address returns
       false** (it changes nothing). So the gate cannot become Live before
       all probes pass, whatever runs at the same time. A `defer` clears the
       probe range, also on a panic. The probe object is a heap object with
       the **`Immutable`** kind (so `Set` needs no snapshot area, and
       `Ranges` gives the test origin back with no owner). The probes:
       `Set`, `MayHaveTaint`, `Any`, `Ranges`, `Clear` on the probe object,
       with a test origin. During the probes the gate stays 0 (Armed), so no
       other hook does work, and the clear hooks do nothing.
    5. All probes pass: `CAS(0 → 1)` (Live). This is the same end state as
       "the first successful `Set` makes the gate Live" [ref: design 1.2.5]:
       the gate is Live from the end of init.
    6. A probe fails, or the self-test panics (the `recover` catches it):
       `CAS(0 → 2)` (Off), keep the name of the probe (or "panic") for the
       log line, add 1 to a telemetry counter. The application starts
       normally.
    7. A later PR that adds probes of hooks that need the Live gate (the
       runtime lowerings) stores 3 (Tripped) when such a probe fails.
    - **Test-only probe failure:** a string variable
      `heapranges.probeFailure`, empty by default, set only with
      `-ldflags=-X` in the helper program of the tests. When it names a
      probe, that probe reports a failure. No env var and no runtime knob is
      needed before `init`.

13. **The `nosplit` structure (choice).**
    - Each entry point (`MayHaveTaint`, `Any`, `Ranges`, `Set`, `Copy`,
      `Map`, `Clear`) is `//go:nosplit`. Before its first branch on the
      result, it calls only the classifier and atomics.
    - The classifier is its own `//go:nosplit` function: typed pointer in,
      "inside one heap slot of an in-use heap span, or not" out. It calls
      only `spanOfHeap`, `(*mspan).objIndex` and atomics (all `nosplit`).
    - Entry points and the classifier keep small frames: the linker limits
      the stack of a `nosplit` call chain to about 800 bytes (a woven build
      that breaks this limit fails at link time with "nosplit stack
      overflow", which is a build-time check too). Work that needs more
      stack is done after the decision, in normal functions.
    - The 2 clear hooks have `//go:nowritebarrierrec`. They and all their
      callees use explicit bounds checks with unsafe address arithmetic, and
      explicit checks for 0 before a division or a shift, so the compiler
      emits no panic call.

14. **Logging and telemetry without import cycles (choice).** See item 11.
    The rule "no non-test file of `heapranges` imports `internal/build` or
    `internal/config`" is checked by a unit test (`go list -deps` of
    `heapranges` in the unwoven build, and a parse of its imports).

15. **Woven tests in a package that nothing imports (choice).**
    - All woven tests are in `internal/taint/heapranges/heaprangestest`
      (only `_test.go` files, plus a `doc.go`). It imports `heapranges`,
      `heapranges/internal/knobs` and `internal/build`. Nothing imports it.
      So when later PRs add hook packages that import `heapranges`, the woven
      tests stay free of otelc import cycles.
    - Test files in `heapranges` itself are unwoven only (drift test, import
      test, escape test, env var parsing). They never import
      `internal/build`, so `scripts/otelc-test.sh` never selects
      `heapranges`.
    - `knobs.ReclaimRound()` runs one reclaimer round synchronously, with the
      same function that the background goroutine calls (`reclaimOnce`). A
      Go `sync.Mutex` in `heapranges` (off the request path, `checklocks`
      annotated) makes the rounds one at a time, so each queue keeps one
      consumer.
    - Helper programs for subprocess and build tests (built as item 16
      says): `heaprangestest/internal/initprog` (a woven `main` that runs
      one scenario that an argument names, for example "taint until drops",
      and then prints the gate, the Off reason, the counters, and its own
      `-asan`, `-msan` and `-race` build settings as JSON), and
      `heaprangestest/internal/codegenprog` (a tiny woven `main` for the
      assembly check).

16. **Nested builds from inside a woven test (choice).** The tests build
    `initprog` and `codegenprog` with the tool that runs them
    (`build.Tool()`, then the host binary from `go tool -n <tool>`). One
    helper function in `heaprangestest` does every nested build, with these
    rules:
    - **otelc:** the nested command gets a fresh `OTELC_WORK_DIR`
      (`t.TempDir()`). The outer `otelc go test` holds its build lock in its
      own `OTELC_WORK_DIR` until the test ends, so a nested otelc with the
      inherited value waits for ever. (Orchestrion needs no change: a nested
      build inside `go tool orchestrion go test` works.)
    - **Build flags:** the helper reads `-asan`, `-msan` and `-race` from
      `debug.ReadBuildInfo().Settings` of the test binary, and passes the
      same flags to the nested `initprog` build. `initprog` prints its own
      settings, and every test that runs it checks that they are equal to
      the settings of the test binary (proof that the flags were passed).
      `codegenprog` is built with no sanitizer (the assembly check is for
      the normal build).
    - **Lazy, at most once:** each variant (`initprog`, `initprog` with
      `-ldflags=-X …heapranges.probeFailure=any`, `initprog` with the
      panicking probe, `codegenprog`) has its own `sync.Once`. Only the
      tests that need a variant build it. `TestMain` builds nothing. The
      binaries go in one temporary directory for the test process.
    - Each nested build has a timeout (5 minutes) with a clear failure
      message, so a hang never reaches the global `go test` timeout.

### 2.2 Rejected alternatives

| Alternative | Why it is rejected |
|---|---|
| Body-less `//go:linkname` functions in ordinary `heapranges` files (no function variables) | An unwoven build fails to link (the runtime symbols do not exist). |
| Injected files in a sub-directory (`heapranges/inject/`) | otelc blank-imports the `path` of the file rule; a directory with no buildable file cannot be imported, and with `path` set to `heapranges` the file is not found. |
| `heapranges` imports `internal/config` | `internal/config` pulls in dd-trace-go, which does not build on js/wasm. |
| `internal/config` imports `heapranges` (v2) | otelc import cycle in the woven tests of `internal/build` and `heapranges` (tested by the critic). |
| `heapranges` imports `internal/build` | Same cycle: otelc blank-imports hook packages (which import `internal/config`) into the tested `internal/build` package. |
| Woven tests in the `heapranges` package | When a hook package imports `heapranges` (later PRs), the woven tests of `heapranges` get an otelc import cycle. |
| `export_test.go` for the knobs | Only the tests of `heapranges` itself could use them, and those tests must stay unwoven. |
| An env var that makes a probe fail | Production code would read a test-only env var. A link-time variable has no runtime cost. |
| Shared atomic counters in the clear hooks | A shared read-modify-write is a retry loop on arm64 without LSE. |
| An `unsafe.Pointer` field on `mspan` for the table | Stores of a pointer field can need write barriers, which the clear hooks must not run. |
| A plain `uint64` field | Not always 8-byte aligned on 32-bit platforms; `Load64` would panic if it ever ran. |
| Separate fields for the table pointer and the inline entry | 12 bytes, not 8. One field with the state machine of item 3 is enough. |
| Replace a detached table with an inline entry on a 1-object span | The 4 160-byte table would be lost for ever (a budget leak with no counter). |
| A field on `heapArena` | No operation of this PR needs one. |
| Allocate retirement queues in the sweep hook on first use | The sweep hook must not allocate. |
| Allocate queues from the first slab only, and let the refiller map the next one | With `GOMAXPROCS ≥ 64` the queues fill the first slab, and the self-test fails (Off at init). |
| A writer pushes the records of an unpublished chain back to the free list | It breaks "only the reclaimer pushes" and the ABA argument. |
| Separate slab kinds (records, tables, blocks) | 3 slabs of 1 MiB would not fit the 1 MiB minimum budget. |
| The self-test makes the gate Live, and a failed probe goes Off | Off can be reached only from Armed. |
| Global probe mode (all `Set` calls) | Narrower is safer: only the probe object skips the gate CAS. |
| Hand-written Orchestrion template next to the otelc file | Two copies drift apart. |
| `go tool <tool>` with the target `GOOS`/`GOARCH`, or `go build ./...` for a cross-build | `go tool` then builds the tool for the target, and `./...` has an otelc import cycle at `930976e`. |
| Name the drift test `TestDrift…` to match the existing gotip step | The criterion proposes `TestRuntimeDrift`. This PR changes the gotip step regex instead. |
| Split this PR in two (storage, then lifetime and CI) | The stack order is approved. The storage cannot be verified alone without its clear hooks and reuse tests. The PR is organized in commits instead (section 3). |

## 3. Steps

Each step is one commit (Conventional Commits), except step 1. Line numbers
are at `930976e`.

**How to cross-build with a tool (used in step 1, the "Cross-build" job and
`TestCompileTimeLayoutChecks`):**

```sh
# In the module of the program. No GOOS/GOARCH here: this gives the host binary.
tool=$(go tool -n orchestrion)        # or: go tool -n otelc
# Then run the host binary for the target, on one program.
GOOS=linux GOARCH=386 "$tool" go build -o "$out" ./cmd/sentinel
```

1. **Spike (no commit in the PR).** A scratch branch
   `romain.marcadier/heap-taint-ranges-spike` with a draft PR (title
   `test: check runtime weaving on all platforms`, closed after the spike;
   the branch, the title and the description have no word "design" and no
   issue ID of the tracker) runs CI on the hosted runners. The result of
   each item, with a link to the CI run, goes in the PR description. Stop,
   and ask Romain, if item A, 2 or 3 fails for one tool [ref: decision 4].
   - **A.** With Orchestrion v1.15.0 and the pinned otelc, on go1.26 and
     go1.27: add the `mspan` field (`atomic.Uint64`), inject one pushed
     runtime function, prepend the `countAlloc` prologue. The woven build
     links. An unwoven `go build ./...` of the module still links.
   - **2. otelc file rule and import graph.** The `add_file` rules with the
     files in `heapranges/` work, and `heapranges` is blank-imported into
     `main`. `scripts/otelc-test.sh` runs the `heaprangestest` tests, the
     `internal/build` tests, and the existing woven tests, with no import
     cycle.
   - **3. `init` runs.** A woven program that does not import `heapranges`,
     with both tools: `GODEBUG=inittrace=1` prints the `init` of
     `heapranges`. With `DD_IAST_TAINT_TRACKING_ENABLED=true`, the init log
     and state show `Enabled() == true`, `MappedBytes() >= 1 MiB`, and
     in-process `MemStats.OtherSys >= MappedBytes()`.
   - **4. Assembly.** `-gcflags=runtime=-S`, with a fresh `GOCACHE`, prints
     the injected functions with each tool, for linux/amd64, linux/arm64 and
     darwin/arm64 (host binary of the tool, target `GOOS`/`GOARCH`,
     `codegenprog`).
   - **5. Experiments.** `GOEXPERIMENT=runtimefreegc` and
     `GOEXPERIMENT=arenas` reach the woven build with both tools (the program
     prints the `GOEXPERIMENT` build setting, and uses the `arena` package).
   - **6. asan and msan.** One woven `-asan` build and one woven `-msan`
     build (`CC=clang`) with each tool.
   - **7. Skipped runtime aspect.** `heapranges` woven, runtime aspect
     removed: the link error names
     `runtime.ddiastHeapRangesNeedTheWovenRuntime`.
   - **8. One woven run per OS.** Run the existing woven unit tests with
     both tools on `macos-latest`, `macos-15-intel` and `ubuntu-24.04-arm`.
     The spike reported the existing Windows and macOS amd64 test failures
     before step 12. The Windows feature-off job is scoped as stated above.
   - **9. Nested build from inside a woven test.** A woven test, run with
     `go tool orchestrion go test` and with `scripts/otelc-test.sh`, builds
     and runs a first `initprog` with the helper of 2.1 item 16 (fresh
     `OTELC_WORK_DIR` for otelc). It passes with each tool, the program is
     woven, and in a `-race` run `initprog` reports `-race=true`. Also
     record the build time of each tool (for the CI time of the jobs).
2. **`feat(taint)`: read the taint tracking env vars.**
   - New `internal/taint/heapranges/env.go` (the 3 reads of item 11, with
     the keeping observer, and the 2 env var name constants), `report.go`
     (`//go:build !js && !wasip1`) and `report_other.go`
     (`//go:build js || wasip1`).
   - `internal/config` does not change.
   - `README.md:52-64`: 2 new rows (experimental, off by default; the memory
     limit range, `0`, the clamp, and the default for an invalid value).
   - Unwoven tests in `heapranges` for the parsing: `0`, clamp low, clamp
     high, negative (warning, default), invalid text. Woven subprocess test
     `TestGateOffByConfig` in `heaprangestest` (with `initprog`):
     `DD_IAST_ENABLED=false`, `DD_IAST_TAINT_TRACKING_ENABLED` unset or
     `false`, limit `0`: each gives Off with its reason.
3. **Runtime-side file, generator and rule files.** New, in
   `internal/taint/heapranges/`:
   - `runtime_inject.go`: compile-time checks of every runtime symbol it
     uses (`var _ func(uintptr) *mspan = spanOfHeap`, and the same for
     `objIndex`, `countAlloc`, `addReusableNoscan`, `gcmarkBits`, `acquirem`,
     `releasem`, `memstats.other_sys`, `gcController.mappedReady`,
     `asanenabled`, `msanenabled`, `runtimeFreegcEnabled`,
     `arm64HasATOMICS`, `MaxObjsPerSpan`, `procyield`, `osyield`,
     `nanotime`), the gate word, the classifier, the pushed entry points. It
     names no `mmap` and no platform-only symbol.
   - `heapranges_inject.go`: the body-less linknamed declarations, the
     function-variable assignment (API and `knobs`), the reference to
     `runtime.ddiastHeapRangesNeedTheWovenRuntime`.
   - `internal/knobs/knobs.go`: the knob and inspection function variables.
   - `internal/gen/main.go` and `orchestrion.yml.tmpl`: `go generate` writes
     `orchestrion.yml` (the `mspan` field, the runtime declarations with
     `links:`, the 2 prologues, the `heapranges` declarations).
   - `otelc.yml`: `add_struct_fields` on `runtime.mspan`, `add_file` into
     `runtime` and into `heapranges` (`path` = `heapranges`), 2
     `inject_code` prologues.
   - `orchestrion.tool.go:17-18` and `otel.instrumentation.go:26-27`: import
     `heapranges`.
4. **Slabs, bump allocator, budget and the background goroutine.** New
   `slab_unix.go` (`//go:build linux || darwin`, `syscall.Mmap` anonymous
   private RW, 1 MiB), `slab_other.go` (no allocator), `worker.go` (the init
   slabs of item 6; refill period; "refill needed" flag; up to 2 ready slabs
   in a lock-free ready list; budget check; Go-side "refiller paused" flag
   for the tests; accounting call that adds to `memstats.other_sys` and
   `gcController.mappedReady`; the internal "mapped bytes" counter). Runtime
   side: slab descriptors with bump indexes (item 5). Slabs are never
   unmapped.
5. **`mspan` field, entry tables, records and reads.** The state machine of
   item 3, the classifier, `MayHaveTaint` (4 or 5 loads), `Any`, `Ranges`
   (bounded: 16 records, 64 ranges), announcement slots (1 024 × 8 bytes,
   BSS), critical sections with `acquirem`.
6. **Writes.** Copy-on-write chains published by one CAS on the entry (at
   most 4 tries), the unpublished-chain rule (item 6), the merge rule (equal
   origin, marks, bits and contiguous snapshots), the 64-range bound with
   the unknown-origin tail, the 4 GiB − 1 bound, `POISON` by exchange on a
   failed real write, mandatory markers in the 3 places (entry, inline
   entry, `SPAN_POISON`), `PRIVATE`, the conflict state, memory kinds, the
   "exposed path" bit, snapshot areas and the comparison of the requested
   slice only, and the scan budget of 64 KiB. A mandatory marker with no
   place trips the breaker.
7. **Epoch-based reclamation.** Per-P retirement queues (1 024 slots of
   16 bytes: chain index and retirement epoch; one producer, one consumer;
   an append is 3 stores), allocated as in item 6; per-P counter blocks;
   `reclaimOnce` (take the batch, advance the epoch, scan the
   announcements, free only older chains, stop at the first younger slot),
   called by the background goroutine on a period of 10 ms and by
   `knobs.ReclaimRound`; the free-list pushes; the lost-capacity counter
   apart from live memory.
8. **Clear hooks.** The `countAlloc` and `addReusableNoscan` prologues
   (item 9).
9. **Gate, probe mode, circuit breaker, self-test, counters.** New
   `gate.go`, `breaker.go` (`Trip(reason)`: store 3, keep the reason, one
   counter; a scoped `recover` helper for the analysis code of later PRs),
   `selftest.go` (item 12), and the counters in
   `internal/instrumentation/telemetry/telemetry.go` and
   `internal/instrumentation/heartbeat/heartbeat.go:36-87`.
10. **Tests of the criteria** (section 4.1). New `_test.go` files in
    `internal/taint/heapranges/heaprangestest/`, and the helper programs
    `heaprangestest/internal/initprog` and
    `heaprangestest/internal/codegenprog`. Each woven test skips with
    `build.Instrumented()` (so `scripts/otelc-test.sh` selects
    `heaprangestest`). Each test has a negative control or a positive
    control first.
11. **Drift test and goldens.** New `internal/taint/heapranges/drift_test.go`
    (unwoven): parses `$(go env GOROOT)/src`, hashes the body of each hooked
    and used runtime function, lists every call site of `countAlloc`,
    `addReusableNoscan`, `(*mspan).init`, `freeSpan`, `freeManual`, `freegc`,
    `freeUserArenaChunk`, the writers of `freeindex` and `allocBits`, the
    order of the specials pass, `moveInlineMarks` and `countAlloc` in
    `(*sweepLocked).sweep`, the `_KindSpecial*` constants, the mark-bit
    layout, the `sysAlloc` accounting, and `h.spanalloc.zero = false`.
    Goldens: `testdata/runtime-go1.26.golden`,
    `testdata/runtime-go1.27.golden`. A Go minor with no golden file fails. A
    `-update` flag rewrites the goldens.
12. **Generated-code check and CI.**
    - New `heaprangestest/codegen_test.go` (`TestCompileTimeLayoutChecks`,
      section 4.1).
    - Normalize Windows separators in `scripts/otelc-test.sh` before the
      `/internal/build/otelc.yml` path match.
    - `.github/workflows/ci.yml`: the jobs of section 4.2; add them to
      `green-ci` `needs` (`:460`) and to its 2 conditions (`:463-484`);
      gotip drift step (`:333`): `-run 'Drift'` (matches `TestRuntimeDrift`
      and the drift tests of later PRs), and a `-v` grep that it ran;
      sentinel step (`:206-213`): `DD_IAST_TAINT_TRACKING_ENABLED=true`.
    - `_integration/otelc/internal/sentinel/hooks.manifest`: lines for linux
      and darwin (amd64, arm64), for "set, any, clear" and "reuse after
      sweep". `witnesses.go:10`: the 2 witnesses (the reuse witness loops
      until a new object has the same address, with a bound, and then fails
      if it did not happen).
13. **Micro benchmarks.** `heaprangestest/bench_test.go`: the 3 cases of the
    quick check (a clean object, a clean slice of a tainted object, a
    tainted slice), and `Set`, `Copy`, the sweep hook for one span of 1 024
    dead tainted objects. Numbers only, no threshold.

## 4. Tests

### 4.1 Tests of the criteria

Each woven test runs from the repository root, with each tool:

```sh
go tool orchestrion go test -count=1 -shuffle=on -run '^<Name>$' ./internal/taint/heapranges/heaprangestest/
scripts/otelc-test.sh -count=1 -shuffle=on '-run=^<Name>$'
```

(`scripts/otelc-test.sh` rejects `-run '^<Name>$'` with a space. The PR
description uses `'-run=^<Name>$'`.)

| Criterion | Test or CI job | What it checks (and its negative or positive control) |
|---|---|---|
| AC-P4 | CI jobs "Platform tests" on linux/arm64, darwin/arm64 (both tools, oldstable and stable) and darwin/amd64 (`macos-15-intel`, both tools, stable) | Run every woven unit test (`go tool orchestrion go test ./...`, `scripts/otelc-test.sh`) and the `_integration/otelc` tests. A "tests ran" step runs `TestClearBeforeReuse` with `-count=1 -v` and greps `--- PASS: TestClearBeforeReuse `. darwin/amd64 is in CI; if the runner is not available, a recorded manual run, labeled "manual", is linked in the PR. |
| AC-P5 | `TestOffOnUnsupportedPlatforms`; CI jobs "Feature off" (windows/amd64, linux/amd64 `-asan`, linux/amd64 `-msan`, both tools) and "Cross-build (build only)" (linux/386, freebsd/amd64, both tools) | The test runs `initprog` with `DD_IAST_TAINT_TRACKING_ENABLED=true`. `initprog` is built with the `-asan`, `-msan` and `-race` flags of the test binary (2.1 item 16), and the test first checks that the settings that `initprog` prints are equal to those of the test binary (else it fails: the flags were not passed). On an unsupported build, `Enabled()` is false, the gate is Off with the reason "platform", `Set` returns false, the internal mapped counter is 0. On a supported build it checks the platform table function, and that the same subprocess is On (positive control). "Cross-build" uses the host binary of each tool (`go tool -n`), and builds one woven program for each target: `_integration/otelc/cmd/sentinel` for linux/386 and freebsd/amd64. |
| AC-P6 | `TestRuntimeDrift` (unwoven: `go test -count=1 -run '^TestRuntimeDrift$' ./internal/taint/heapranges/`) | Golden match for go1.26 and go1.27. Negative controls in the test: a changed body hash fails, a missing call site fails, a minor with no golden file fails. |
| AC-P7 | `TestCompileTimeLayoutChecks` (runs only when `DD_IAST_CODEGEN_CHECK=1`, in the "Codegen check" job; else it skips with a message) | (1) Every runtime identifier that `runtime_inject.go` uses has a `var _ T = sym` check (parsed with `go/ast`); a copy of the file with one check removed fails the test. (2) For linux/amd64, linux/arm64 and darwin/arm64: the host binary of **the tool that runs the test** (`build.Tool()`, then `go tool -n`), the target `GOOS`/`GOARCH`, **one fresh `GOCACHE`** (`t.TempDir()`, shared by the 3 ABIs), `-gcflags=runtime=-S`, on `codegenprog` (otelc with `OTELC_RULES` set to the `heapranges` rule file, and a fresh `OTELC_WORK_DIR`). Positive control: each expected symbol (each entry point, the classifier, the 2 clear hooks) is in the output; a missing symbol fails. Each entry point and the classifier is `STEXT nosplit`; every function that the classifier calls, directly or indirectly, is `STEXT nosplit`. The 2 clear hooks and all their callees: `STEXT nosplit`, and no `CALL` to `runtime.gcWriteBarrier*`, `runtime.panicIndex*`, `runtime.panicBounds*`, `runtime.panicdivide*`, `runtime.panicshift`, `runtime.panicunsafe*`, `runtime.panicmem*`, `runtime.throw`, `runtime.mallocgc*` or `runtime.lock*`. The `MayHaveTaint` fast path has no load of the knob word. |
| AC-P8 | CI job "Generated template" | `go generate ./internal/taint/heapranges/...` then `git diff --exit-code`. |
| AC-P11 | CI job "arm64 baseline" (`ubuntu-24.04-arm`, `GOARM64=v8.0`, `GODEBUG=cpu.atomics=off`, both tools) | Runs the positive heap range tests (`TestSetCopyClear`, `TestClearBeforeReuse`, `TestConcurrentNeighbours`) with `-count=1 -v`, and greps `--- PASS:` for each. A test asserts that the runtime sees `arm64HasATOMICS == false` (proof that the retry loops ran). |
| AC-S4 | `TestTaintMemoryLimitAndNoWaiting` | **Limit:** `initprog` with a 2 MiB limit taints until drops. The internal mapped counter is ≤ the limit; the `OtherSys` delta is **≥** the mapped bytes; the internal mapped counter **==** the bytes that the allocator mapped (counted in `slab_unix.go`). **Queues in the budget:** `initprog` with `GOMAXPROCS=128` and the default limit: the gate is Live, 128 queues exist, and the init mapped 3 slabs. `initprog` with `GOMAXPROCS=128` and a 1 MiB limit: the gate is Live, 16 queues exist (the cap), and a retirement on a P index of 16 or more (knob) counts lost capacity while the entry is cleared. **Reuse:** round 1 taints, frees (a GC) and reclaims many objects; then the refiller is paused (the **Go-side flag**, not a spin pause, because the next rounds need a GC); rounds 2 to 10 taint, free and reclaim again: after each round the records in use go back to the round-1 baseline, and no record comes from a bump (the bump counters of records do not change). Tables are reported, and the test checks that the table count is ≤ the number of distinct `mspan` structs that held a tainted object. **No waiting:** refiller paused, ready list and free list empty: `Set` returns false in less than 100 ms, the slab count does not change (no `mmap`), the drop counter grows; after resume, a slab is mapped. **Lost capacity:** full queue knob, P index above the maximum knob, and an unpublished chain with a full queue: entries are cleared, lost capacity grows, live memory is a separate number. |
| AC-S7 | `TestClearBeforeReuse`; CI jobs "Runtime experiments" (`runtimefreegc`, `nogreenteagc`, `arenas`; both tools) and "Stack move" (both tools) | Sweep reuse for 10 sizes from 8 B to 1 MiB, 2 000 objects each, with proof of reuse (equal addresses). The 1 MiB objects are made in batches of 64 (bounded CI memory). **`freegc`** (only in `runtimefreegc`): an `append` loop on a local slice (the compiler path `growsliceNoAlias`); the address of the old array goes to `Set` through a helper that does not make it escape. Positive control: the per-P "cleared by `addReusableNoscan`" counter grows by 1, and the new object at that address is clean. A refused `freegc` (small size) clears nothing (counter unchanged), and a tainted neighbour keeps its ranges. Tiny block with an interior finalizer that revives: every object keeps its ranges (same block, checked by address; non-race build). 10 000 cleanups on a live object: it keeps its ranges, a dead neighbour is cleared. Detached table on a reused `mspan`; forced stale table (knob): clean for readers and writers, reset by the next sweep. 4 GiB object refused by `Set` and `Copy` (a lazy allocation; skipped on 32-bit and under `-race`). Reads on stack, static and manual-span memory: clean, no table touched. **User-arena memory** (only in `arenas`): `Set` refuses, reads are clean, no table touched. **Stack buffer** (only in "Stack move", built with `-gcflags=all=-d=maymorestack=runtime.mayMoreStackMove`): refused for reads and writes. Green Tea inline mark bits: live and dead tainted objects in one small-object span (and the same in `nogreenteagc`). Random model test (seeded; the seed is in the failure message). Negative controls: with each clear hook off (knob), the matching subtest fails. |
| AC-S10 | `TestRecordLifetimeUnderConcurrency` | With pause knobs (2.1 item 8), and reclaimer rounds from `knobs.ReclaimRound` (synchronous, same code path; the background reclaimer is paused by its Go-side flag during these cases): (1) reader paused mid-chain while the chain is replaced, retired and the pool is cycled; (2) writer paused before its CAS while its old chain is retired and its record indexes would be reused **more than 256 times** (300 synchronous rounds, well inside the 2 s bound); (3) 2 writers on one entry (each chain retired exactly once, no record in 2 chains after the pool cycles); (4) a retirement after the batch was taken is not freed in that round; (5) full queue; (6) concurrent `Set`, `Copy`, `Clear` and sweeps under load (no pause knob in this case; the background reclaimer runs; the free list stays consistent); (7) an unpublished chain (CAS lost 4 times, and a pop failed in the middle of a chain): its records are in the retirement queue of the P, are freed only after a reclaimer round, and are never in 2 chains; (8) the free-list ABA case: a writer paused between its read of the head and its CAS, while other writers pop and the reclaimer pushes: its CAS fails. Negative control: with a knob that skips the announcement, case 1 detects the reuse. Each case fails when a pause timed out. |
| AC-S13 | `TestReservedEntryValues` | `PRIVATE` and `POISON` never followed and never in a queue (queues inspected); `PRIVATE` kept across a sweep, a clear of the last range and a refill; reset to 0 when the object dies (sweep and `addReusableNoscan`); `SPAN_POISON` stored with the budget full before the first table, for an ordinary range, a sensitive range and an unknown range; every object of the span poisoned; a failed source label in place only dropped; a buffer allocated in that span never private; reset only when no object is live; a large object uses its inline entry; `Clear` and a clean `Copy` on a 1-object span give field `0` (`INLINE(e) → 0`); the table of another span (knob) trips the breaker. **`mspan` struct reuse:** one struct is reused small (many objects, gets a table) → 1-object (size class 67, 32 KiB: uses entry 0 of the existing table, never `INLINE`) → small again: the table count does not grow, and no stale inline value or entry is read. A struct first used with `INLINE`, then reused for a small span: the field is `0` after the sweep, and the small span gets a table. At each sweep that frees a span, the field is `0` or a detached table. |

Other tests (not mapped to a criterion of this PR):
`TestSelfTestFailureKeepsGateOff` (`initprog` built with
`-ldflags=-X …heapranges.probeFailure=any`: the gate is Off, the reason
names the probe, and the runtime-side count of `CAS(0 → 1)` successes is 0;
a second build makes the probe panic: Off with the reason "panic", and the
program exits 0), `TestGateOffByConfig` (step 2), `TestSetCopyClear`,
`TestConcurrentNeighbours`, the import test of `heapranges` (2.1 item 14),
and the escape check of the API (`-gcflags=-m`: the pointer arguments do
not escape).

### 4.2 New CI jobs (in `.github/workflows/ci.yml`, required by "Green CI")

Every "tests ran" step uses `-count=1 -v` and greps `--- PASS: <Name> `.

| Job name | Runner | Matrix | Steps |
|---|---|---|---|
| Platform tests | `ubuntu-24.04-arm`, `macos-latest`, `macos-15-intel` | tool × Go (`macos-15-intel`: stable only) | Woven unit tests, otelc script, `_integration/otelc` tests, "tests ran" step |
| arm64 baseline | `ubuntu-24.04-arm` | tool | `GOARM64=v8.0`, `GODEBUG=cpu.atomics=off`, the positive tests, "tests ran" step |
| Feature off | `windows-latest`; `ubuntu-latest` with `-asan` (gcc); `ubuntu-latest` with `-msan` (`CC=clang`) | tool × Go on Windows; tool on Linux | `TestOffOnUnsupportedPlatforms` and the woven unit tests, "tests ran" step. On Windows run only `./internal/taint/heapranges/...`. |
| Cross-build (build only) | `ubuntu-latest` | tool × (linux/386, freebsd/amd64) | `tool=$(go tool -n <tool>)` (no `GOOS`/`GOARCH`); then `GOOS=… GOARCH=… "$tool" go build` of `_integration/otelc/cmd/sentinel` |
| Runtime experiments | `ubuntu-latest` | tool × (`runtimefreegc`, `nogreenteagc`, `arenas`) | `GOEXPERIMENT=<value>`; `TestClearBeforeReuse` and `TestReservedEntryValues`, "tests ran" step |
| Stack move | `ubuntu-latest` | tool | `-gcflags=all=-d=maymorestack=runtime.mayMoreStackMove`; `TestClearBeforeReuse`, "tests ran" step |
| Codegen check | `ubuntu-latest` | tool × Go | `DD_IAST_CODEGEN_CHECK=1`; `TestCompileTimeLayoutChecks`, "tests ran" step |
| Generated template | `ubuntu-latest` | – | `go generate` and `git diff --exit-code` |

The existing jobs also run the new tests: "Unit Tests" (both tools, both Go
versions), "Race" (both tools), "Sentinel" (now with taint tracking on), and
gotip (drift and sentinel, signal only). In these jobs
`TestCompileTimeLayoutChecks` skips (no `DD_IAST_CODEGEN_CHECK`).

### 4.3 Commands before each commit

```sh
gofmt -l $(git ls-files '*.go')
go vet ./...
go tool checklocks ./...
go test -shuffle=on ./...                       # unwoven: drift, import, escape, env var tests
go tool orchestrion go test -shuffle=on ./...   # woven, Orchestrion
scripts/otelc-test.sh -shuffle=on               # woven, otelc
go generate ./internal/taint/heapranges/... && git diff --exit-code
(cd _integration/otelc && go tool orchestrion go build -o /tmp/s ./cmd/sentinel && DD_IAST_TAINT_TRACKING_ENABLED=true /tmp/s)
(cd _integration/otelc && go tool otelc go build -o /tmp/s ./cmd/sentinel && DD_IAST_TAINT_TRACKING_ENABLED=true /tmp/s)
```

### 4.4 Clean-room similarity scan (reproducible)

Run from the repository root, at the head of the PR. It needs `gh`, `jq` and
Node.js (for `jscpd`). It downloads the 3 PoC heads read-only (no change to
the repository). Notes:
- Paths are physical (`pwd -P`), because `jscpd --absolute` writes resolved
  paths (on macOS, `/var` is a link to `/private/var`).
- `jscpd` skips, with no message, files of more than 1 000 lines or 100 KB
  (its defaults). `--max-lines 1000000 --max-size 100mb` removes this limit,
  and the scan fails when `jscpd` did not read every input file.
- The scan reads only Go and YAML files (`--format go,yaml`), on both sides.
- The positive control is a known 40-line copy, in a file of more than
  1 000 lines. The scan must find it, else the command fails.

```sh
set -euo pipefail
base=930976e
poc=$(cd "$(mktemp -d)" && pwd -P)
ctl=$(cd "$(mktemp -d)" && pwd -P)
for pr in 39 52 58; do
  sha=$(gh pr view "$pr" --repo DataDog/dd-iast-go --json headRefOid -q .headRefOid)
  echo "PR #$pr head: $sha"
  mkdir -p "$poc/$pr"
  gh api "repos/DataDog/dd-iast-go/tarball/$sha" | tar -xz -C "$poc/$pr" --strip-components=1
done
count() { find "$@" -type f \( -name '*.go' -o -name '*.yml' -o -name '*.yaml' \) | wc -l | tr -d ' '; }
poc_files=$(count "$poc")

# "Ours": a copy of the changed Go and YAML files (outside _docs/).
mkdir -p "$ctl/ours"
git diff --name-only --diff-filter=d "$base"..HEAD -- '*.go' '*.yml' '*.yaml' \
  | grep -v '^_docs/' | tar -cf - -T - | tar -xf - -C "$ctl/ours"

scan() { # $1: output directory; $2: number of "ours" files; other arguments: "ours" paths
  out=$1; ours_files=$2; shift 2
  npx --yes jscpd@4.3.0 --absolute --no-gitignore --format go,yaml \
    --max-lines 1000000 --max-size 100mb --min-lines 8 --min-tokens 50 \
    --mode strict --reporters json --output "$out" "$@" "$poc/39" "$poc/52" "$poc/58" >/dev/null
  read_files=$(jq '.statistics.total.sources' "$out/jscpd-report.json")
  want=$((ours_files + poc_files))
  if [ "$read_files" -ne "$want" ]; then
    echo "jscpd read $read_files files, want $want: a file was skipped" >&2; exit 1
  fi
  jq --arg poc "$poc" '[.duplicates[]
    | select((.firstFile.name | startswith($poc)) != (.secondFile.name | startswith($poc)))
    | {poc: ([.firstFile.name, .secondFile.name] | map(select(startswith($poc))) | first),
       ours: ([.firstFile.name, .secondFile.name] | map(select(startswith($poc) | not)) | first),
       lines}]' "$out/jscpd-report.json"
}

# 1. Positive control: a known copy of 40 lines of a PoC file, appended to a
#    copy of a large file of this PR (more than 1 000 lines).
mkdir -p "$ctl/control"
cp internal/taint/heapranges/runtime_inject.go "$ctl/control/planted.go"
src=$(find "$poc/58" -name '*.go' -size +8k | sort | head -n 1)
sed -n '20,59p' "$src" >> "$ctl/control/planted.go"
[ "$(wc -l < "$ctl/control/planted.go")" -gt 1000 ] \
  || { echo "the control file must have more than 1 000 lines" >&2; exit 1; }
scan "$ctl/report-control" 1 "$ctl/control" \
  | jq -e --arg f "$ctl/control/planted.go" 'any(.[]; .ours == $f)' >/dev/null \
  || { echo "positive control NOT found: the scan does not work" >&2; exit 1; }
echo "positive control: found"
rm -r "$ctl/control"

# 2. The real scan.
scan "$ctl/report" "$(count "$ctl/ours")" "$ctl/ours"
```

The PR description gives the 3 head SHAs, the command, the result of the
positive control ("found"), and the result of the real scan: the list of
runs of 8 or more equal lines between this PR and a PoC (expected: none, or
only the license header and imports, each one explained).

## 5. Acceptance checklist (for the Reviewers)

- [ ] AC-P4: "Platform tests" jobs green on linux/arm64, darwin/arm64,
      darwin/amd64 with both tools; their "tests ran" steps passed.
- [ ] AC-P5: "Feature off" (windows, asan, msan) green and executed;
      "Cross-build (build only)" (386, freebsd) green, with the host
      tool binary and one program per target; `TestOffOnUnsupportedPlatforms`
      passed with both tools,
      and in the asan and msan jobs `initprog` reported the same sanitizer
      setting as the test binary.
      Decision 28 records option (b).
- [ ] AC-P6: `TestRuntimeDrift` passes on go1.26 and go1.27; its negative
      controls exist; the gotip step runs it (`-run 'Drift'`).
- [ ] AC-P7: "Codegen check" jobs green with both tools and both Go
      versions; the output for the 3 ABIs is in the job log; the positive
      symbol checks exist; the deny list is complete.
- [ ] AC-P8: "Generated template" job green.
- [ ] AC-P11: "arm64 baseline" job green; the `arm64HasATOMICS == false`
      assertion passed.
- [ ] AC-S4: `TestTaintMemoryLimitAndNoWaiting` passes with both tools,
      with the `GOMAXPROCS=128` cases.
- [ ] AC-S7: `TestClearBeforeReuse` passes with both tools, in the default
      build, `runtimefreegc`, `nogreenteagc`, `arenas` and "Stack move"; the
      `addReusableNoscan` positive control passed; the negative controls fail
      when a hook is off.
- [ ] AC-S10: `TestRecordLifetimeUnderConcurrency` (8 cases) passes with both
      tools and in the "Race" job; no pause timed out.
- [ ] AC-S13: `TestReservedEntryValues` passes with both tools and in
      `runtimefreegc`, with the `mspan` reuse cases and `INLINE(e) → 0`.
- [ ] Off by default: with no env var, `Enabled()` is false and no slab is
      mapped; `DD_IAST_ENABLED=false` is Off; WEAK_HASH, WEAK_CIPHER and
      deduplication tests and system-tests stay green.
- [ ] Import graph: no non-test file of `heapranges` imports
      `internal/build` or `internal/config`; `internal/config` does not
      import `heapranges`; the woven tests are only in `heaprangestest`.
- [ ] The clear hooks use only per-P counters (load and store), and the queue
      producer index is a store.
- [ ] Parity: `orchestrion.yml` (generated) and `otelc.yml` have the same
      targets (1 `mspan` field, runtime declarations, `heapranges`
      declarations, 2 prologues); both force the link and the `init`.
- [ ] `runtime_inject.go` names no `mmap` and no platform-only symbol; the
      Windows job compiles it.
- [ ] No identifier of the design or the plan in any changed file outside
      `_docs/` (code, tests, `testdata/`, `.github/`, `hooks.manifest`, the
      sentinel). These 2 commands (they need ripgrep, `rg`) print nothing, or
      each hit is checked by hand:

      ```sh
      files=$(git diff --name-only --diff-filter=d 930976e..HEAD | grep -v '^_docs/' || true)
      # With no path, rg searches the whole tree (_docs/ included): stop.
      [ -n "$files" ] || { echo "no changed file outside _docs/" >&2; exit 1; }
      # IDs: case-sensitive, so Go names such as s1, t2 or h1 do not match.
      rg -n 'AC-[A-Z]|\bS[0-9]{1,2}\b|\bX1\b|\bT[0-9]{1,2}\b|\b(C(8|9|1[0-5])|H[1-5])\b|PR ?#51' $files
      # Words: case-insensitive.
      rg -n -i '\b(decision|section) [0-9]' $files
      ```
- [ ] Branch name, PR title and PR description: no word "design", no issue
      ID of the tracker. The same for the spike branch and its draft PR.
- [ ] Clean room: the PR description has "No code in this PR is copied from
      PR #39, #52 or #58.", the positive control result ("found") and the
      result of the command of 4.4.
- [ ] `README.md` has the 2 env var rows (type, default, range, effect).
- [ ] `gofmt`, `go vet`, `checklocks` clean.
- [ ] Every new review finding has a test in this PR.

## 6. Risks

| Risk | Effect | How the plan reduces it |
|---|---|---|
| A tool cannot add a field to `runtime.mspan`, inject into `runtime`, or prepend to a runtime method | The PR cannot be built for one tool | Step 1 item A, before any other work; a failure stops the PR and goes to Romain. |
| An otelc import cycle in the woven tests (now or in a later PR) | `scripts/otelc-test.sh` fails | No `internal/build` and no `internal/config` in `heapranges`; woven tests only in `heaprangestest`; the rule for later PRs is in the package doc; spike item 2. |
| A fault in the runtime-side code crashes the host (no `recover` there) | Host crash | Off by default; bounded loops; explicit bounds, division and shift checks, with no panic call (checked in the assembly); no allocation, no lock, no write barrier in the clear hooks (`//go:nowritebarrierrec`, the `atomic.Uint64` field); `nosplit` proof; the random model test and the forced interleavings. |
| A panic in the self-test at init | The application does not start | The self-test runs under `recover`; a panic gives Off; the test with the panicking probe checks that the program exits 0. |
| A reuse path that the clear hooks do not see | A stale range on a new object | Drift test of every free and reuse path; stale ranges have the origin of an ended request (foreign, no finding); proof-of-reuse tests for 10 sizes, `freegc`, `nogreenteagc`, `arenas`. |
| A table lost by a field transition | Budget leak with no counter | The state machine never replaces a table; the invariant test at each span free; the table count ≤ the `mspan` struct count. |
| Large hosts (`GOMAXPROCS` 64 to 1 024) | Off at init, or most of the budget in queues | Init maps the slabs of the queues and the self-test synchronously; the queue cap is one quarter of the budget; the `GOMAXPROCS=128` tests. |
| A retry loop in the sweep hook on arm64 without LSE | A cost that the design forbids | Per-P counters and the queue index use a load and a store; the "arm64 baseline" job; the bounded-work criterion of a later PR counts the operations. |
| An unwoven build stops linking | Users and `go test ./...` break | Function variables, not body-less functions, in ordinary files; spike item A; the existing unwoven CI steps cover it. |
| Woven runtime in every test binary of the module changes existing tests | Existing tests fail or slow down | Off by default; spike item 8 runs the existing woven tests on every new OS first; the existing jobs run with the woven runtime from this PR. |
| Test knobs cost time on the hot path | Slower clean path | Knobs are read only on slow paths; the generated-code test checks the `MayHaveTaint` fast path. |
| Pause knobs deadlock with a stop-the-world | CI hangs | `GOMAXPROCS`, GC percent and memory limit set before the first pause; no stop-the-world call while a pause is held (enforced by a test helper); synchronous reclaimer rounds; a 2 s bound on each pause, then a test failure. |
| Flaky GC tests | Red CI with no defect | Reuse loops with a bound and a clear failure message; seeded random tests that print the seed; 1 MiB objects in batches; 100 ms (not 1 ms) for "no waiting". |
| macOS and Windows runners are slow or not available | Long CI | `macos-15-intel` on stable only; manual darwin/amd64 evidence as the documented fallback. |
| `-asan` or `-msan` builds fail with a tool for a reason that is not ours | Red "Feature off" job | Spike item 6; a tool defect is reported to Romain with the error, not hidden. |
| `TestCompileTimeLayoutChecks` is slow (3 fresh woven builds of the runtime) | Longer CI | It runs only in the "Codegen check" job (4 jobs); one fresh cache for the 3 ABIs; it skips in every other job. |
| The clean-room scan reports nothing because it is broken | A copy is not found | The positive control (in a file of more than 1 000 lines) must be found first; the scan fails when `jscpd` did not read every input file; no file size limit. |
| A nested build from inside a woven test hangs, or builds another variant than the test binary | otelc tests time out; a sanitizer test tests a normal build | A fresh `OTELC_WORK_DIR` for each nested otelc command; the `-asan`, `-msan` and `-race` flags passed on and checked in the output of `initprog`; a 5-minute timeout on each nested build; spike item 9. |

## 7. Out of scope

- The runtime lowering hooks (`concatstrings`, `growslice`, …), the bypass
  token, and the unsafe-context checks: the next PR in the dependency graph.
- The request owner, the origin registry, the real snapshot owners, the
  `runtime.g` fields: a later PR. This PR uses test origins and test owner
  slots.
- Sources, sinks, standard library wrappers, JSON, the scoped `recover` in
  analysis code (only the helper is here), the bounded-work criterion of the
  transforms, the circuit breaker criterion: later PRs.
- The benchmark report: a later PR. This PR adds micro benchmarks only.
- Unmapping slabs (not in v0).
- Any change to the design document, and any change to `internal/config`.

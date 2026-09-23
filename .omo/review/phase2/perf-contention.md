# perf-contention: lock contention in the taint store and request admission
Verdict: Nothing in scope blocks on the propagation or lookup hot path, so there is no deadlock and no lock that makes every request wait. Two try-locks cause measurable silent false negatives, though. The global `Store.ownerMu` try-lock drops 15-70% of sampled requests even when free capacity exists. The exclusive `sourceMu` try-lock makes concurrent visitors in the same request miss taint. The one blocking global lock, `overflowMu`, is held across the whole 512-root `Finish` loop, and it accounts for about 95-99% of all mutex delay.

Scope covered: `internal/taint/store/{store,value,lookup,owner,root,overflow,limits}.go` and the lock sites in `binding.go`, `writer.go` and `mutation.go`. `internal/taint/request/{scope,owner,lookup,http,lazy}.go`. I wrote parallel benchmarks (`b.RunParallel`) and deterministic mechanism tests in a private copy. They ran with `-cpu=1,(2,)4,8,16`, `-count=3`, `-mutexprofile` and `-blockprofile` under `GOTOOLCHAIN=go1.26.6`. All sources, raw outputs, pprof files and top-N text are in `.omo/review/evidence/perf-contention/`, and `SUMMARY.txt` holds the medians and commands.

**Noise caveat:** the machine was shared with about 15 agents. A serial pure-CPU control (`BenchmarkPCWorkUnit`) ranged from 4.4 to 38 us/op across runs, so treat the ns/op scaling ratios as indicative only. The drop and miss rates, and the ranking of locks in the profiles, are robust to this noise. Load mostly reduces real overlap, so if anything the measured rates are understated.

**Scaling summary** (median ns/op; scale = cpu1/cpuN):

| Benchmark | cpu1 | cpu16 | scale | loss metric at cpu16 |
|---|---|---|---|---|
| `MayContain` hit (read-only gate) | 91 ns | 31 ns | 3.0x | 0 misses |
| `Lookup` hit, distinct keys | 1459 ns | 372 ns | 3.9x | 0 misses |
| `Lookup`, same key from all goroutines | 1568 ns | 370 ns | 4.2x | 0 misses |
| `Derive`, own owner, tight loop | 78 ns | 27 ns | 2.9x | 4.0% of derives dropped (4 cpus: 1.1%) |
| Mixed derive + lookup, per-request owners | 578 ns | 113 ns | 5.1x | 0.17% of reads miss, 0.7% of writes fail |
| Store request lifecycle (Acquire, 8 sources, Finish, plus handler work) | 11.7 us | 2.9 us | 4.1x | 75% of Acquires fail; 0.9% of requests lose a source |
| `request.Begin`, 8 sources, `Finish` (max=64) | 24.2 us | 2.9 us | 8.5x | 70% of permitted requests dropped |
| Intra-request visitors only | 773 ns | 417 ns | 1.9x | 19.8% of visits miss (4 cpus: 4.5%) |

**Top contended locks:** `-mutexprofile` measures delay on blocking locks only. Try-lock failures never appear in it, so they are measured by the loss counters above.

- **Store package:** `sync.(*Mutex).Unlock` at `store/owner.go:203` accounts for 94.9% (54.8 s) of mutex delay, and 99.4% in the second run. This is the global `overflowMu`, taken at `owner.go:182`.
- **Request package:** the same site accounts for 96.9% of delay, reached through `Analysis.Finish` at `request/owner.go:270`.
- **Block profile:** `owner.go:182 overflowMu.Lock` is 33-42% of all blocking. The remainder is test-harness channel and WaitGroup waits.
- **No other in-scope lock appears.**

## Findings
### perf-contention-F1: A global `ownerMu` try-lock in `Store.Acquire` drops sampled requests even when capacity is free
- Severity: High
- Category: false-negative
- Location: internal/taint/store/owner.go:24-28 (critical section 29-61); internal/taint/request/owner.go:83-86; internal/taint/request/scope.go:95-98
- Claim: After a request passes sampling and wins a permit through the CAS bitset (`request/owner.go:65-80`), `Store.Acquire` still takes the process-global `ownerMu` with `TryLock`. If any other request is inside `Acquire` at that moment, the permit is released and the request becomes `DecisionCapacityDropped`, even though up to 64 owners are free. The critical section is not trivial: a linear owner scan, then clearing the chosen owner's 8 `writerRecord`s (each holds a 1.5 KiB `ranges.Set`, about 13 KiB in total), 24 atomic stores and a counter reset. Serial `Acquire` plus `Finish` costs about 1.2 us. The losses are measured, silent, and never reported through telemetry (`AcquireDrops()` has no production caller):
  - **Default config (`MaxConcurrentRequests=2`):** 18% of permitted requests are dropped at 2 cpus, and 15-41% at 4-16 cpus.
  - **`MaxConcurrentRequests=64`:** 39%, 61%, 71% and 70% of permitted requests are dropped at 2, 4, 8 and 16 cpus.
  - **`Manager.Acquire`/`Finish` alone (max 16/64):** 73-86% of calls fail.
  - **Effect:** the effective sampling rate is several times lower than configured, and the vulnerabilities in the dropped requests are never reported.

  The lock is not needed for correctness: the permit CAS already serializes admission, so each permit index could map 1:1 to a store owner slot, or slots could be claimed with a CAS on `owner.state`.
- Evidence:
  - Deterministic mechanism test: `.omo/review/evidence/perf-contention/store_zz_perf_contention_test.go` (`TestPCAcquireDroppedWithFreeCapacity`), run with `go test -run TestPC -v ./internal/taint/store`. It prints `Acquire with 64 free owners while ownerMu held: disabled=true acquireDrops=1` (see `mechanism.test.txt`).
  - Rate: `request_zz_perf_contention_test.go` (`BenchmarkPCBeginRequestFinish`, `...Default2`, `BenchmarkPCAdmissionMax*`) and `store_zz_perf_contention_test.go` (`BenchmarkPCRequestLifecycle`), run with `go test -run '^$' -bench 'PCBeginRequestFinish' -benchtime=200ms -count=3 -cpu=1,2,4,8,16 ./internal/taint/request`. `request2.bench.txt` shows, for example, `BenchmarkPCBeginRequestFinish-8 ... 0.7051 storedrop/permitted` and `BenchmarkPCBeginRequestFinishDefault2-8 ... 0.4055 storedrop/permitted`. `request.bench.txt` shows `BenchmarkPCAdmissionMax64-16 ... 0.7274 storeacqdrop/op`.
- Fix: Remove `ownerMu` from the admission path. Claim the owner slot with `owner.state.CompareAndSwap(unused|dead -> active)` in the scan and do the reset after winning the CAS, or bind permit index i to owner slot i. Move the writer-table clearing out of any global critical section. At minimum, retry the try-lock a bounded number of times before dropping, and export `AcquireDrops` to telemetry.

### perf-contention-F2: The exclusive `sourceMu` try-lock on the read path makes concurrent visitors in one request see a tainted value as clean
- Severity: Medium
- Category: false-negative
- Location: internal/taint/request/lookup.go:143-157 (`copySources`); internal/taint/request/owner.go:25, 139, 173, 206, 235, 247
- Claim: Every `VisitString`/`IsTaintedString` hit, including sink evidence collection (`evidence/evidence.go:112,156`) and the public `taint.IsTainted*`, resolves sources under the request slot's `sourceMu`. That is a plain `sync.Mutex` taken with `TryLock`. Two goroutines of the same request that read concurrently therefore make each other miss: one of them reports the value clean, and a sink reached in parallel can silently skip a real vulnerability. A read racing a source add fails the same way. Different requests do not interfere, because the lock is per slot. Measured rates in tight loops:
  - **Visitors only:** 0.07%, 4.5%, 6.2% and 19.8% of visits miss at 2, 4, 8 and 16 goroutines.
  - **Visitors racing duplicate source adds:** 91-99% of visits miss.

  Real handlers have fewer overlapping visits, so real rates are lower, but the mechanism is deterministic.
- Evidence:
  - Deterministic mechanism test: `request_zz_perf_contention_test.go` (`TestPCConcurrentVisitorSeesClean`), run with `go test -run TestPC -v ./internal/taint/request`. It prints `IsTaintedString(tainted) while a concurrent visitor holds sourceMu = false (after release: true)`.
  - Rate: `BenchmarkPCIntraRequestVisitOnly` and `BenchmarkPCIntraRequestSourceVsVisit`. `request2.bench.txt` shows `...VisitOnly-16 ... 0.1978 visitmiss/visit`, and `request.bench.txt` shows `...SourceVsVisit-8 ... 0.9911 visitmiss/visit`.
  - Strictly this is a High-category mechanism (a false negative at a supported sink). I rated it Medium because it needs concurrency within a single request.
- Fix: Make `sourceMu` a `sync.RWMutex` and use `TryRLock` in `copySources`, `Source` and `SourceCount`, which removes reader-versus-reader misses. Better still, since the table is append-only per generation, publish entries with an atomic count (seqlock or an immutable prefix) so readers take no lock. Alternatively, because the critical section is a bounded copy of at most 64 entries, block briefly instead of dropping.

### perf-contention-F3: `Owner.Finish` holds the global `overflowMu` across the whole 512-root loop, which serializes finishes and truncates other requests' ranges
- Severity: Medium
- Category: perf
- Location: internal/taint/store/owner.go:181-203; internal/taint/store/overflow.go:8-18; internal/taint/store/root.go:354-358
- Claim: `Finish` takes the process-global blocking `overflowMu` for all 512 `rootRecord`s, clearing about 320 B each (roughly 160 KiB of stores), no matter how many roots were used or whether any root has an overflow block. The consequences:
  - **Finish is serialized process-wide.** This is the dominant contended lock in every profile, at 94.9-99.4% of mutex delay and 33-42% of blocking delay.
  - **Other requests lose ranges.** Their `allocateOverflow` uses `TryLock` on the same mutex, so a publish that needs more than 10 ranges (possible only when `DD_IAST_MAX_RANGE_COUNT` > 10) is silently truncated to `GuaranteedRanges=10` whenever any request is finishing. The truncation drops later sources, a provenance loss that crosses requests: 0.84-1.09 truncations per 8-publish request at 4-16 cpus, i.e. 10-14% of multi-range publishes.

  Serial `Finish` with a single root costs about 1.5-3.2 us.
- Evidence:
  - Deterministic mechanism test: `store_zz_perf_contention_test.go` (`TestPCOverflowTruncatedDuringOtherFinish`) prints `adopted=true inputRanges=20 storedRanges=10 truncationDrops=1`.
  - Rate: `BenchmarkPCRequestLifecycleOverflow`. `store2.bench.txt` shows `-16 ... 1.089 rangetrunc/op`.
  - Profiles: `store.mutex.top.txt` shows `52.02s 94.92% sync.(*Mutex).Unlock ... store.(*Owner).Finish owner.go:203`. `request.mutex.top.txt` shows 96.9% at the same site. `store.block.top.txt` points to `owner.go:182`.
- Fix: Iterate only `[0, rootNext)`. Collect the non-zero `root.overflow` indices while holding only `rootsMu`, then free them in one short `overflowMu` section, or skip `overflowMu` entirely when no root has an overflow block. Alternatively, make the overflow pool per owner.

### perf-contention-F4: Shard and owner try-lock drops are small but invisible
- Severity: Low
- Category: false-negative
- Location: internal/taint/store/value.go:116-138; internal/taint/store/lookup.go:87-89, 114-116, 148-159; internal/taint/store/owner.go:119-125
- Claim: This is by design (digest check 25), so I report measured rates rather than a defect. With per-request owners on 256 shards:
  - **Source publication:** in a realistic lifecycle, 0.9-2.1% of requests (8 sources each) lose a source, so taint is never applied.
  - **Derive:** 1.1-4.0% of derives are dropped in a tight derive loop.
  - **Reads:** 0.08-0.17% of gate or lookup reads miss when mixed with other requests' writes.

  Contention between readers alone is never lost. The owner `Counters()` that record these losses, and `Store.AcquireDrops()`, have no production caller, so contention loss cannot be observed in the field.
- Evidence: `store.bench.txt` (`BenchmarkPCDeriveOwnOwner-16 ... 0.0398 fail/op`; `BenchmarkPCMixedReadWrite-16 ... 0.001713 readmiss/read`) and `store2.bench.txt` (`BenchmarkPCRequestLifecycle-8 ... 0.02114 srcfail/op`). Reproduce with `go test -run '^$' -bench 'PCDeriveOwnOwner|PCMixedReadWrite|PCRequestLifecycle$' -cpu=1,4,8,16 ./internal/taint/store`.
- Fix: Emit the drop counters, contention in particular, as telemetry when the owner finishes. Consider one bounded retry in `putWindow` for source roots, where a drop loses the whole source.

### perf-contention-F5: The `Lookup` slow path costs about 16x `MayContain` because of 1.5 KiB `ranges.Set` copies
- Severity: Low
- Category: perf
- Location: internal/taint/store/lookup.go:68-76, 111, 167-194
- Claim: Serial `Lookup` hit costs about 1.2-1.5 us, against 91 ns for `MayContain`. Each lookup zeroes the snapshot (up to 4 entries x 1.5 KiB), then builds `compact` (1.5 KiB), `canonical` and `windowSet` (1.5 KiB each), and copies `windowSet` into `entry.Ranges`. This is roughly 8-12 KiB of memory traffic per owner hit on every gate hit. The parallel scaling of this read-only path, 3.9-4.2x at 16 cpus, is also modest, although the machine noise makes that figure unreliable.
- Evidence: `store2.bench.txt`/`store.bench.txt` (`BenchmarkPCLookupHit` at 1459 ns and `BenchmarkPCMayContainHit` at 91.2 ns, both cpu=1 medians).
- Fix: Keep ranges compact (a count plus a `[]Range` view into caller-owned scratch) instead of full `Set` values, and reset only `count` in `Snapshot.reset`.

## Checked and found correct
- No blocking acquisition happens on any propagation or lookup hot path. Every hot-path lock (shard, `lifecycleMu`, `rootsMu`, `writersMu`, bindings, `sourceMu`, `overflowMu` on allocation) uses `Try*`, which I verified by grepping every `.Lock`/`RLock` call site. Blocking locks exist only in `Finish` (`lifecycleMu`, `writersMu`, `rootsMu`, `overflowMu`), `freeOverflow`, `Stats`, `Manager.Acquire`/`Finish` (`sourceMu`) and `Scope` (`mu`).
- Lock order is consistent (`lifecycleMu` -> `writersMu`; `lifecycleMu` -> `rootsMu` -> `overflowMu`), and every inner acquisition on the other paths is a try-lock, so no deadlock cycle exists. No benchmark or test hung.
- Readers alone never lose data. `MayContain` and `Lookup` from 16 goroutines showed 0 misses on both distinct and identical keys, because `TryRLock` only fails while a writer holds or is waiting for the lock.
- Cross-request isolation of `sourceMu`: visitors in one request never contend with another request's source table.
- With the default `MaxConcurrentRequests=2`, the permit CAS bitset caps concurrent `store.Acquire` callers at 2. F1 still reproduces, at 15-41% of permitted requests.
- `Store` owners and shards are large, separately laid-out structs (a shard holds a 4 KiB slot array), so there is no false sharing between shard locks.

## Not covered / open questions
- Wall-clock scaling ratios are unreliable under the shared-machine load (the control varied up to 9x). Re-run `SUMMARY.txt`'s commands on an idle host before quoting ns/op.
- I did not measure the writer (`writersMu`), binding-table and `mutation.go` try-lock drop rates under parallel load.
- Contention in the end-to-end woven path (orchestrion-instrumented `net/http` server under a load generator) was not measured, and the per-request drop rate there depends on handler duration.
- I did not assess `Scope.mu` RWMutex reader-count bouncing when many goroutines share one request context. It is not a global lock.

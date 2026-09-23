# store-concurrency: Concurrency safety of internal/taint/store under the Go memory model
Verdict: NOT SAFE. No data race exists in the Go-memory-model sense (every plain field is mutex-guarded; the package runs 50x -race clean), but there is one logical race. `Acquire` recycles an owner slot without taking `lifecycleMu`, and `alive()` loads the generation and the state separately. A finished request's handle can therefore pass `beginWrite` and publish binding or writer state into the next request. This was reproduced on unmodified code (High). The remaining findings are Low or Info.

Scope covered: every non-test file in `internal/taint/store` (store.go, owner.go, root.go, value.go, lookup.go, mutation.go, binding.go, writer.go, overflow.go, limits.go), read line by line. Callers read for reachability: `request/owner.go:57-104,257-273`, `request/scope.go:47-59,209-223`, `request/lookup.go:59-162`, `request/reader.go:33,75`, `propagation/writer.go:49-227`, `propagation/propagation.go:70-105,395-420`, and `operatorbridge`/`jsonbridge` gates. Run in the private copy with GOTOOLCHAIN=go1.26.6: new stress, race and seam tests; the existing store tests (-race, -count=50); `go tool checklocks`; and `go vet`.

## Findings

### store-concurrency-F1: Slot reuse lets a finished request's handle write bindings or writer state into the next request
- Severity: High
- Category: cross-request
- Location: internal/taint/store/owner.go:20-60 (Acquire), owner.go:127-129 (alive), owner.go:131-149 (beginWrite); affected writers binding.go:77-108 and writer.go:117-335
- Claim: The code relies on the invariant "holding `lifecycleMu.RLock` and seeing `stateActive` pins the generation". That invariant is false, because `Acquire` moves a slot from Dead to Active (`generation.Add(1)` at :53, then `state.Store(stateActive)` at :59) without taking `lifecycleMu`. `alive()` evaluates `o.gen == generation.Load()` and then `state.Load() == stateActive` as two independent atomic loads. With a stale handle (gen g, slot Dead after `Finish`), the following interleaving is possible:
  1. `beginWrite` passes its gen check (:135) and `TryRLock` (:139).
  2. `alive()` loads generation == g.
  3. A new request's `Acquire` runs to completion.
  4. `alive()` loads state == Active and returns true.

  Operations with no later re-check then mutate the successor's tables. `BindObject`/`BindObjectValue` insert the old request's object (reached in production through `request/reader.go:33,75` via `OwnerRef.Handle`). `UpdateWriter`, `AdoptBufferWriter`, `TruncateWriter` and `ResetWriter` write or drop writer state (reached through `propagation/writer.go:49-227` via `WriterRef`/`Entry.Handle`). Old-owner source IDs thus become the successor's provenance, and `copySources` resolves them against the successor's source table (wrong source or false positive), or the successor's own writer state gets wiped. Root publishes (`reserveRootSlot`/`publishRoot`) also land in the successor's roots and charge. `putWindow`'s second `alive()` (value.go:140) usually rolls these back. If the rollback's `TryLock` fails (root.go:371-375), the anchor and charge stay with the successor until it finishes. The trigger is any goroutine that keeps working on a finished request's reader or builder, such as async work that outlives the handler, while the slot is recycled.
- Evidence:
  - Unmodified code, natural scheduling. Harness: `.omo/review/evidence/store-concurrency/zz_review_concurrency_test.go`, `TestReviewStaleHandleBindAfterSlotReuse`. Output: `stale-bind-natural.txt`.
  - Command: `GOTOOLCHAIN=go1.26.6 REVIEW_STRESS=60s go test -run TestReviewStaleHandleBindAfterSlotReuse -count=1 -v ./internal/taint/store/`
  - Output: `stale handle gen=460230 bound object into reused owner slot gen=460231` / `cycles=460231 workers=14 ... cross_generation_bindings=1` / `--- FAIL (51.48s)`. The detector cannot give a false positive: `Finish` resets bindings under the lifecycle write lock, and the object was freshly allocated.
  - Deterministic consequence: `zz_review_seam_test.go` plus `owner-alive-seam.diff`. The review-only hook runs `Acquire` between the same two loads, in the original order. Output is in `stale-handle-seam.txt`: `LookupObject ref[0]: index=0 generation=2` and `fresh request (gen 2) now reports writer provenance: [{Start:0 Length:4 SourceID:7}]`. The control (sequential reuse) is correctly rejected.
  - This independently confirms store-stress-F1.
- Fix: Make `Acquire` take `record.lifecycleMu.TryLock()` (skip the slot on failure, as it already does for `writersMu`) around the reset and the Active store, which restores the invariant. Independently, have `alive()` (and `Lookup`'s check at lookup.go:152) load `state` before `generation`. Under RLock, an Active observed from the new `Acquire` forces a later generation load to see g+1. Add the natural stress test as a regression test.

### store-concurrency-F2: The same load-order gap lets Lookup build an Entry that mixes two owner generations
- Severity: Low
- Category: race
- Location: internal/taint/store/lookup.go:152-195
- Claim: `Lookup` checks `generation == window.ownerGen` and then `state == Active` under the lifecycle RLock, which is the pattern from F1. When `Acquire` falls between the two loads, the successor's root with the same `{rootID, rootGen}` is copied. `{0,1}` is the most common pair, since every request's first root is ID 0, generation 1. The Entry then pairs the successor's ranges and `OwnerID` (:183) with the old `OwnerGen` (:191). Downstream checks reject this Entry: `Entry.Handle` checks generation and ID (lookup.go:40), and `copySources` requires both `ownerID` and `ownerGen` to match (request/lookup.go:140,146). So nothing leaks today, but the store returns an internally inconsistent Entry, and any consumer that trusts `Entry.Ranges` without `copySources` would bleed taint.
- Evidence: static reasoning only (NEEDS-REPRO). The window is the one reproduced in F1.
- Fix: Same as F1 (Acquire under `lifecycleMu`, or load state before generation). Also load `owner.id` once, before the generation check, and compare it.

### store-concurrency-F3: A rebind racing a mutation claim undercounts value counters and can close the `!= 0` fast gates
- Severity: Low
- Category: race
- Location: internal/taint/store/value.go:172-185 vs mutation.go:88-97
- Claim: Rebinding an existing key from root R1 to R2 reserves R2's quota (value.go:175) and then releases R1's quota (value.go:180). A `claimMutation(R1)` that runs in between (no shard lock) bulk-subtracts R1's count, which still includes the key, from owner and process `values`. The release then becomes a no-op because the generation changed, and R2 keeps the key uncounted. After this, `values` can read 0 while a live tainted window exists, so `operatorbridge.HasValues` and `jsonbridge.hasValues` report no taint (a false negative) until `Finish` reconciles the counters. It is latent because `PublishBytesMutation`, the only caller of `claimMutation`, has no production caller. It agrees with store-value-F2.
- Evidence: `.omo/review/evidence/store-concurrency/rebind-drift-seam.txt` (seam diff included, `zz_review_seam_drift_test.go`) shows `after rebind: owner_values=0 process_values=0 r2_quota_count=1 (one live key)`. A natural 30 s stress on unmodified code ran 210,665 iterations and observed no drift, because the window is a few instructions long.
- Fix: In the rebind path, when `releaseRootValue` finds R1's quota generation already advanced, add the value back to owner, process and operator counters. Alternatively, hold R1 `rootsMu` across the transfer.

### store-concurrency-F4: No `+checklocks:` field annotations, so the CI checklocks run verifies nothing in the store
- Severity: Low
- Category: ci
- Location: internal/taint/store/store.go:63-181, binding.go:38-44, writer.go:36-43
- Claim: None of the mutex-guarded fields carry a `// +checklocks:<mu>` annotation. This covers `rootRecord` plain fields and `rootNext`/`rootFree*` (rootsMu), `writers`/`writerCount` (writersMu), `bindingTable.entries/index/count/readerCount` (bindings.mu), `shard.slots/tombstones/probe*` (shard.mu) and `overflowFree/overflowN` (overflowMu). `go tool checklocks` therefore passes trivially, and the many `// +checklocksforce: TryRLock.` comments are inert. Several are duplicated on one line (owner.go:144, value.go:122, lookup.go:153-164). Manual review found every access correctly guarded (see below), but nothing prevents a regression. `request/scope.go` and `spans/` do annotate their fields.
- Evidence: `existing-race-50-and-static.txt`. `grep -c '+checklocks:' internal/taint/store/*.go` is 0 for every file, and `go tool checklocks ./internal/taint/store/` exits 0 with no output.
- Fix: Annotate the fields listed above. Mark `putWindow`, `insertWindow`, `compact`, `publishRangesLocked` and the `*Locked` writer helpers with `+checklocks:`, and add `+checklocksread:` where a read lock is enough.

### store-concurrency-F5: Stale `Finish` has the same check-then-act shape, but no production path reaches it
- Severity: Info
- Category: race
- Location: internal/taint/store/owner.go:158-163
- Claim: `Finish` compares generations (:158) and then CASes Active to Finishing (:162), so a second `Finish` on a stale handle could, in theory, finish the successor if `Acquire` ran between the two steps. In production, `Analysis.Finish` obtains the store owner through `slot.owner.Swap(nil)` (request/owner.go:269-270), and the only other call, at request/owner.go:90, runs on an owner that was never published. Each `*Owner` is therefore finished at most once, and this cannot happen. I rate this lower than store-stress-F3 (Medium) for that reason. The F1 fix, making `Acquire` exclusive with `lifecycleMu`, does not close this by itself. Checking `generation` after the CAS (and restoring Active on a mismatch) would.
- Evidence: static reasoning only (NEEDS-REPRO). Caller audit from rg over non-test code.
- Fix: Optional hardening as described above.

### store-concurrency-F6: `Finish` holds the process-wide `overflowMu` across its 512-root scan
- Severity: Info
- Category: perf
- Location: internal/taint/store/owner.go:182-203; overflow.go:24
- Claim: `Finish` takes the global `overflowMu` once and scans all 512 roots while holding it. Meanwhile, `freeOverflow` in other requests uses a blocking `Lock`, reached from `rollbackRoot` (root.go:379) and `PublishBytesMutation` (mutation.go:45,54,68), so those host goroutines block for the length of the scan. The wait is bounded (microseconds) and cannot deadlock, but it goes against the drop-rather-than-block policy.
- Evidence: static reasoning only.
- Fix: Take `overflowMu` only for roots with `overflow != 0`, or collect the block indices and free them in one short critical section.

## Checked and found correct
- **Guard map (plain fields).** Root record fields, `rootNext`/`rootFree*` → `rootsMu`. Writer records and `writerCount` → `writersMu`. Binding table → `bindings.mu`. Shard slots and stats → `shard.mu`. `overflowFree`/`overflowN` → `overflowMu`. Every other shared field is `sync/atomic` (generation, state, id, quotas, counters, writer index arrays). The one exception is `Store.writerActive`, a plain pointer; it is written once before publication, and `request/scope.go:47-59` publishes the manager through `atomic.Pointer` after `BindWriterActive`, which gives the needed happens-before. No field mixes atomic and plain access.
- **Overflow blocks.** Blocks are written outside `overflowMu` (publishRangesLocked:360, prepareRanges:115) only while exclusively allocated. Publication to `Lookup` goes through `rootsMu` (Lock, then RLock). Frees happen only after `root.overflow` is replaced under `rootsMu`, and the free→allocate handoff is ordered by `overflowMu`. I found no double-free path: rollback, Finish and mutation each clear or replace `root.overflow` under `rootsMu`.
- **Lock order.** The order is lifecycleMu → writersMu → rootsMu → overflowMu → bindings.mu (Finish), with ownerMu → writersMu in Acquire. The only blocking acquisitions are in `Finish`, `freeOverflow`, `bindings.reset` and `Stats`. Every nested acquisition elsewhere is `Try*`, and no code path holds a later lock while blocking on an earlier one, so the graph has no cycle and cannot deadlock. The store runs no callbacks under any lock. `Lookup` does bounded, allocation-free range work under RLock, and `strings.Clone`/`make` run outside all locks (root.go:40,120,162).
- **Every `Try*`/`defer` pair is unlocked exactly once**, including the early-return branches. `reclaim`'s recursive `TryRLock` on a lifecycle the caller already holds is safe, because `Try` fails instead of deadlocking when a writer is pending.
- **`insertWindow` and `claimMutation` ordering.** Counters are reserved first and the generation quota last (value.go:198-216). A claim therefore bulk-subtracts only owned reservations, and a late insert for an old generation fails `reserveRootValue`. The `setGen` check (value.go:121) stops a new generation from getting windows before its ranges are published (mutation.go:64).
- **Writer seqlock.** The `writerVersion` odd/even brackets with atomic index arrays in `writerPresent` answer "possibly present" whenever there is doubt, so any error is conservative.
- **Handle checks.** `Entry.Handle` checks the id, which `Acquire` stores between the generation increment and the Active store, so `Handle` cannot return a successor. For `OwnerRef`/`WriterRef.Handle`, any gap is caught by `beginWrite`'s fresh generation check except for the F1 window.
- **Race detector.**
  - `TestReviewFullSurfaceRace`: 6 churners doing Acquire, Taint*, Derive, PublishBytesMutation, bindings, the writer API and Finish, plus 4 readers doing Lookup/MayContain, `Handle` then `Derive`, object and writer lookups, invalidation and Stats. It passed with `-race -count=50`, with zero charge, value, writer or operator-mirror residue and all 256 overflow blocks freed (`full-surface-race-50.txt`).
  - The existing store tests with `-race -count=50 -skip TestReview`: `ok ... 830.688s`. `go vet` and `go tool checklocks` both exit 0. See `existing-race-50-and-static.txt`.

## Not covered / open questions
- I did not run the woven (orchestrion) end-to-end version of F1. The consequence chain above source resolution (a wrong source reaching an actual report) is argued from `copySources` and the writer propagation code, not executed.
- I did not look at wrap-around of `uint32` root generations or `uint64` owner generations under a concurrent claim (see store-value-F6).
- The bound on how often F1 happens in production (it depends on the rate of async-after-finish work multiplied by the slot-recycle rate) is unmeasured.

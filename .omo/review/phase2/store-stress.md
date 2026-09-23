# store-stress: randomized concurrent stress of internal/taint/store
Verdict: Not correct under concurrency. There are no data races, no panics, and no provenance corruption for live owners across about 19.5 minutes and 69.7M operations under `-race`. Two High defects exist. A stale `Owner` handle can publish writer and binding state into the next request that reuses its slot (cross-request bleed). A fully occupied shard stays permanently unusable after its owners finish.
Scope covered: `internal/taint/store/{store,owner,root,value,lookup,mutation,binding,writer,overflow,limits}.go` (all read). Callers read: `internal/taint/request/owner.go:100-275`, `request/reader.go:20-40`, `propagation/writer.go:40-230`. Everything was run with Go 1.26.6 in a private copy. The harness ran 39 seeds of 30 s each: 26 at GOMAXPROCS=16 and 13 at GOMAXPROCS=2, all with `-race`, 32-64 workers, and 6 seeds in forced-collision mode. Targeted reproducers ran with and without `-race`.

## Findings

### store-stress-F1: Stale owner handle passes beginWrite during slot reuse and publishes into the next request
- Severity: High
- Category: cross-request
- Location: internal/taint/store/owner.go:127-149 (`alive`, `beginWrite`), owner.go:53-59 (`Acquire`); consumers binding.go:77-107, writer.go:117-160, mutation.go:79-88
- Claim: `alive()` makes two separate loads: `o.gen == generation` and then `state == stateActive`. `Acquire` never takes `lifecycleMu`, so holding `lifecycleMu.RLock` does not exclude slot reuse. `Acquire` bumps the generation (l.53) and stores `stateActive` last (l.59). A late goroutine using the handle of a finished request can load generation `g` just before the bump and then load the new generation's `stateActive`. `beginWrite` therefore returns true for a dead handle. Root and window publication is saved by the second `alive()` check in `putWindow`. Paths without a second check write straight into the new owner. `BindObject`/`BindObjectValue` bind the old request's reader or URL into the new request's table. `UpdateWriter`/`AdoptBufferWriter` create writer state in the new owner, carrying the old request's owner-local source IDs, which are then resolved against the new request's source table. That state is charged to the new request. `claimMutation` can also CAS the new owner's root, because root IDs and generations restart at 1 for each owner generation; this wipes that owner's provenance. Production reaches these paths through `Handle()` and then a write, in `propagation/writer.go:110-132` (UpdateWriter) and `request/reader.go:33-37` (BindObjectValue). The design and architecture claim that "late goroutines are dropped by beginWrite's alive()" and that a stale handle "cannot publish into a reused slot"; neither holds.
- Evidence: `.omo/review/evidence/store-stress/stale_review_test.go` and `stale-handle.out.txt`. Command: `STALE_BUDGET=60s go test [-race] -run '^TestReviewStale' -count=1 -v ./internal/taint/store`. Captured output:
  - `builder written only through FINISHED request gen 4736 is tracked by NEW request gen 4737 (id 4800); snapshot=true ranges=1 first={Start:0 Length:4 SourceID:7 ...}`
  - `object bound only through the FINISHED request's handle (gen 5054) is bound to the NEW request (idx=0 gen=5055, id=5118)`
  
  Each reproduces within 0.1-6 s. The randomized harness also hit the underlying torn read organically: `KNOWN[torn-alive]` appeared in 13 of 13 GOMAXPROCS=16 seeds in `campaign/known-and-stats.txt`, and the first unclassified run is in `campaign/run1-p16-all.log`.
- Fix: Make slot reuse exclusive with in-flight writers. `Acquire` should `lifecycleMu.TryLock()` a candidate slot (skipping it on failure, as it already does for `writersMu`) around the generation/state transition. Alternatively, pack generation and state into one `atomic.Uint64` and check that. At minimum, `alive()` must load state before generation, because `Acquire` stores generation before state.

### store-stress-F2: A fully occupied shard is permanently wedged after its owners finish
- Severity: High
- Category: false-negative
- Location: internal/taint/store/value.go:147-193 (probe loop), value.go:225 (compaction only after a successful insert)
- Claim: `putWindow` turns every stale slot it probes into a tombstone. It inserts only when it finds an empty slot within `ProbeLimit`; tombstones alone are refused (l.188-192) to avoid duplicates. `compact` runs only from `insertWindow` after a successful insert. Once a shard has no empty slot, no insert can ever succeed, so it never compacts. Every key hashing to that shard, about 1/256 of all values, is dropped for the process lifetime, even after every occupant has finished. Each such event permanently disables IAST for another slice of values. The reproducer fills shard 0 with 129 values from one request, using legitimate `TaintBytes` and `Derive` windows chosen by address. Organic saturating churn with 4 owners at 4,096 values reached a peak occupancy of 127/128 and `MaxProbe=64`, but did not fully wedge a shard in 1,500 rolling steps. The consequence is proven; the organic trigger is a near miss, not an observation.
- Evidence: `.omo/review/evidence/store-stress/wedge_review_test.go` and `wedge.out.txt`. Command: `go test -run '^TestReviewShardWedgeAfterOwnerFinish$' -count=1 -v ./internal/taint/store`. Captured output:
  - `round 2 (owner B2): shard-0 derives ok=0 fail=640; other-shard derives ok=199; shard-0 TaintString ok=0/50; shard0 live=0 tomb=128 empty=0 compactions=0->0`
  - `shard 0 permanently wedged`
  
  Organic near miss: `organic-saturation.out.txt` shows `rolling: steps=1500 owners=4 worstOcc=127/128`. Forced-collision harness seeds show the same end state, `Tombstones:64 Compactions:0 MaxProbe:64`.
- Fix: When the probe window is exhausted and `shard.tombstones > 0`, call `compact(shard)` under the held lock and retry the probe once. Alternatively, compact on any tombstone threshold crossing, including the reclaim path at l.164, not only after a successful insert.

### store-stress-F3: Stale Finish can finish the owner that reused the slot
- Severity: Medium
- Category: race
- Location: internal/taint/store/owner.go:157-162
- Claim: `Finish` checks `o.gen != generation` and then does `CAS(stateActive→stateFinishing)` as two steps. If the old owner finishes and `Acquire` reuses the slot between them, a stale second `Finish` kills the new request's owner and releases all its taint. The doc comment says it "cannot finish a later generation that reused the owner slot". Current production callers make a single store `Finish` per analysis: `request.Analysis.Finish` does `owner.Swap(nil)`, which is why this is Medium. However, `Analysis.Finish` (request/owner.go:260) uses the same check-then-CAS pattern on the analysis slot. I did not reproduce that path.
- Evidence: `stale_review_test.go` `TestReviewStaleFinishKillsReusedSlot` and `stale-handle.out.txt`, which shows `new owner (gen 19, id 82) was finished by the previous request's stale handle (gen 18); state=3`. The harness hit it organically once: `KNOWN[stale-finish-kills-reused-owner] seed=511356610 ... owner id=21501 idx=30 gen=337 is no longer alive although its creator never finished it` (`campaign/known-and-stats.txt`).
- Fix: Same as F1: make the state transition atomic with generation, either with a packed gen/state word and a single CAS, or with `Acquire` holding `lifecycleMu`.

### store-stress-F4: Failed rollback leaks a reserved root slot and its charge until Finish
- Severity: Low
- Category: memory-bound
- Location: internal/taint/store/root.go:370-375 (`rollbackRoot`), root.go:281-320
- Claim: When `publishRoot` or `putWindow` fails and `rollbackRoot` then loses its `rootsMu.TryLock`, the reserved root ID, `rootCount`, and up to 192 KiB of request and process charge stay consumed until `Finish`. The comment says this is intentional and it is bounded, but repeated contention can exhaust a request's 2 MiB or 512-root budget and cause later drops. The harness counted such leaked reservations at quiescent points (`leakedReservations`, 166 cumulative observations in `campaign/per-run-stats.txt`).
- Evidence: harness quiescent counter; the first detection was in collide seed 16 (`owner 2 rootCount 1 != published roots 0`) before the invariant was relaxed to a counter.
- Fix: Use a blocking `rootsMu.Lock()` in `rollbackRoot`. It is off the success path, and the critical section is O(1).

### store-stress-F5: Adoptable randomized store stress harness
- Severity: Info
- Category: test-gap
- Location: internal/taint/store (new test file)
- Claim: No existing test combines owner churn, reuse, stale handles, mutation, writers, bindings, and overflow with a model. The harness (`evidence/store-stress/stress_review_test.go`, runner `campaign.sh`) is ready to adopt. It is gated by `STORE_STRESS=1` and deterministic in op choice per `STRESS_SEED`, which it always prints. Design:
  - Each worker owns a private model of the values it published: the root ref, the canonical ranges, and derived windows. After every op it checks global and owner counter bounds. After lookups of its own keys it does exact byte-level provenance equality, accepting only the documented truncation to 10 ranges when the overflow pool is empty.
  - Sources are banded per owner ID (`id%60 * 1000`), so any cross-owner range is detectable.
  - An owner registry validates `Entry` index, generation, and ID, and checks that no entry appears after its owner finished.
  - After a mutation, or a claimed failed mutation, old keys must resolve to nothing.
  - Writer snapshots must be a byte-subset of an ideal model.
  - Object lookups may only return owners that bound the object.
  - Between epochs, a quiescent checker verifies:
    - live slots equal `owner.values`, and per-root quota equals live references;
    - process totals equal the sum over owners, including the operator and writer mirror counters;
    - overflow blocks are neither shared nor double-freed;
    - tombstone counters are exact;
    - every live slot is reachable within `ProbeLimit`;
    - there are no duplicate live slots;
    - dead-slot residue is zero;
    - after drain the store is empty.
  
  It was validated by mutation testing: removing the Lookup generation check, the Finish overflow free, or the claim counter subtraction is each caught in epoch 0 (`mutants.txt`). Known classes (F1, F3) are counted as `KNOWN[...]` and fail only with `STRESS_STRICT=1`.
- Evidence: `campaign/summary-*.txt` and `campaign/per-run-stats.txt`
- Fix: Adopt it under `internal/taint/store`, run briefly in CI (for example 10 s), and gate a long soak behind the environment variable.

## Checked and found correct
- No `WARNING: DATA RACE` and no panic in 39 `-race` seeds of 30 s each (GOMAXPROCS 2 and 16, forced-collision included): 69.7M ops, 2.34M byte mutations, 758k sets that needed overflow blocks, 988k stale-`Finish` calls, 227k foreign `Entry.Handle` derives, and 536k writer snapshots (`campaign/*`).
- Strict lookups: 17.73M model checks and 17.54M hits. There was no wrong range, no cross-owner source, no duplicate owner entry, no entry for a finished owner, and no stale provenance after a successful or claimed-failed mutation. Safe misses due to contention were 1.0% (178,559).
- 1,734 quiescent checks passed, covering value, charge, writer and mirror accounting, per-root quota versus live slots, overflow ownership and free-list uniqueness, exact tombstone counters, live-slot reachability, and cleared dead slots. Every run drained to an empty store (values, charge, writer states and mirrors at 0, `OverflowFree=256`).
- The documented host-value contract holds. Rejected lengths (0, 1, and over 64 KiB) are refused and return the original value; clones preserve content and capacity; `TaintBytes` never aliases its input.
- Writer snapshots never contained provenance absent from the ideal model, including under foreign `InvalidateBuffer`/`InvalidateWriterPointer` calls.

## Not covered / open questions
- The same check-then-CAS pattern exists in `request.Analysis.Finish`/`Active` (request/owner.go:125-129,258-273). Could a stale `Analysis` race analysis-slot reuse? This is static only.
- Physical GC address reuse is exercised only implicitly: finished values are dropped from the model and absence is checked by owner ID. Retained-heap size under saturation was not measured.
- The `forceWriterLockFail` seam and `AdoptBufferWriter` value-copy transfers were not randomized. Writers used synthetic views, not real `bytes.Buffer` objects.
- `PublishBytesMutation` has no production caller at HEAD, so F1's mutation-claim variant is latent.

# store-fuzz: model-based sequence fuzzing of internal/taint/store
Verdict: Correct under single-threaded op sequences. A 15-minute model-based fuzz run (145,718 execs, no crasher) plus deterministic seed and flood runs found no panic, no accounting drift, no exceeded limit, no leaked overflow block, and no false or stale taint. Two Low lookup edge cases were reproduced.
Scope covered: `internal/taint/store/{store,limits,owner,root,value,lookup,mutation,overflow,binding,writer}.go`, read in full. They were exercised by a new `FuzzStoreSequence` and by `TestStoreSequenceSeeds` and `TestStoreSequenceFlood` in the private copy, using Go 1.26.6. Consumer checks in `internal/taint/propagation/propagation.go:150-192` and `internal/taint/request/lookup.go:59-120`.

## Harness (evidence/store-fuzz/sequence_fuzz_test.go)
The fuzzer decodes fuzz bytes into up to 256 ops over 6 owner handles, choosing from 27 operation kinds:
- Owner lifecycle: Acquire/Finish, saturating all 64 owners, and ops through stale (finished or reused-slot) handles.
- Root creation: `TaintString`, `TaintSourceString`, `TaintBytes`, `TaintSourceBytes`, `AdoptSourceBytes`, and `AdoptString`/`AdoptBytes` with random canonical 0-64 range sets and limits 1-64, including invalid sets.
- Address reuse: re-adoption of any live or released root's anchor by any owner, which deterministically simulates a numeric address being reused while stale slots remain in the index.
- Windows and mutation: `Derive` with own, foreign, and stale refs; `PublishBytesMutation` with a valid base, an interior base, a foreign buffer, a cap mismatch, nil or invalid sets, and stale refs.
- Bulk and flood: bulk taint (up to 600 roots), bulk derive (up to 300 windows), and a flood op that drives owners to 4,096 values and the process to 16,384 values, then churns owners.
- Other APIs: `BindObject`, `BindObjectValue`, `LookupObject` and `LookupObjectValue` (up to 300 bindings, reader-kind transitions); builder `UpdateWriter`, `TruncateWriter`, `ResetWriter`, `InvalidateWriterPointer`, `SnapshotWriter`, and `LookupWriterValue`.

The reference model predicts every op's boolean outcome **before** the real call. It covers each limit (roots per owner, request and process bytes, request and process values, 256 values per root, overflow-block availability, bindings, readers, writers) and the lowest-free owner index, generation, and ID on Acquire.

After every op the harness asserts:
- **Accounting:** each owner's charged bytes, values, `rootCount`, bindings, readers, and writers; process charged bytes and values; the operator and writer mirror counters; each root's generation and `valueQuota`; overflow `overflowN == 256 - held`; each shard's `tombstones` counter against the actual tombstone count; and `probeMax <= 64`.
- **Lookups** on newly touched keys plus 24 rotating keys. The key set includes every clean input value, every stale window, and every released key. For each key it checks the exact owner, owner ID and generation, root ref, sliced ranges, and limit; that `MayContain` is true for every live key; that `Entry.Handle` is valid while the owner is live; and that saved entries are invalid after Finish.
- **Full sweeps:** all keys after each Finish and at the end of the sequence.
- **Drain:** after all owners finish, charged bytes, values, writers, and mirror counters are 0 and all 256 overflow blocks are free.

Failure through the probe bound is accepted only when some 64-slot probe window is physically full. That case was never hit.

## Findings
### store-fuzz-F1: Stale same-key slots consume Lookup's 4-owner fanout and hide a live owner
- Severity: Low
- Category: false-negative
- Location: internal/taint/store/lookup.go:125-139
- Claim: `Lookup` collects the first `MaxSnapshotOwners` slots that match `(pointer, length, kind)` **before** checking owner generation or state (validation happens later, at lines 141-196). A slot of a finished owner, or of a superseded root, therefore takes one of the 4 windows. If more than 4 owners ever held the same key at once and one of them later finishes, the remaining 4 or fewer live owners are not all returned until an insertion on that chain reclaims the stale slot (`value.go:163`). Only lookups are affected, and only when more than 4 owners registered the same allocation. That already exceeds the documented 4-owner fanout, and insertions reclaim stale same-key slots, so this is a narrow provenance loss.
- Evidence: evidence/store-fuzz/review_fanout_test.go (`TestReviewStaleSlotsConsumeLookupFanout`); command in evidence/store-fuzz/reviews.out:
  `GOTOOLCHAIN=go1.26.6 go test -v -run TestReview ./internal/taint/store/` gives `after finishing owner 1: live owners=[2 3 4 5] visible=[2 3 4]` and then `BUG: 4 live owners (<= MaxSnapshotOwners) hold the key but Lookup returned 3`. The fuzzer first found this through re-adoption, and the model now counts it as `crowded`.
- Fix: in the probe loop, skip a matching slot whose owner generation or state is already stale (`s.stale(slot)` uses only atomic loads) before it consumes a window. Alternatively, collect up to `ProbeLimit` candidates and validate them before applying the 4-entry cap.

### store-fuzz-F2: Lookup returns owner entries with zero ranges, and propagation publishes zero-provenance roots for them
- Severity: Low
- Category: perf
- Location: internal/taint/store/lookup.go:182-195; internal/taint/propagation/propagation.go:159-191
- Claim: a window lying entirely in an untainted gap of a multi-range root still produces an `Entry` whose `Ranges.Len()==0`, because `Slice` of a non-intersecting window is valid but empty. Reporting is not affected: `request.deliverEntry` skips entries with a zero count (`request/lookup.go:103-107`), so there is **no false taint**. Propagation, however, gates only on `snapshot.Len()==0`. For example, `copyStringHit` then calls `strings.Clone` and `AdoptString` with an empty set. That allocates a host-visible clone and charges a root slot, root bytes, and a value slot that carry no provenance. The cost stays within the store's bounds, but it spends the per-request budgets (512 roots, 2 MiB, 4,096 values) and hot-path allocations on untainted data.
- Evidence: evidence/store-fuzz/review_fanout_test.go (`TestReviewEmptyRangeEntry`); evidence/store-fuzz/reviews.out gives `untainted gap window: snapshot.Len()=1 entry.Ranges.Len()=0 MayContain=true`. The propagation consequence is static reasoning from propagation.go:159-191.
- Fix: in `Lookup`, do not append an entry when `windowSet.Len()==0` (line 186). Alternatively, make propagation callers skip entries with empty `Ranges` and return the original result when every entry is empty.

### store-fuzz-F3: The probe-exhaustion drop path is unreachable at design load, so it is untested by sequences
- Severity: Info
- Category: test-gap
- Location: internal/taint/store/value.go:185-188
- Claim: with the process at its 16,384-value limit, plus three rounds of full owner churn and 240 compactions, the maximum probe length observed was 37 of the 64 allowed, and `probeSkips=0`. Under normal address distribution the probe-bound drop at the end of `putWindow` is never taken, so only the `forceCollision` unit tests cover it. This is an observation, not a defect.
- Evidence: evidence/store-fuzz/seeds.out gives `compactions=240 aborts=0 probeSkips=0 crowded=0 maxProbe=37 avgProbe=2.42`.
- Fix: none required. Keep the `forceCollision` tests.

## Checked and found correct
- **No panic or divergence:** `go test -run '^$' -fuzz=FuzzStoreSequence -fuzztime=15m -parallel=2 ./internal/taint/store/` passed: 145,718 execs, 296 corpus entries, `PASS` / `EXIT=0` (evidence/store-fuzz/fuzz.log). No crasher was produced, so there is no testdata corpus to save. `TestStoreSequenceSeeds` (300 x 1,500-byte sequences) and `TestStoreSequenceFlood` pass, and together they reach 80.2% store statement coverage (evidence/store-fuzz/seeds.out). Coverage includes `compact` (88%), `rollbackRoot`, and `insertWindow` (100%).
- **Admission is exact:** every predicted limit (request and process bytes, request and process values, 512 roots, 256 values per root, overflow exhaustion keeping 10 ranges, 256 bindings, 8 readers, 8 writers, 64 owners) matched the store with no spurious drop. Nothing exceeded a limit.
- **Accounting and reuse:** owner and process charged/values counters, the operator and writer mirrors, per-root `valueQuota`, and root counts stayed exactly equal to the model through re-points, mutations, rollbacks, and Finish. After every sequence the store drains to 0 bytes, 0 values, 0 writers, and 256 free overflow blocks. Every new root is published at generation 1, and a released root ID is reused safely.
- **Window identity:** re-adopting the same allocation re-points the owner's slot (latest root wins, quota moves) and never duplicates it. Cross-owner adoption yields separate entries. Re-adopting a released anchor never revives the old owner's taint, which also exercises the stale-slot reuse path deterministically.
- **Mutation:** `PublishBytesMutation` behaves as documented in every rejection case (stale ref, interior base, foreign buffer, cap mismatch, nil or invalid set, string root). A successful claim invalidates every old window of the root, bulk-subtracts its value count, and never restores stale provenance. Overflow blocks move correctly between generations.
- **Host values:** `TaintString`, `TaintBytes`, and the source variants return equal content, length, and capacity. The clone is fresh on success and the input is returned on failure. Stale-handle ops never publish.
- **Index invariants:** the shard `tombstones` counter always equals the number of physical tombstones, including across compaction. Lookup of every live key never misses in `MayContain`.

## Not covered / open questions
- The model is single-threaded, so contention paths (`TryLock` failures, reclaim under a pending Finish, rollback contention) are not covered. Other nodes cover concurrency. Reasoning I did not reproduce: the `putWindow` update path at `value.go:175-184` can re-point a stale-but-unreclaimed own slot without incrementing `values`, but that only happens while the owner is finishing and Finish reconciles it, so I filed no finding.
- The bytes.Buffer writer surface (`AdoptBufferWriter`, anchored views, `InvalidateBuffer` overlap, the dirty bit) is not modelled; only builder-kind writers are.
- Root and slot generation wrap-around at 2^32 mutations is not exercised.
- Throughput fell to 0 execs/sec during slow flood and full-sweep inputs on the loaded machine, so the 15 minutes explored about 146k sequences.

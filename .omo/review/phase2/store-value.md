# store-value: value handles, identity and address index (internal/taint/store/value.go)
Verdict: value.go is crash-safe and identity-sound. No reachable panic, no uintptr-to-pointer conversion, no collision between distinct live values, and no handle that outlives its anchor. I found one reproduced Medium false negative: tombstones in a full probe window are never reused. The other findings are Low accounting and perf issues. There are no Critical or High findings.
Scope covered: internal/taint/store/value.go in full (keyHash, shardIndex/initialSlot, validKey, inWindow, reserve*/releaseRootValue, putWindow, insertWindow, stale, reclaim, recordProbe, compact). For context I read store.go, limits.go, lookup.go, owner.go, root.go, mutation.go and overflow.go, and the tests identity_test, handle_test, compaction_test, churn_test, saturation_test, generation_test and admission_behavior_test. I also read the AdoptString/AdoptBytes call sites and propagation/conversion.go, request/reader.go and ReadAllBytes. I ran the store package tests in a private copy: `-race` (pass), `-d=checkptr` (pass), and `GOOS=linux GOARCH=386 go vet` (clean).

## Findings
### store-value-F1: Tombstones in a probe window with no empty slot are never reused, so inserts are dropped as "full" while the store is empty
- Severity: Medium
- Category: false-negative
- Location: internal/taint/store/value.go:147-193 (comment 190-191, drop 192-193); compaction trigger value.go:225-227
- Claim: putWindow inserts into `firstTombstone` only when it later reaches an empty slot (`case 0`, value.go:150-156). If the 64-slot probe window holds only live slots and tombstones, including stale slots that this same loop has just reclaimed into tombstones (value.go:163-170), the insert falls through to `drops.full` even though free tombstones exist. The comment at 190-191 says this protects against a duplicate key beyond the window. That reasoning is wrong. Every insertion path puts a key at `start+probe` with `probe < ProbeLimit`: putWindow uses the empty slot or an earlier tombstone, and compact uses `probe < ProbeLimit` (value.go:295-304). So a 64-probe scan with no match proves the key is absent. Compaction runs only after a *successful* insertWindow (value.go:225), so the blocked window stays unusable until an unrelated key in the same shard happens to succeed. Failed probes still increment `shard.tombstones`. The trigger is a window that was fully occupied once, for example under saturation with many concurrent owners, whose owners have since finished. After that, a fresh request loses taint on keys that hash into the window, and it goes silently (only `drops.full` counts it). This violates rule 4 in an edge case after load and is transient, so the rating is Medium, not High.
- Evidence: .omo/review/evidence/store-value/zz_review_tombstone_test.go uses real hashing, not `forceCollision`. It searches windows of a 60 KB root for keys with shard 0 and start 0. Run `GOTOOLCHAIN=go1.26.6 go test -count=1 -run TestReviewTombstoned -v ./internal/taint/store/` (output in tombstone_window.out.txt):
  `owner A derived 64/64 start-0 windows in shard 0` / `after A.Finish: ProcessValues=0` / `owner B start-0 derives=[false false false] fullDrops=3 tombstones=64 maxTombstones=64 processValues=1` / `unrelated start-100 derive=true compactions=1` / `retry start-0 derive after compaction=true` / `BUG: window insert dropped as full although every slot in its probe window is a tombstone`. With candidate_fix.diff applied, tombstone_window.fixed.out.txt shows `derives=[true true true] fullDrops=0`, and the whole store package passes with `-race`.
- Fix: after the probe loop, `if firstTombstone >= 0 { return o.insertWindow(&shard.slots[firstTombstone], shard, key, offset, rootID, rootGen, ProbeLimit, true) }` (candidate_fix.diff), and delete the incorrect comment. Add a regression test for "every slot in the probe window is a tombstone".

### store-value-F2: Repointing an existing slot concurrently with a mutation claim undercounts value counters
- Severity: Low
- Category: memory-bound
- Location: internal/taint/store/value.go:172-186; internal/taint/store/mutation.go:88-95
- Claim: the same-owner path that reuses an existing key reserves quota on the new root and then releases the old root's quota, but it does not touch `owner.values`/`store.values`. Suppose `claimMutation` on the old root runs between those two steps, or the slot was already stale but not reclaimed because the owner is `stateFinishing` (value.go:260). The claim then bulk-subtracts this slot from the value counters, while the slot is still counted in the new root's quota. A later claim on the new root subtracts it again. `owner.values` and `store.values` move together and Finish reconciles them (owner.go Swap), so the process counter does not drift permanently. While the request is live, though, RequestValueLimit/ProcessValueLimit can be exceeded by one slot per such race. The race needs one allocation adopted into two roots (the digest P2 double-root case) concurrently with a byte mutation.
- Evidence: static reasoning only (Low, no repro needed): interleaving putWindow(value.go:176) → claimMutation(mutation.go:88-95) → releaseRootValue no-op (value.go:180, generation mismatch).
- Fix: in the repoint branch, when the old slot is stale (`o.store.stale(slot)`) or the old release fails, increment `owner.values`/`store.values` exactly as insertWindow does. The simpler alternative is to tombstone the old slot and go through insertWindow.

### store-value-F3: An aborted compaction is retried on every successful insert into the shard
- Severity: Low
- Category: perf
- Location: internal/taint/store/value.go:225-227, 281-313
- Claim: when compact aborts (value.go:306-308), `shard.tombstones` stays at 32 or more, so every later successful insertWindow in that shard runs compact again. Each run does up to 128 keyHash calls and 128x64 probes plus a 4 KiB candidate copy, all under the shard write lock on the propagation hot path. An abort is possible because compact re-places slots in index order, not in their original insertion order, so linear-probe displacement can exceed 64 even with fewer live slots. TestCompactionAbortLeavesShardUnchanged shows that aborts happen, but nothing throttles the retries. The cost is bounded, so this is Low.
- Evidence: static reasoning only.
- Fix: record a per-shard "compaction failed at tombstone count N" watermark and retry only after the tombstone count grows. Alternatively, compact in probe-distance order.

### store-value-F4: Test seams are read on every production keyHash call
- Severity: Low
- Category: quality
- Location: internal/taint/store/value.go:10-17
- Claim: `forceCollision`, a package-level `atomic.Bool`, is loaded on every keyHash call: MayContain, Lookup, putWindow, and each slot visited by compact. The load is cheap (one ldar/mov), but a test hook sits on the hottest path, and any caller in the package can flip it to collapse the index into one shard and slot. `forceWriterLockFail` is declared here but used by writer code.
- Evidence: static reasoning only.
- Fix: move the seams behind a build tag or an unexported `hash func(Key) uint64` field set only by tests.

### store-value-F5: Stale slots use up Lookup's four-window budget before validation
- Severity: Info
- Category: false-negative
- Location: internal/taint/store/lookup.go:118-137 (with value.go:231-271 lazy reclaim)
- Claim: Lookup copies the first four key-matching slots before validating owner or root generation, and stale slots are reclaimed only by a putWindow probe (value.go:163), never by Lookup. If a key has a live window from a fifth owner, or stale slots stay unreclaimed (for example while their owner is `stateFinishing`), stale entries can push a live owner out as `fanout`. For this to happen, one address has to be shared by at least five owners, which only occurs through cross-owner propagation. This is rare.
- Evidence: static reasoning only.
- Fix: count only windows that pass the cheap atomic owner-generation and state check (`stale()`) against the budget of four.

### store-value-F6: Root-generation comparisons are not wrap-aware
- Severity: Info
- Category: quality
- Location: internal/taint/store/value.go:75-95; mutation.go:84-87
- Claim: `claimMutation` wraps the uint32 root generation to 1, and `reserveRootValue` uses `generation < currentGeneration`, so after 2^32 mutations of one root a stale RootRef would match again (ABA). A single request cannot plausibly perform 4 billion in-place publishes, so this is not reachable in practice.
- Evidence: static reasoning only.
- Fix: none needed. If you want certainty, refuse to claim at `^uint32(0)` and invalidate the root instead of wrapping.

## Checked and found correct
- **Identity.** The key is `(uintptr data pointer, uint32 length, kind)` (store.go:48-61). Empty strings, nil slices, zero-length slices, over-4-GiB values, KindInvalid and the `^uintptr(0)` tombstone sentinel are all rejected (value.go:31-33). No real non-empty object can have the data pointer `^uintptr(0)`. Two live values with the same key are byte-identical views of one memory range, and `kind` separates string views from bytes views.
- **Can two distinct live allocations collide?** No. Every live, validated slot lies inside `[base, base+span)` of an anchored root (inWindow, value.go:35-49), and that range is a live heap object: strings anchor with span=len, bytes anchor with span=cap. Anchors are cleared only (a) in Finish, after the state has left `stateActive` and under `lifecycleMu.Lock`, which Lookup and putWindow both observe (owner.go; lookup.go:146-151; value.go:143); (b) in rollbackRoot, which runs only before a window for that root is published and before the RootRef is returned; or (c) when PublishBytesMutation replaces the anchor with a slice of the same base and capacity, which must be the same allocation because both are alive (mutation.go:51). Nothing else, including a stack, can therefore occupy a live slot's address. Stale numeric slots are always filtered by owner generation, state, root generation and setGen.
- **Rodata literals and substrings.** TaintString and TaintBytes always clone. Derive accepts only keys that lie inside the root's range, so a literal or unrelated substring can never be derived. Substrings of the same root with different lengths are distinct keys, and the same pointer and length means the same bytes. TestEqualLiteralDoesNotShareManagedTaint and TestAddressReuseDoesNotReviveFinishedOwner cover this. conversion.go:42 adopts the fresh `string(b)` result, which is heap-allocated because the parameter leaks to heap, and `len<2` excludes staticuint64s.
- **Handles.** An Owner is validated by generation, state, ID and beginWrite. A RootRef is checked under `rootsMu` against both `generation` and `setGen`. A RootRef from an earlier owner generation cannot be used because the owner handle's generation gates it. Entry.Handle revalidates the owner ID (handle_test.go).
- **Bounds.** Probe index math is uint8 with at most 127+63=190, so it never wraps. Slot, root and owner indices are guarded (value.go:111, 179, 232-242, 246-262, 290). In inWindow, the `rootEnd` and `valueEnd` overflow checks and the `uint32` offset check are correct, and the code builds and vets cleanly on GOARCH=386. `-d=checkptr` runs clean (vet386_checkptr.out.txt).
- **Every key sits within ProbeLimit slots of its start slot, on both insertion paths**, so the dedup scan in putWindow is exhaustive. No shard slot is ever reset to 0 except by compact, which preserves linear-probe chain integrity: each key is placed at the first empty slot from its start. Compact never drops a slot belonging to a live owner generation, and an abort leaves the shard unchanged.
- **Counter ordering in insertWindow.** It reserves owner values, then process values, then root quota last (value.go:196-218). For every interleaving with claimMutation's CAS on generation followed by the quota swap, the reservation is either refused or bulk-reconciled exactly once. Stale reclaim never decrements (value.go:267-269). TestDistinctMutationWindowsDoNotAccumulateCounters agrees with this.
- **Locking.** No blocking lock is taken while a shard lock is held. reclaim's nested `TryRLock` on the caller's own `lifecycleMu` cannot deadlock. All non-atomic root fields are read under `rootsMu`, and shard fields under `shard.mu`. The store package passes `-race`, including TestMillionOperationChurn.
- **No panics.** putWindow and its callees are reachable only through beginWrite, which rejects nil or disabled owners, so `o.owner` and `o.store` are non-nil there.

## Not covered / open questions
- Whether every AdoptString/AdoptBytes caller really passes an allocation base (propagation/*, writer.go:235, reader.go:116) is left to the propagation and writer nodes. The store cannot verify it.
- The existing-slot repoint is last-writer-wins: an adopt of an already-indexed key replaces that key's provenance (TestExistingWindowTransfersRootReservation). Both roots stay charged. This is digest P2. It is safe but wastes budget, and it can replace ranges if two callers adopt the same allocation with different sets.
- I did not measure the rate at which MayContain returns true on stale slots after owner churn (digest check 24), and I ran no wall-clock benchmarks.
- 32-bit coverage was vet only. There is no 386 execution on this host.

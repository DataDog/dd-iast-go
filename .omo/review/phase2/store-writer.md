# store-writer: writer state for strings.Builder / bytes.Buffer (internal/taint/store/writer.go)
Verdict: Bounds and release-on-finish are correct and no writer entry outlives its owner, but two defects are reproduced. First, writer activity in one request wipes another request's writer provenance nearly every time the two overlap (High, false negative across requests). Second, strings.Builder views have no anchor, so a clean builder can match stale state after GC reuses the address (High, false positive).
Scope covered: internal/taint/store/writer.go (all functions), store/owner.go (Acquire/Finish writer paths), store/store.go (owner struct), store/binding.go:dynamicPointer, internal/taint/propagation/writer.go, internal/taint/writerbridge/bridge.go, iast/propagation/writer.go, iast/propagation/orchestrion.yml:1057-1519,1553-1681. Ran reproducers and existing Writer/Buffer/Builder tests with -race on GOTOOLCHAIN=go1.26.6, without weaving.

## Findings
### store-writer-F1: Unrelated writer activity in another request wipes an owner's entire writer state
- Severity: High
- Category: cross-request
- Location: internal/taint/store/writer.go:85-96, 372-383, 412-433
- Claim: `writerPresent` returns `true` ("conservative possible match", line 432) whenever the target owner's `writerVersion` is odd on 3 back-to-back reads. There is no wait between reads, so this happens whenever the owner is inside any writer critical section. The caller then tries `writersMu.TryRLock`/`TryLock`, which fails for that same reason, and sets `writerDirty` (lines 89/94, 376/381). `clearDirtyWritersLocked` then drops every writer entry of that owner. So whenever request A calls a writer wrapper (`LookupWriterValue` from Prepare/Update/Reset/Truncate/String) or a woven bytes.Buffer hook on any unrelated buffer (`InvalidateBuffer`), it scans all 64 owners. If that scan overlaps request B's writer operation, B loses all Builder/Buffer taint, even though B never tracked A's object. The loss is silent, and the dirty paths at 93-96 and 380-383 do not increment `drops.contention`.
- Evidence: .omo/review/evidence/store-writer/zz_review_writer_crossreq_test.go (public wrappers, two live requests): `GOTOOLCHAIN=go1.26.6 go test -count=1 -run TestReviewCrossRequest -v ./iast/propagation/` gives `B builder checks=400 lost-taint=399; A clean buffer writes=15190`. The control with `REVIEW_NO_A=1` gives `lost-taint=0`. Store level, .omo/review/evidence/store-writer/zz_review_writer_test.go: `TestReviewUnrelatedInvalidationPoisonsOwner` (deterministic) gives `B.writerDirty after unrelated invalidation = true, B contention drops = 0` and `B.SnapshotWriter(tracked builder) = false`. `TestReviewUnrelatedInvalidationRate` gives `ops=200000 ... provenance losses=192491`, and the control gives `losses=0`. Outputs: .omo/review/evidence/store-writer/poisoning-crossreq.out.txt, .omo/review/evidence/store-writer/poisoning-store.out.txt.
- Fix: Do not treat "version odd" as a match. Spin a bounded number of times until the version is even (for example up to 64 loads, no blocking). Then dirty the owner only if a stable index snapshot actually contains the pointer or an overlapping backing. Otherwise skip the owner without dirtying it. If the result is still inconclusive after the bound, dirty only the slots whose pointer or range matches (a per-slot dirty bit), not the whole owner. Count every dirtying as contention.

### store-writer-F2: strings.Builder view ABA after GC address reuse reports clean content as tainted
- Severity: High
- Category: false-positive
- Location: internal/taint/store/writer.go:23-34 (builders keep no Anchor), 257-261, 448-451; iast/propagation/writer.go:202-205
- Claim: A builder entry is validated only by numeric `(Pointer, Length, Capacity)`. The entry anchors the Builder object but not its backing array. If the backing is replaced outside the wrapped hooks and the old array is freed, a new array can be allocated at the same address with the same len and cap, and the stale ranges then apply to unrelated clean bytes. Unwrapped replacement includes `b = strings.Builder{}`, `*s = T{}`, Reset through a method value or a dependency, followed by `fmt.Fprintf(&b, ...)`, `io.WriteString`, or a template write. `BuilderString` then publishes a tainted clone, which can reach an SQL or command sink and produce a false-positive report. Buffers are immune because their Anchor keeps the old array alive.
- Evidence: .omo/review/evidence/store-writer/zz_review_builder_aba_test.go: `GOTOOLCHAIN=go1.26.6 go test -count=5 -run TestReviewBuilderABA -v ./iast/propagation/` fails 5 of 5 runs with `address reused after 5 attempts; result="cccccccccccccccccccccccc" tainted=true`. Output: .omo/review/evidence/store-writer/builder-aba.out.txt.
- Fix: Anchor builder views as well. In `builderView`, set `Anchor = unsafe.StringData(builder.String())` and `Backing` to that address when `Cap() > 0`. `validWriterView` and the Buffer-only interval index already accept this. The old array then stays live while the entry exists, and view equality includes the anchor. The charge is already `sizeClass(cap)`.

### store-writer-F3: Repeated String() on an unchanged tracked writer burns the request root budget
- Severity: Medium
- Category: false-negative
- Location: internal/taint/propagation/writer.go:215-237 (uses writer.go SnapshotWriter)
- Claim: Every `BuilderString`/`BufferString` call on a tracked writer publishes a new root: a fresh clone for Builder, the fresh `String()` result for Buffer. Nothing is cached, even when the view has not changed. A handler that calls String() in a loop (logging, progress output, retries) uses up the 512-roots-per-owner (or 2 MiB) budget. After that, the String() results and every other new root in the same request are dropped. The drop itself is bounded by design, but duplicate roots for the same unchanged writer content waste the budget.
- Evidence: .omo/review/evidence/store-writer/zz_review_builder_budget_test.go: `go test -run TestReviewRepeatedBuilderString -v ./iast/propagation/` gives `first untainted String() result at call #511 of 700`. Output: .omo/review/evidence/store-writer/builder-string-budget.out.txt.
- Fix: Cache the last published string, with its view and set version, in `writerRecord`. Return the cached result when the view is unchanged, and drop the cache on any view change or removal.

### store-writer-F4: The "4 owners per receiver" limit is soft, and exceeding it wipes a whole owner
- Severity: Low
- Category: memory-bound
- Location: internal/taint/store/writer.go:104-107; internal/taint/propagation/writer.go:123-133
- Claim: The second loop in `updateWriter` creates entries for owners that appear in the input snapshot even when `LookupWriterValue` already returned 4 owners, so a receiver can be tracked by more than 4 owners. On the next lookup, the 5th owner is dirtied, which wipes all 8 of its writers, not just this receiver. Memory stays bounded at 8 entries per owner, so the only harm is lost provenance.
- Evidence: static reasoning only
- Fix: Skip creating a new entry when the receiver's owner fanout is already full. On fanout overflow, remove only the matching entry instead of dirtying the owner.

### store-writer-F5: A dirty owner keeps stale entries, charges and the process fast gate until it next writes
- Severity: Low
- Category: perf
- Location: internal/taint/store/writer.go:85, 241-251
- Claim: `LookupWriterValue` skips dirty owners, so Lookup-driven paths never clear them. Their entries, anchors and charges, plus `writerbridge.Active()`, stay in place until that owner's next Update/Adopt/Reset/Truncate or Finish. Until then, every bytes.Buffer mutation in the process takes the `InvalidateBuffer` slow path. Everything is still bounded and released at Finish.
- Evidence: static reasoning only
- Fix: In `LookupWriterValue`, when a dirty owner is seen and `writersMu.TryLock` succeeds, clear it inline.

### store-writer-F6: Dirtying on lock failure is not counted
- Severity: Low
- Category: quality
- Location: internal/taint/store/writer.go:93-96, 380-383
- Claim: Both paths set `writerDirty` without incrementing `drops.contention`, so the losses in F1 do not show in the counters (observed: `B contention drops = 0` after the wipe).
- Evidence: .omo/review/evidence/store-writer/poisoning-store.out.txt
- Fix: Add `record.drops.contention.Add(1)` on both paths.

## Checked and found correct
- No orphaned entries. Every removal path (`removeWriterLocked`, `clearDirtyWritersLocked`, `releaseWritersForFinishLocked`, the `Acquire` re-clear) balances `writerCount` and `addWriterStates`. Finish takes `lifecycleMu.Lock` and `writersMu.Lock`, clears the anchors, and subtracts the writer charge before `charged.Swap(0)`, so nothing is subtracted twice (owner.go:171-179, 207-211). Late writes are rejected by `beginWrite` (gen, state, lifecycle RLock).
- Bounds: `MaxWriters=8` is enforced at writer.go:210-212. The charge is `sizeClass(cap)` and `validWriterView` rejects cap above 64 KiB. Owner and process reservations use CAS with rollback (474-496). New-entry charge failure removes the entry with states balanced.
- Lock order is lifecycleMu then writersMu on every path, and hot paths only use TryLock, so there is no deadlock. The seqlock `writerVersion` stays balanced because the deferred increment runs before the deferred Unlock (LIFO).
- Buffer copy transfer: `AdoptBufferWriter` finds the donor by exact view (pointer, len, cap, backing, anchor), drops a stale receiver entry first, and re-keys the donor to the receiver. A later write by the donor into the shared backing hits the BackingWrite hook with `preserve` and invalidates the copy. The Buffer Anchor prevents address reuse, so there is no Buffer ABA.
- Mutable exposure: `Bytes`/`AvailableBuffer`/`Peek`/Read-family hooks invalidate the receiver and overlapping backings. `bufferView`'s own `Bytes()` call is suppressed by the expectation marker.
- `UpdateWriter` arithmetic is done in uint64. A mismatched pre-view restarts from written ranges at offset `before.Length`, so earlier content becomes a miss, not a false positive. `TruncateWriter` slices from 0 to after.Length. The `InvalidateBuffer` swap-remove loop does not skip entries.
- The existing writer tests pass with -race: .omo/review/evidence/store-writer/baseline-writer-tests.out.txt (exit 0).

## Not covered / open questions
- I did not do a woven (orchestrion) run of the native bytes.Buffer hooks. F1 was reproduced through the public wrapper path (`LookupWriterValue`), and I expect the hook path (`InvalidateBuffer`) to amplify it, because it fires for every bytes.Buffer write in the process.
- I reviewed collisions and nesting in the writerbridge expectation table (128 slots, 4 probes) only statically. They look conservative (a miss invalidates).
- Retained heap versus charged bytes for interior-slice Buffers (`NewBuffer(big[:0:n])`) is a documented trade-off and I did not re-measure it here.

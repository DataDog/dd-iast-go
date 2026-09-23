# store-root: managed roots (internal/taint/store/root.go)
Verdict: Root creation, adoption, generations and overflow handling are correct and race-free. No Critical or High issue was found. One Medium lifecycle defect: a rollback that loses a TryLock leaks the root slot and its byte charge until owner Finish, so ordinary intra-request contention builds up into request-wide taint loss. The other findings are minor charge-accounting and doc issues.
Scope covered: `internal/taint/store/root.go` (all functions), plus `limits.go`, `overflow.go`, `value.go` (putWindow/insertWindow/reserveRootValue/stale/reclaim), `mutation.go`, `owner.go` (Acquire/beginWrite/Finish), `lookup.go`, `store.go`, and the production callers `request/owner.go` (TaintString/TaintBytes/ManageString), `request/reader.go`, `taint/taint.go`, `propagation/{propagation,conversion,writer,json,string_exact}.go`. Ran reproducers and the full store package under `-race` on go1.26.6 in a private copy.

## Findings
### store-root-F1: Contended rollback leaks the root slot and charge until Finish; leaks accumulate into request-wide false negatives
- Severity: Medium
- Category: leak
- Location: internal/taint/store/root.go:370-375 (also 281-345, where reservation and publication use two separate `rootsMu.TryLock` sections)
- Claim: Every failure after `reserveRootSlot` calls `rollbackRoot`. That function uses `rootsMu.TryLock()`, and on failure it only increments `drops.contention` and returns: "The bounded reservation and any published anchor remain owned until Finish". The rootID is not pushed back to `rootFree`, `rootCount` is not decremented, and `owner.charged`/`store.charged` stay reserved. If `publishRoot` succeeded, the clone also stays strongly anchored. `TryLock` fails whenever any reader holds `rootsMu`: concurrent `Derive`/`putWindow` (TryRLock at value.go:115), propagation `AdoptString`/`AdoptBytes` on other goroutines of the same request, or a foreign owner's `Lookup` (lookup.go:151). These failures are correlated, because the contention that makes `publishRoot` or `putWindow` fail is the same contention that makes the rollback TryLock fail right afterwards. Each leak is permanent for the request. After about 31 leaked 64 KiB roots, the 2 MiB request budget is gone. After 512 leaked roots of any size, `drops.full` rejects every new root. From then on, every source and every propagated result in that request is dropped (false negatives on supported paths). The request's charge also stays counted against the 8 MiB process budget for the life of the request, which matters for long-lived requests. Finish does reconcile everything, so this is request-scoped and not a process leak.
- Evidence: `.omo/review/evidence/store-root/zz_review_root_test.go`; command in `commands.txt`; output in `review-run.txt`, `review-run-race.txt`.
  - Deterministic (shard lock held, 4 derivers): `attempts=121 succeeded=0 leakedRoots=31 leakedCharge=2031616 requestBudget=2097152`, then an uncontended `TaintString(64KiB) after leaks ok=false`. After Finish, `processCharged=0`.
  - Natural contention with no artificial locks and production shape (one source goroutine, since sources are serialized by `sourceMu`; 3 propagation goroutines running `AdoptString`; 4 derivers): `leaked root slots=367` out of 4,800 attempts. Under `-race` the count was `305`.
  - Root-count variant (`zz_review_rollback_test.go`, left in the private dir by an earlier run of this node): `after 512 rejected windows: charged=4096 rootCount=512 values=0 next root admitted=false`.
- Fix: Do not drop the rollback. Two options:
  1. Take `rootsMu.Lock()` (blocking) in `rollbackRoot`. This is bounded, because every rootsMu holder is a short non-blocking section, and the lock order lifecycleMu -> rootsMu -> overflowMu is preserved.
  2. Record the rootID and charge in a small per-owner pending-release bitset/array that the next exclusive holder of rootsMu drains.

  Also fold `reserveRootSlot` and `publishRoot` into one exclusive section. That removes one contention point per root and halves the window.

### store-root-F2: sizeClasses table does not match the Go runtime and undercharges 80 sizes
- Severity: Low
- Category: memory-bound
- Location: internal/taint/store/limits.go:38-39 (used by every charge in root.go:34,74,115,157,199,236,247)
- Claim: The table lists `1088` and `5392`. Go 1.26.6 and 1.27.0 `internal/runtime/gc.SizeClassToSize` have `1024, 1152` and `4864, 5376, 6144`, with no 1088 or 5392 class. Values of 1025-1088 bytes are charged 1088 but retain 1152. Values of 5377-5392 bytes are charged 5392 but retain 6144 (up to 752 B, about 12%, under the real size). The 5377-5392 range is also a real overcharge for 4865-5376. The bound can be exceeded only by a small factor.
- Evidence: `.omo/review/evidence/store-root/zz_review_root_test.go` `TestReviewSizeClassMatchesRuntime`, which uses `cap(append([]byte(nil), make([]byte,n)...))` as the runtime class. Output in `review-run.txt`: `sizes 1..65536: undercharged=80 (first=1025 last=5392 worst n=5377 by 752 bytes)` and `n=5377 charged=5392 runtimeClass=6144`.
- Fix: Replace the entries with the runtime table (`...1024, 1152...`, `...4864, 5376, 6144...`). Add a test that compares `sizeClass(n)` with append-rounded capacity for 1..MaxRootBytes.

### store-root-F3: TaintBytes/TaintSourceBytes replacement zero-fills [len:cap] and breaks aliasing, which the public doc does not say
- Severity: Low
- Category: doc
- Location: internal/taint/store/root.go:120-121,162-163; taint/taint.go:135-141
- Claim: `make([]byte, len(value), cap(value)); copy(clone, value)` copies only the visible bytes. The returned slice has the caller's capacity, but its tail is zeros instead of the caller's spare-capacity bytes. `append` and reslicing to capacity also no longer affect the caller's backing array. The public `taint.TaintBytes` promises "a managed mutable replacement with the same length and capacity", which suggests the replacement is equivalent. This is only reachable through explicit calls to the public API (no woven hook calls it), so the impact is limited.
- Evidence: `TestReviewTaintBytesTailAndAliasDiverge` in `review-run.txt`: `original[:cap]="HEADER-PAYLOAD-TAIL-DATA" managed[:cap]="HEADER\x00\x00..."`; after `append` on managed, `backing` is unchanged.
- Fix: Document that bytes beyond `len` are zeroed and that the result no longer aliases the input. Alternatively, copy `value[:cap(value)]` (the root already charges and spans cap).

### store-root-F4: Adopt pre-check rejections are invisible to drop telemetry
- Severity: Low
- Category: quality
- Location: internal/taint/store/root.go:231-247
- Claim: `AdoptString`/`AdoptBytes` return false for `len<2`, `len/cap > MaxRootBytes`, or an invalid key without incrementing any drop counter. `TaintString` and the other constructors count `oneByte` and `bytes` for the same conditions. Propagation losses caused by oversize results therefore do not appear in `Counters()`, which hides a false-negative class from telemetry.
- Evidence: static reasoning only; compare root.go:26-33 with 233-235.
- Fix: Increment `drops.oneByte`/`drops.bytes` after a successful `beginWrite`, or move the checks into `adopt`.

### store-root-F5: Root generations never advance in production; generation ABA analysis is moot and architecture step 4 is not live
- Severity: Info
- Category: doc
- Location: internal/taint/store/root.go:330-343,391; internal/taint/store/mutation.go:25,79
- Claim: `publishRoot` always runs on a fresh root (generation 0 -> 1). `rollbackRoot` and Finish reset to 0. The only incrementer, `claimMutation`, is called only by `PublishBytesMutation`, and a repo-wide `rg` finds no non-test caller of `PublishBytesMutation`. In production every root generation is 1, so the uint32 wrap and ABA risks are unreachable. The "Byte mutation claims a new root generation" path described in 00-architecture.md step 4 is test-only. Stale-bytes invalidation relies entirely on the writer machinery and on the documented "append/copy/index writes unsupported" limitation.
- Evidence: static reasoning; `rg -n 'PublishBytesMutation|claimMutation' --glob '!*_test.go'` shows only the definitions in mutation.go.
- Fix: Either wire it or document it as reserved API. Not a defect by itself.

### store-root-F6: Process-wide overflow pool is first-come; one request can take all 256 blocks
- Severity: Info
- Category: memory-bound
- Location: internal/taint/store/root.go:354-361; overflow.go:8-18
- Claim: Ranges 11-64 need one of 256 process-global overflow blocks, which are allocated without a per-owner quota. A single owner (512 roots) can hold all of them, and every other request's multi-range roots then truncate to 10 ranges (counted in `drops.ranges`). This matches the documented "guaranteed ten ranges" contract, so it is listed only as a fairness observation.
- Evidence: static reasoning only.
- Fix: Optionally cap overflow blocks per owner (for example 256/MaxConcurrentRequests).

## Checked and found correct
- Every constructor (TaintString, TaintSourceString, TaintBytes, TaintSourceBytes, AdoptSourceBytes, adopt) calls `rollbackRoot` on every failure after `reserveRootSlot` (root.go:41-55, 81-96, 122-136, 166-180, 210-224, 263-267). Early exits before reservation hold no state.
- Charges: string roots use `sizeClass(len)`, byte roots use `sizeClass(cap)` (span = cap), and source variants add the cloned name and the `string(value)` copy. The worst case, 3 x 64 KiB, equals `MaxRootChargeBytes`. The reservation order is owner then process, and the process-failure path undoes the owner charge and returns the rootID (root.go:303-316). Successful rollback subtracts both counters exactly once. Finish swaps the residual, including leaked rollbacks: the reproducer shows `processCharged=0` after Finish.
- Production AdoptString inputs are fresh exact allocations: `strings.Clone` in propagation and JSON, `string(b)` in BytesToString (heap because the param leaks into the root anchor), and `bytes.Buffer.String()`. Builder results are cloned (`publishWriterString(clone=true)`). String charges are therefore accurate for these callers.
- Generation and ABA: a rollback-reset rootID republishes at generation 1. This is safe because a RootRef escapes only after `putWindow` succeeds, successful roots never return to the free list within an owner generation, and `putWindow` failure paths never leave a slot for the new root (including the existing-slot branch, value.go:172-187). Cross-generation safety comes from the 64-bit `ownerGen` in slots, `Entry.Handle`, and the double gen check in `beginWrite`.
- Anchors keep the whole allocation alive (interior pointers included), so no same-owner address reuse can alias a live slot. Clones for tiny values share 16-byte tiny blocks, but at distinct addresses, and spans stay within the object.
- Lock order is lifecycleMu -> rootsMu -> overflowMu everywhere (publishRangesLocked TryLock, rollback/Finish Lock). `PublishBytesMutation` takes overflowMu outside rootsMu, so there is no reverse nesting and no deadlock. Overflow blocks are freed by rollback, Finish, and mutation, and never leak on the TaintString/adopt paths.
- All root constructors, `adopt` and `Derive` go through `beginWrite`, so they are excluded from Finish's `lifecycleMu.Lock()`. Rollback's counter release cannot race Finish's swap.
- Limits: the 512 roots/owner check (`rootCount` = `rootNext` - `rootFreeN`), 2 MiB/8 MiB CAS reservations, the `len<2` rejection (documented), and `len/cap/name > 64 KiB` rejections all drop without changing the host value.
- The full store package under `-race` (go1.26.6) had no data race. All pre-existing tests pass.

## Not covered / open questions
- The AdoptBytes callers' allocation-base proofs (`bytes_exact.go`, `propagation.go:475,593,695`) belong to the propagation node. An interior-slice adoption would undercharge by an unbounded factor, and root.go cannot enforce this.
- value.go:172-187 (outside the primary scope): if `reclaim` loses its `lifecycleMu.TryRLock` (only while Finish is pending), a stale same-owner slot is repointed without incrementing `owner.values`. This is transient counter drift that Finish reconciles. It was not reproduced.
- Retained-heap versus charged measurement under full saturation (24 MiB envelope) was not run here.

# store-binding: Owner binding and lifecycle
Verdict: One High-severity supported-path false negative from object-address binding collisions; owner retirement and panic cleanup otherwise work in the tested paths, with one Low-severity stale-handle telemetry defect.
Scope covered: `internal/taint/store/binding.go` (`BindObject`, `BindObjectValue`, `lookupObject`, `bindingTable.bind/reset`, `OwnerRef`), `owner.go` (`Acquire`, `beginWrite`, `Finish`, handle accessors), plus `store.go`, `lookup.go`, `root.go`, `writer.go`, request owner/scope/HTTP/reader/query callers, net/http entry advice, existing binding/race tests and the phase-1 design/research context.

## Findings

### store-binding-F1: Reader binding replaces URL binding at an aliased address
- Severity: High
- Category: false-negative
- Location: internal/taint/store/binding.go:167-202
- Claim: The binding index and replacement branch compare only the numeric pointer, ignoring `BindingKind`. A valid `*url.URL` can occupy the first field of a body reader: `&body.URL` and `body` then have the same address but are distinct typed objects. `EagerHTTP` binds the URL first and reader second (`internal/taint/request/http.go:74-76`), so the reader overwrites the URL binding. The supported `URL.Query()` callback (`internal/taint/request/lazy.go:27-45`) finds no URL owner and leaves its parsed result clean, even though the active request owns both objects.
- Evidence: `.omo/review/evidence/store-binding/store_binding_review_test.go` and `.omo/review/evidence/store-binding/url-reader-collision.out.txt`. In the private copy, `GOTOOLCHAIN=go1.26.6 go test -run TestReviewURLBindingSurvivesReaderAtSameAddress -count=1 -v -timeout=2m ./internal/taint/request` fails with `URL bindings=0 reader bindings=1 query tainted=false query="attack"`. The fixture checks the shared address and uses the real eager binding and URL-query management paths.
- Fix: Index object bindings by both address and kind; preserve each typed anchor independently and keep the reader-specific limit. Define generic `LookupObject` behavior for multiple kinds on one address without duplicate owner attribution.

### store-binding-F2: Stale owner handle exposes and charges a successor
- Severity: Low
- Category: quality
- Location: internal/taint/store/owner.go:72-75,94-124
- Claim: `Owner.ID`, `Charged`, `Values`, `Counters`, and `RecordBytesDrop` access slot-global fields without checking the handle's captured generation. After `Finish` and slot reuse, an old `Owner` reports the new owner's ID and `RecordBytesDrop` changes the new owner's drop counter. Mutating store operations are protected by `beginWrite`, so this reproducer demonstrates incorrect identity/telemetry rather than incorrect taint publication.
- Evidence: `.omo/review/evidence/store-binding/store_binding_stale_review_test.go` and `.omo/review/evidence/store-binding/stale-owner-handle.out.txt`. `GOTOOLCHAIN=go1.26.6 go test -run TestReviewStaleOwnerCannotMisidentifyAndChargeReusedSlot -count=1 -v -timeout=2m ./internal/taint/store` fails with `previous ID=1 new ID=2 stale.ID()=2 new owner bytes drops=1`.
- Fix: Retain the captured owner ID in the handle for identity reads; generation-gate stale read accessors and serialize mutable drop accounting with the owner lifecycle so a concurrent slot reuse cannot receive a late increment.

## Checked and found correct

- `OwnerRef.Handle` rejects the old generation after slot reuse; the panic-cleanup control in `.omo/review/evidence/store-binding/store_binding_review_test.go` confirmed a stale reference stayed invalid.
- A deferred `Analysis.Finish` on a panicking handler released the reader binding, managed-root charge, value count and analysis permit; `.omo/review/evidence/store-binding/panic-cleanup.out.txt` captures the passing run. Both woven HTTP entry advices install `defer Finish` before eager binding (`iast/net/http/orchestrion.yml:33,107`).
- `Owner.Finish` transitions to `stateFinishing` before taking the lifecycle write lock, clears writer and root anchors under that lock, resets bindings before setting `stateDead`, and does not finish a reused generation. The existing `internal/taint/store` suite passed: `GOTOOLCHAIN=go1.26.6 go test -count=1 -timeout=3m ./internal/taint/store`.
- Independent active owners may bind the same reader; the existing `TestReaderBindingFanoutAndStaleReferences` verifies fanout, per-owner cleanup and invalidation. Non-pointer, typed-nil and zero-sized dynamic bindings are rejected by `dynamicPointer`/binding guards.

## Not covered / open questions

- No woven end-to-end HTTP/SQL sink test or GC-retained-heap saturation run was performed. The failing source-path test invokes the registered binding and query callback directly, without Orchestrion.
- The panic control models the advice's deferred cleanup; it does not induce a panic through an instrumented HTTP server.

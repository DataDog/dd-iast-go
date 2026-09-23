# life-weak-gc: weak-pointer span/owner association under GC pressure
Verdict: The weak-pointer mechanics are correct: across about 1,100 GC-interleaved lifecycles there were no lost live associations and no retention after finish, and the `-race` run was clean. The span-association store around them is not: its capacity accounting and finish semantics drop findings of admitted requests under ordinary concurrency and after late span creation, and with dd-trace-go's span pool they bleed findings across traces. The result is 3 High, 3 Medium, 1 Low, and 1 Info.
Scope covered: internal/spans/{owner,annotation,orchestrion,vulnerability}.go (full read); tainted.go (TryCommitTainted, releaseSourceIdentities); internal/vulnerability/{tainted,report}.go (span selection, dedup); internal/taint/request/{scope,owner}.go (Begin/Acquire/Finish); internal/taint/store/owner.go:18-64; internal/taint/scopebridge; iast/net/http/{orchestrion.yml,http.go}; dd-trace-go v2.11.0-rc.1 tracer span.go (Root, Finish, clear), span_pool.go, tracer.go:887-912, mocktracer. I ran 10 reproducer/check tests on go1.26.6 and go1.27.0, plus a `-race` run.

## Findings

### life-weak-gc-F1: Sampled-out requests fill the annotation store and starve admitted active requests
- Severity: High
- Category: false-negative
- Location: internal/spans/annotation.go:198-212, internal/spans/annotation.go:227-236, internal/config/config.go:74
- Claim: `BindScope` stores `&Annotation{Sampled: active}` for every scope-bound root, including sampled-out and capacity-dropped requests (`annotation.go:200-205`). The store admits only `config.MaxConcurrentRequests` entries (`trimStore`, `annotation.go:235`), which defaults to 2. That is the same number as the analysis permits, but the store also counts spans that are not analyzed: 70% of requests at the default 30% sampling, and `AnnotationFor` spans of non-HTTP traces. `trimStore` evicts only dead weak keys, so live negative entries cannot be evicted. A request that holds an analysis permit (taint tracking runs and costs CPU) then gets `BindScope == nil`, no owner binding, and `NewOrphanTaintedSpan` also fails `trimStore`. `ReportTainted` therefore drops every finding (`vulnerability/tainted.go:62-67`). Forcing GC does not help because these spans are live.
- Evidence: .omo/review/evidence/life-weak-gc/review_gc_internal_test.go (`TestReviewSampledOutRequestsStarveActiveRequest`, `TestReviewSampledOutStarvationRate`); command in evidence/README.md; logs review-run.log and review-run-go127.log:
  `store.Size=2 activeAdmitted=true BindScope=0x0 ExistingForOwner=false ExistingForSpan=false(0x0) orphanAnnotation=0x0`
  With default config (30%, capacity 2), the share of admitted active requests left without an annotation was: `inflight= 3 ... (30.1%)`, `inflight= 4 ... (44.8%)`, `inflight= 8 ... (64.3%)`, `inflight=16 ... (69.4%)`.
- Fix: Do not let negative decisions occupy capacity that active analyses need. Either (a) do not store a negative entry for scope-bound spans, because the scope already carries the decision, or (b) when the store is full and a Sampled annotation must be created, evict a `Sampled:false` entry, which holds no data. At minimum, size the store as `MaxConcurrentRequests` Sampled entries plus separately bounded negatives.

### life-weak-gc-F2: Spans created after root Finish resurrect an annotation keyed on the finished root, leaking a slot and silently discarding findings
- Severity: High
- Category: false-negative
- Location: internal/spans/orchestrion.go:28, internal/spans/annotation.go:186-212, internal/spans/annotation.go:122-147, iast/net/http/http.go:21-26, internal/vulnerability/tainted.go:100-105
- Claim: `Finished` deletes the root's entry (`LoadAndDelete`) and leaves no tombstone. Any later `BindScope`, `AnnotationFor`, or `AnnotationForContext` on a span of that trace re-creates an entry keyed on the finished root, because `child.Root()` still returns the finished root. Triggers include the woven `StartSpanFromContext` hook (`BindStartSpan`, which also covers contrib DB spans) and weak-crypto `Report` from a goroutine that outlives the handler. Nothing ever finishes that entry, since `Finished(child)` does not match the root key. It stays in the store while anything reaches the root span (the child, or the context held by the goroutine), and only GC plus a later trim reclaims it. With the default capacity of 2, two such goroutines disable IAST for all new requests. If the scope is still active (the window between root Finish and scope Finish), the new annotation is Sampled and gets owner-bound. `TryCommitTainted` then returns true, and `commitTainted` records the hash in dedup, but the finding can never be emitted. Identical findings in later requests are then deduplicated away for the one-hour window. The dedup consequence is static reasoning from `tainted.go:100-105`.
- Evidence: .omo/review/evidence/life-weak-gc/review_gc_internal_test.go (`TestReviewLateBindAfterRootFinishLeaksSlot`, `TestReviewLateBindActiveScopeSilentlyDropsCommittedFinding`), review-run.log:
  `store.Size after two finished requests with late child spans = 2` / `next active admitted=true annotation=0x0` / `store.Size after late children finished (roots still reachable) = 2` / `store.Size after roots unreachable + GC + trim = 0`
  `lateAnnotation=0x4b8228ff9b08 ExistingForOwner=true committed=true rootFinished=true` then `BUG: finding committed to an annotation of an already-finished root`.
- Fix: At `Finished`, replace the entry with a shared closed, unsampled tombstone instead of deleting it. `BindScope`, `AnnotationFor`, and `ExistingFor*` then see a closed entry and never re-create one. `trimStore` must drop tombstones first when capacity is needed, and dead keys as today. Alternatively, record the root span ID in the annotation and reject re-creation for a root whose span is finished. Do not add dedup hashes for commits into annotations that can no longer flush.

### life-weak-gc-F3: With dd-trace-go's span pool, a recycled root inherits another trace's annotation (cross-trace bleed or false negative)
- Severity: High
- Category: cross-request
- Location: internal/spans/annotation.go:31, internal/spans/annotation.go:190-197, internal/spans/owner.go:21 (dd-trace-go v2.11.0-rc.1 ddtrace/tracer/span_pool.go:17-42, tracer.go:901-912)
- Claim: dd-trace-go v2.11.0-rc.1 can recycle `*tracer.Span` objects through `sync.Pool`. This is enabled by `DD_TRACER_EXPERIMENTAL_SPAN_POOL_ENABLED` or `tracer.WithSpanPool(true)`, which is opt-in and experimental but reachable by customers. The only identity the store keys on is `weak.Pointer[tracer.Span]`. A recycled object has the same weak handle, and `Value()` is non-nil, so any stale entry is inherited by whatever new trace root reuses that object. Stale entries come from F2, and from abandoned or unfinished entries. `BindScope` returns the stale Sampled annotation, carrying the previous trace's findings, to a new active HTTP request, and they are emitted on the new request's span. A stale negative entry instead makes an admitted active request return nil. This breaks the invariant that a weak key means "this span". The comment in span_pool.go also says opting in requires not inspecting spans after release.
- Evidence: .omo/review/evidence/life-weak-gc/review_pool_internal_test.go (`TestReviewSpanPoolRecycledRootInheritsStaleAnnotation`, real tracer with httptest agent, GOMAXPROCS=1), review-pool.log and review-run-go127.log:
  `attempts=1 recycledSameObject=true ... scopeActive=true BindScope==stale:true staleSampled=true vulnerabilitiesAlreadyOnNewRequest=1` then `BUG (cross-request bleed): new request root inherited trace A's annotation carrying 1 foreign finding(s)`
  `... scopeActive=true BindScope==stale:false staleSampled=false ...` then `BUG (false negative): active admitted request inherited trace A's negative decision; BindScope returned nil`
- Fix: Store the root's `(traceID, spanID)` in `Annotation` and in `ownerSpanBinding`, and validate it on every load (`BindScope`, `AnnotationFor`, `ExistingForSpan`, `ExistingForOwner`, `Finished`). Treat a mismatch as absent, and replace or close the stale entry. This check is cheap, and it also hardens F2. Alternatively, document span-pool mode as unsupported and disable IAST when it is enabled.

### life-weak-gc-F4: `Finished` runs `weak.Make` on every finished span in the process, even with IAST disabled
- Severity: Medium
- Category: perf
- Location: internal/spans/orchestrion.go:27-31, internal/spans/orchestrion.yml:26-30
- Claim: The woven `Span.Finish` prologue calls `Finished` for every span. `Finished` immediately calls `weak.Make(span)`, which registers a runtime weak-handle special and allocates a handle for spans that never had one. That is almost all spans, since only roots of IAST-touched traces are keys. It does this even when `config.Enabled` is false and the store is empty. This adds allocation and GC special-record work to every application span for no benefit, which conflicts with rule 2.
- Evidence: .omo/review/evidence/life-weak-gc/review_gc_internal_test.go (`TestReviewFinishedAllocatesPerSpan`), review-run.log: `config.Enabled=true store.Size=0 allocs per Finished(never-annotated span)=1.00` and `config.Enabled=false store.Size=0 allocs per Finished(never-annotated span)=1.00`
- Fix: Gate before `weak.Make` with `if !config.Enabled || store.Size() == 0 { return }`, or with a cheap atomic entry counter. Optionally also skip when `span.Root() != span && span.Root() != nil`, because only roots and root-less spans are keys.

### life-weak-gc-F5: Request admission drops up to about 30% of scopes under plain concurrency with free capacity
- Severity: Medium
- Category: false-negative
- Location: internal/taint/store/owner.go:24-27, internal/taint/store/owner.go:34-36
- Claim: This is outside my primary scope and was found while building the GC harness. `Store.Acquire` gives up when `ownerMu.TryLock` fails, and it skips slots whose `writersMu.TryLock` fails. With 8 goroutines calling `request.Begin` and 64 free slots, 0 to 387 of 1,200 admissions came back `DecisionCapacityDropped`. The number depends heavily on scheduling. "Drop rather than block" is the documented policy, but losing about a third of sampled requests to a short mutex, with capacity available, is a large false-negative rate. It deserves a CAS-based slot claim.
- Evidence: .omo/review/evidence/life-weak-gc/review_gc_internal_test.go (`TestReviewAdmissionDropsUnderConcurrency` and the `admissionDrops` counter in the lifecycle test). The go1.26.6 run in review-run.log showed `forceGC=false concurrency=8 capacity=64 admitted=813 dropped=387`; the go1.27 run in review-run-go127.log showed `forceGC=false ... dropped=0` and `forceGC=true ... dropped=32`. Earlier runs logged `admissionDrops=785` and later `47`/`132`/`70` of 1,200.
- Fix: Claim owner slots with a per-slot state CAS (`stateUnused/Dead -> stateAcquiring`) instead of a global `TryLock`, or retry `TryLock` a bounded number of times. Also decouple the `writersMu` reset from acquisition.

### life-weak-gc-F6: No test exercises GC, recycling, or post-finish binding on the span association
- Severity: Medium
- Category: test-gap
- Location: internal/spans/owner_internal_test.go:19-116, internal/spans/annotation_sampling_test.go:154-169
- Claim: The existing tests keep every span strongly reachable, never call `runtime.GC`, never drop references to observe weak collection or `trimStore` reclamation, and never bind after root finish or with the span pool. `TestNegativeAnnotationsRespectCapacity` treats negative entries consuming capacity as the intended behavior, without checking the starvation effect on active requests described in F1. F1 through F3 are all invisible to the current suite.
- Evidence: The reproducers in .omo/review/evidence/life-weak-gc/ fail against HEAD while the existing suite passes (base-test logs in phase1).
- Fix: Adopt the passing checks (`TestReviewGCLifecycleNoLossNoRetention`, `TestReviewAbandonedSpanReclaimed`, `TestReviewContextOnlyReachability`) as regression tests, and the failing ones once fixed.

### life-weak-gc-F7: The dead-annotation release and its source-byte charge depend on an unrelated later bind
- Severity: Low
- Category: memory-bound
- Location: internal/spans/annotation.go:227-249
- Claim: An abandoned or never-finished root that gets collected keeps its `processEventSourceBytes` charge (at most 256 KiB per event, 2 MiB process-wide) until some later `AnnotationFor`, `BindScope`, or orphan call runs `trimStore` while the store is at or above the threshold. Memory stays bounded. In the interim, other annotations' commits can fail against the process charge. The effect is limited, and trimming does work once triggered.
- Evidence: .omo/review/evidence/life-weak-gc/review_gc_internal_test.go (`TestReviewAbandonedSpanReclaimed`): `charge before trim=25 after=0 storeSize=0`. The charge was released only after an explicit `trimStore()`.
- Fix: Optionally attach `runtime.AddCleanup(root, ...)` at annotation creation to release the charge and delete the key when the span is collected, or trim when `reserveEventSourceBytes` fails.

### life-weak-gc-F8: The owner binding keeps a closed annotation (with its Event) alive after the root finishes
- Severity: Info
- Category: memory-bound
- Location: internal/spans/owner.go:18-23, internal/spans/owner.go:90-98
- Claim: `ownerSpanBinding.annotation` is a strong pointer. After `Finished`, the closed annotation, with its vulnerabilities and sources, stays reachable through `ownerSpans[index]` until scope Finish, or until `ExistingForOwner` sees a dead root. There are 64 slots, so this is bounded and short-lived. `Finished` could `CompareAndSwap` the binding to nil to release it earlier.
- Evidence: Static reading. The lifecycle test shows everything is collected after scope Finish (`aliveAnnotations=0`).
- Fix: Optional: clear matching `ownerSpans` entries in `Finished` (the annotation pointer is an adequate match key).

## Checked and found correct
- Weak-pointer usage: keys are `weak.Make` of heap-allocated `*tracer.Span` base pointers (`&Span{}` or pool). dd-trace-go's tracer has no `SetFinalizer` or `AddCleanup` (grep), so there is no resurrection, and `Value()` cannot be nil while the span is reachable. The span is referenced only weakly: neither the store key nor `ownerSpanBinding.root` retains it, and `Annotation` holds no span pointer.
- No loss under GC pressure: `TestReviewGCLifecycleNoLossNoRetention` ran 8 workers with GC percent 1, an allocation churner, and `runtime.GC()` twice between every step (start, bind, lookup, commit, Finished, finish, scope finish). Across 1,153 (go1.26.6), 1,130 (go1.27.0), and 1,068 (`-race`) lifecycles there were 0 failures: `ExistingForOwner`/`ExistingForSpan` always resolved the live span and annotation, and every event was emitted. The `-race` run reported no data race.
- No retention after finish: the same test logs `aliveSpans=0 aliveAnnotations=0 storeSize=0 processSourceBytes=0` after `mock.Reset()` and GC.
- A span reachable only through a `context.Context` keeps resolving across 5 GCs (`TestReviewContextOnlyReachability`).
- An abandoned, unreachable root is collected. `ExistingForOwner` CASes the dead binding to nil (`owner.go:79-82`), and `trimStore`/`releaseDeadAnnotation` release the entry and its source charge (`TestReviewAbandonedSpanReclaimed`).
- `bindOwnerSpan` re-validates identity after the CAS and rolls back on a concurrent scope finish. The existing `TestOwnerSpanConcurrentBindAndFinish` passes under `-race`. `finishOwnerSpan` matches both id and generation.
- The orphan path calls `Finished` explicitly and then `Finish`, which runs the hook again. `LoadAndDelete` makes the second call a no-op.

## Not covered / open questions
- I did not run a woven (orchestrion) build. The Finish hook and `BindStartSpan` wrapping were emulated with direct calls, as `http.go` does. That contrib `StartSpanFromContext` call sites are woven (the F2 trigger) comes from reading `iast/net/http/orchestrion.yml:50-75` and was not observed in a woven binary.
- The one-hour dedup suppression after a commit into a never-flushed annotation (F2) is static reasoning from `vulnerability/tainted.go:100-105`, with no end-to-end reproducer.
- F5 is outside my primary scope. It should be cross-checked by the request/store admission node.
- I did not test with a moving GC or on 32-bit targets. The weak-pointer semantics are specified by the Go runtime independently of these.

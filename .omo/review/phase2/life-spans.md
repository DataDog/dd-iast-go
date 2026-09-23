# life-spans: span/owner association, annotation at finish, orphan reporting
Verdict: NOT correct. The payload, transactional commit and owner-binding code is sound. The span association store around it is not. A late annotation on a finished root plus a second `Finish()` gives a reproduced data race in the Finish prologue (Critical). At the default capacity of 2, sampled-out requests starve active ones, whose tainted findings are then dropped. Late binds silently lose findings. Every weak-hash call made outside a span emits its own orphan trace span. Counts: 1 Critical, 3 High, 2 Medium, 2 Low.
Scope covered: internal/spans/{annotation,owner,orchestrion,payload,tainted,vulnerability,constants}.go and orchestrion.yml; callers internal/vulnerability/{tainted,report}.go, iast/net/http/{http.go,orchestrion.yml}, iast/crypto/hash/orchestrion.yml, internal/taint/request/scope.go, internal/model/event.go; dd-trace-go v2.11.0-rc.1 span.go (Finish/Root/SetTag/SetMetaStruct), span_pool.go, tracer.go processOutChunk, context.go GLS notes; commit 87ecf02. Ran 5 reproducers, including one under `-race` against a real tracer and a fake agent. Overlap: life-weak-gc-F1/F2 found the same root causes for F1/F2 independently. This node adds the dropped-finding/empty-orphan outcome, the resulting data race (F3), and F4/F5.

## Findings
### life-spans-F1: Negative sampling decisions fill the 2-slot annotation store; active requests lose their annotation and their tainted findings are dropped
- Severity: High
- Category: false-negative
- Location: internal/spans/annotation.go:198-212, internal/spans/annotation.go:227-236, internal/spans/vulnerability.go:23-27, internal/vulnerability/tainted.go:62-68,125
- Claim: Since 87ecf02, `BindScope` stores `Annotation{Sampled:false}` for every sampled-out and capacity-dropped scope. The store bound is `config.MaxConcurrentRequests` (default 2), which is the *active-analysis* bound. With 2 sampled-out requests in flight (70% of traffic at the default sampling rate), a concurrently admitted active request (it holds a permit and tracks taint) hits `trimStore()==false`. The result: `BindScope` returns nil and tags the span `_dd.iast.enabled=0`, and no owner binding exists. `ReportTainted` then falls through to `NewOrphanTaintedSpan`, which creates and finishes an orphan span but gets no slot either (`!trimStore()` returns a nil annotation), so the finding is dropped. Every later sink hit emits another empty orphan span, deduplicated hits included. Weak-sink findings for the request are dropped too (`AnnotationForContext` returns `nonSampledAnnotation`).
- Evidence: .omo/review/evidence/life-spans/zz_review_lifespans_test.go `TestReviewNegativeDecisionsCrowdOutActiveRequest`; `go test -count=1 -v -run TestReviewNegativeDecisions ./internal/vulnerability/` gives repro.out.txt: `active request: scope.Active()=true decision=3 BindScope annotation nil=true`, `ReportTainted first=false second(dedup)=false`, `weak-sink annotation for active request sampled=false`, two `finished span name="vulnerability" enabled=1 has_iast_json=false`, `name="active-request" enabled=0`.
- Fix: Do not count negative decisions against the active bound. Give them a separate fixed cache, or size the store as permits plus a bounded negative area. Never deny an annotation to a scope that holds a permit. In `NewOrphanTaintedSpan`, check capacity before `tracer.StartSpan`.

### life-spans-F2: A span bind or report after root Finish re-creates an open annotation that is never flushed; findings are silently lost
- Severity: High
- Category: false-negative
- Location: internal/spans/orchestrion.go:28, internal/spans/annotation.go:134-142,190-205, iast/net/http/http.go:21-25
- Claim: `Finished` removes the root's entry with `LoadAndDelete`. Afterwards, any `BindScope` or `AnnotationFor` on that root with `LoadOrCompute` stores a fresh open annotation. That happens for a late `StartSpanFromContext` (woven `BindStartSpan`), a weak report, or any child whose `Root()` is the finished root, since `Root()` keeps returning `trace.root`. `bindOwnerSpan` also rebinds the owner to it. Later `ReportTainted` and `Report` calls commit into this annotation and return true, but the root's Finish prologue has already run, so the findings are never emitted. Without the late bind, the same report would at least have become an orphan event. The entry and its event-source byte charge stay in the store until the span is GC'd and some later `trimStore` runs.
- Evidence: `TestReviewLateBindAfterRootFinishLosesFindings` gives repro.out.txt: `late bind: annotation nil=false same-as-original=false closed=false`, `ReportTainted returned true; zombie annotation holds 2 vulnerabilities`, `zombie still in store for finished root=true`, and no finished span has an IAST event.
- Fix: In `Finished`, replace the entry with a closed tombstone (for example a shared closed annotation) instead of deleting it. `trimStore` then removes it once the weak key is nil, so `LoadOrCompute` for a finished root returns a closed annotation and callers take the orphan path.

### life-spans-F3: Second Finish() of a root with a re-created annotation calls SetMetaStruct on a finished span, racing the trace writer
- Severity: Critical
- Category: race
- Location: internal/spans/orchestrion.go:39-46 (enabled by internal/spans/annotation.go:134-142 re-creation; dd-trace-go span.go:458-472, 862-866 has no `finished` guard)
- Claim: The woven prologue runs `Finished` on every `Span.Finish` call, and dd-trace-go explicitly tolerates repeated `Finish`. A late report after the first Finish re-creates a sampled annotation with a vulnerability (F2). A second `Finish()` on that root then runs `span.SetMetaStruct("iast", &ann.Event)` and `SetTag`. `SetTag` ignores finished spans. `setMetaStructLocked` does not, and the agent writer encodes finished spans without the span lock (`processOutChunk` → `payloadV04.push` → `metaStructMap.EncodeMsg`). The result is a data race on `span.metaStruct` (a map write, possibly racing its iteration, which the Go runtime reports as an unrecoverable fatal error) and on the `Event` being encoded. Preconditions: a real agent that supports meta_struct (the default modern agent), a customer double-Finish on a root, and a sink report between the two Finish calls that carries the root in its context.
- Evidence: `TestReviewDoubleFinishSetsMetaStructOnFinishedSpan` (real `tracer.Start` with a httptest agent that returns `span_meta_structs:true`). `go test -race -count=1 -v -run TestReviewDoubleFinish ./internal/vulnerability/` gives race.out.txt: `real tracer meta_struct available (SetMetaStruct returned) = true`, then 18 `WARNING: DATA RACE`, for example `Write ... (*Span).setMetaStructLocked() span.go:865 ← SetMetaStruct ← spans.Finished() orchestrion.go:44` against `Previous read ... (*metaStructMap).EncodeMsg() meta_struct.go:25 ← payloadV04.push ← processOutChunk tracer.go:909`, and `--- FAIL ... race detected during execution of test`. Peak RSS was 405 MB (under 4 GB).
- Fix: Use the F2 tombstone, so a repeated `Finished` sees a closed annotation and returns before touching the span. Defensively, record `flushed` on the annotation and never call `SetMetaStruct` or `SetTag` for an annotation created after its root's first Finish. Report upstream the missing `finished` check in `setMetaStructLocked`.

### life-spans-F4: Weak-crypto reports outside any span create and finish one orphan trace span per call, before any sampling or dedup gate
- Severity: High
- Category: perf
- Location: internal/spans/vulnerability.go:17-19, internal/vulnerability/report.go:45-54 (callers: iast/crypto/hash/orchestrion.yml `__dd__iast_ReportWeakHash__(nil, ...)`)
- Claim: Hooks pass a nil ctx. With no active GLS or context span (startup, background workers, SDK checksum code, `uuid.NewMD5`), `Report` calls `tracer.StartSpan` and defers `Finish` for every `md5.Sum`, `sha1.New` and similar call. The sampling decision (`AnnotationFor` → `samplingDecision`) and the event-local dedup come afterwards. `Report` has no process-level dedup (the tainted path has `taintedReportDedup`), so each sampled call re-emits the same finding with `ManualKeep`. Each orphan also briefly occupies one of the 2 store slots, which feeds F1. The cost is a full trace span per hash call, plus 59 allocations (with stack traces on), where one cheap dedup or sampling check would avoid all of it.
- Evidence: `TestReviewWeakReportWithoutSpanCreatesOrphanPerCall` gives repro.out.txt: `100 weak-hash calls at one call site -> 100 orphan spans` and `allocations per weak-hash call with no span in context: 59`. The duplicate `ManualKeep` events need the woven Finish hook, which plain tests lack. That part is static reasoning (report.go:51-108 has no `dedup.Set` use).
- Fix: Before creating an orphan span, run a process-level dedup check on (type, location or evidence) and the sampling decision. Rate-limit orphan creation. Reuse the `taintedReportDedup` pattern for `Report`.

### life-spans-F5: Annotation-store capacity check is a TOCTOU; concurrent first binds exceed MaxConcurrentRequests
- Severity: Medium
- Category: memory-bound
- Location: internal/spans/annotation.go:132-142,199-205,227-236; internal/spans/vulnerability.go:25-29
- Claim: `trimStore()` is evaluated outside `LoadOrCompute`/`LoadOrStore`, so N goroutines binding distinct roots at once all see spare capacity and all insert. The overshoot is bounded by the number of concurrent binders (each annotation is about 3.3 KiB of fixed arrays plus its event), and it self-corrects on later calls. Still, the documented admission bound is not a bound.
- Evidence: .omo/review/evidence/life-spans/zz_review_internal_test.go; `go test -count=1 -v -run TestReviewStoreCapacityTOCTOU ./internal/spans/` gives toctou.out.txt: `configured cap=2, max observed annotation store size=7`.
- Fix: Reserve capacity with an atomic counter (CAS increment before insert, decrement on delete or trim), or re-check `store.Size()` after insert and roll back.

### life-spans-F6: Real-tracer meta_struct path and lifecycle edges are untested
- Severity: Medium
- Category: test-gap
- Location: internal/spans/annotation_test.go, annotation_sampling_test.go, owner_internal_test.go (all use mocktracer); internal/spans/orchestrion.go:44-46
- Claim: With mocktracer, `SetMetaStruct` always returns false, so the production msgpack meta_struct branch is never exercised against a real tracer. No test covers default capacity 2 with mixed decisions, a bind or report after root Finish, a double Finish, or concurrent first binds. F1, F2, F3 and F5 all live in these gaps. Tests always force `MaxConcurrentRequests=64`.
- Evidence: the reproducers in the evidence dir are the missing tests; `configureSamplingTest` and `configureOwnerSpanTest` set 64.
- Fix: Add those tests, including a `-race` real-tracer test with a fake agent like F3's.

### life-spans-F7: A negative span annotation short-circuits owner fallback in selectTaintedAnnotation
- Severity: Low
- Category: false-negative
- Location: internal/spans/annotation.go:84-97; internal/vulnerability/tainted.go:111-114
- Claim: `ExistingForSpan` returns `found=true` for a `Sampled=false` annotation, for example a worker span sampled out by legacy `AnnotationFor`. `selectTaintedAnnotation` stops there and `TryCommitTainted` rejects it, so taint from another *active* owner is dropped instead of being reported on the owner's bound span. This is arguably consistent with "report on the sink span", but it is undocumented.
- Evidence: static reasoning only (NEEDS-REPRO).
- Fix: Return found only for `Sampled` annotations, or document that a sampled-out sink span vetoes foreign-owner reports.

### life-spans-F8: RequestTainted is never incremented; request.tainted telemetry always submits 0
- Severity: Low
- Category: quality
- Location: internal/spans/annotation.go:54-55,215-221; internal/spans/orchestrion.go:33
- Claim: The only write to `RequestTainted` is in a test (annotation_test.go:90). `Finished` submits `request.tainted=0` for every finished annotation, including negative and orphan ones.
- Evidence: grep for `RequestTainted` finds annotation.go:28,55,220 and annotation_test.go:90 only.
- Fix: Increment the counter from the request owner's tainted-value count at scope finish, or remove the metric and only submit it for sampled annotations.

## Checked and found correct
- Weak-key identity: `weak.Make(root)` equality is stable per object. The owner binding holds only a `weak.Pointer` to the span, and `ExistingForOwner` validates id, generation, not-closed, a live weak value and an unchanged slot. `bindOwnerSpan` handles concurrent scope Finish with a CAS plus a post-check rollback (read; the existing `TestOwnerSpanConcurrentBindAndFinish` covers it).
- Lock order: `Finished`, `Report` and `TryCommitTainted` take the annotation lock, then the span lock (`SetMetaStruct`, `SetTag`, `RecordStackTrace` → root `SetTag`). No path takes the span lock and then the annotation lock, because the prologue runs before any dd-trace-go lock in `Finish` (span.go:1060-1115). No deadlock.
- Orphan `ReportTainted` defers `Finished` and then `Finish` after `TryCommitTainted` unlocks. The legacy `Report` defer order unlocks before `span.Finish`.
- `TryCommitTainted`: all bounds are reserved before publication. The process source-byte CAS reservation is rolled back on panic or false. The staged source index is copied by value. The redaction upgrade re-redacts earlier parts. `SourceIndex` pointers target immutable `eventSourceIndexes` values. Per-event quota is `min(config.VulnerabilitiesPerRequest, 64)` (model/event.go:51).
- Payload: `BuildLimitedPayload` keeps ≤25,000 bytes via three fallback levels. The fallback drops sources and evidence, so nothing unredacted is emitted. After close, `ann.Event` is never mutated (`Report` and `TryCommitTainted` check closed under the lock), so handing `&ann.Event` to the deferred encoder is safe on the normal single-Finish path.
- The ManualKeep tag is set in the prologue before `rulesSampling.SampleTrace` and `s.finish`, so retention takes effect.
- 87ecf02 precedence: an existing span decision wins over the scope decision, and negative entries are released independently on Finish (tests reviewed). The store and threshold presize use the config values loaded in `config.init` before spans' package vars are initialized.
- `releaseDeadAnnotation` closes the annotation and releases its source bytes under `TryLock`, only for dead weak keys.

## Not covered / open questions
- Span-pool recycling (dd-trace-go opt-in `SpanPoolEnabled`) and weak-key reuse were not re-tested here; see life-weak-gc-F3.
- The F4 duplicate-event and ManualKeep volume was not measured in a woven build (heavy build, deferred on this shared machine).
- How often customers double-Finish a root in practice (the F3 precondition) is unknown.

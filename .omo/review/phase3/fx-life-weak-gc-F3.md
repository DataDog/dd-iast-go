# fx-life-weak-gc-F3: span-pool recycling makes a new root inherit a stale annotation

## Verdict per finding
- **life-weak-gc-F3: CONFIRMED** (adjusted severity **High**, reachable only when dd-trace-go's opt-in span pool is enabled). I reproduced it end to end in a woven build: an ordinary HTTP handler, the real tracer with `WithSpanPool(true)`, and the woven `StartSpanFromContext`, SQL-sink and `Span.Finish` hooks. The agent received request B's span carrying request A's SQL injection (bleed). In a second scenario, request B's own SQL injection was dropped entirely (false negative). One detail of the finder's claim needs correcting. Its sampled-bleed trigger, `AnnotationFor(old)` "from `vulnerability.Report` with a job ctx", is not reachable from woven code at HEAD: every `ReportWeakHash`/`ReportWeakCipher` call site passes a `nil` ctx (`iast/crypto/hash/orchestrion.yml:39,77,91,122,136`), so `Report` always takes the orphan-span path (`internal/vulnerability/report.go:45-49`). The reachable stale-entry creator is the woven `BindStartSpan` (`iast/net/http/http.go:21-26` -> `BindScope`), which I used. The core claim holds.

## Reproduction
My reproducer is `.omo/review/evidence/fx-life-weak-gc-F3/review_f3_pool_test.go`, placed in `iast/integration/testapp/` of the private copy:
`cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -count=1 -timeout 10m -run 'TestReviewF3WovenSpanPool' -v .` (log: `woven-go1266.log`, peak RSS about 380 MB)
- `control-no-late-span`: PASS. The recycled root gets its own event (`colB`), which rules out a harness artifact.
- `negative-after-request`: the handler starts `async.work` from the request ctx and finishes the root. After the response, a goroutine starts `late.async` from that ctx, then finishes it and the work span.
  `late goroutine: late.Root()==rootA:true ... scopeActive=false ... ExistingForSpan(rootA)=true sampled=false`
  `variant=negative-after-request requestsB=1 recycledRootA=true ... scopeActive=true`
  `agent span request-B-0: ... metrics[_dd.iast.enabled]=<nil> iastEvent=` / `orphan 'vulnerability' spans carrying request B's finding: 0`
  → `BUG: request B's own SQL injection is not attached to request B's span`. B's finding is lost outright: `ExistingForSpan` returns the unsampled stale annotation as found, `TryUseOpen` rejects it (`!a.Sampled`), and no orphan fallback runs (`internal/vulnerability/tainted.go:113-117`).
- `sampled-bleed`: the handler finishes its span early, then (with the scope still active) starts `late.db` from the ctx and runs a tainted `ExecContext`.
  `variant=sampled-bleed requestsB=1 recycledRootA=true ... vulnsOnArrival=1`
  `agent span request-B-0: ... iastEvent={"sources":[{"origin":"http.request.parameter","name":"colA","value":"aa_from_request_A"}],"vulnerabilities":[{"type":"SQL_INJECTION",...,"line":166,...}]}`
  → `BUG (cross-request bleed): agent received request B's span request-B-0 carrying request A's finding`.
- Finder's reproducer re-run (`finder-repro-go1266.log`): both variants FAIL, as reported.
- Go 1.27.0: the woven build fails on the pre-existing encoding/json v2 break (`dec.r undefined`, base-test-127-F1; log `woven-go1270-buildfail.log`), so I could not exercise it end to end. The mechanism does not depend on the Go version, and the finder's plain-test run on go1.27 also showed it.
- Harness note: with GOMAXPROCS(1), if the tracer worker releases rootA before the late span starts, the late span *is* rootA's recycled object, and its `Finish` deletes the stale key by accident. The async-work span keeps trace A open so this does not happen. Production has many Ps and per-P pools, so it does not rely on that accident.

## Reachability
- **Not default.** It needs `DD_TRACER_EXPERIMENTAL_SPAN_POOL_ENABLED=true` or `tracer.WithSpanPool(true)` (dd-trace-go v2.11.0-rc.1 `option.go:1657-1662`; `span_pool.go:17-42`; release after encoding at `tracer.go:901-912`). The flag is experimental but customer-settable, and neither README nor `01-design-intent.md` mentions the span pool or excludes it. This is not a documented limitation.
- **Triggers in ordinary code, once the pool is on:** (1) fire-and-forget work that calls `tracer.StartSpanFromContext(r.Context()/child ctx, ...)` after the request ended. This includes woven contrib spans such as DB calls from a goroutine. It leaves a `Sampled:false` entry, and the next request that reuses the root object silently loses all IAST findings. (2) Any span started from the request ctx after the request span finished while the IAST scope is still active (an early `span.Finish()`, or a tracing middleware nested inside the scope-opening handler) re-creates a Sampled entry, and the next request that reuses the object emits the earlier request's findings and sources. Each stale entry affects one later root, because the victim's own `Finished` deletes it. It recurs whenever the trigger recurs.
- A related path the finder did not mention: `NewOrphanTaintedSpan` uses `LoadOrStore(weak.Make(span))` on a freshly pooled span (`internal/spans/vulnerability.go:24-33`), so an orphan finding can also land in, or be rejected by, a stale entry. It has the same root cause.
- The dd-trace-go pool contract ("callers opting in must avoid inspecting the spans", `span_pool.go:15-16`) does not excuse this. The customer code above never inspects a finished span. IAST's own key identity is what goes stale.

## Adjusted severity
**High (unchanged).** It is a cross-request provenance bleed and a silent false negative on the supported SQLi path, which violates rule 4. It takes only one customer-settable tracer flag plus common async-span patterns, so it is not raised to Critical. Default configuration is unaffected.

## Root cause (file:line)
- `internal/spans/annotation.go:31`: the store is keyed only by `weak.Pointer[tracer.Span]`, which identifies the *object*, not the span. That identity is sound only if span objects are never reused.
- `internal/spans/annotation.go:190-197` (`BindScope`), plus `:128-139` (`AnnotationFor`), `:83-95` (`ExistingForSpan`), and `vulnerability.go:28-31`: these trust any entry found under the weak key with no identity check.
- `internal/spans/annotation.go:198-205` together with `orchestrion.go:28` (the F2 dependency): after the root's `Finished` has run, `BindScope` re-creates an entry on the finished root, and nothing removes it before the pool clears the object and reuses it. `owner.go:21` (`ownerSpanBinding.root`) has the same object-identity assumption.

## Minimal fix
Record the root's identity when the annotation is created (`root.Context().SpanID()`, plus the trace ID if cheap). `clear()` zeroes `spanID`, and `spanStart` assigns a fresh one on reuse. On every load (`BindScope`, `AnnotationFor`, `ExistingForSpan`, `TryUseExisting`, `NewOrphanTaintedSpan`, `Finished`, `ExistingForOwner`), compare it with the live root's ID. On a mismatch, treat the entry as absent: `CompareAndDelete`/replace it, close it, and release its source charge. Alternatively, weave a tracer-internal hook on `(*Span).clear` that deletes `weak.Make(s)` from the store, keeping it gated on a non-empty store (see F4). **Caution for F2:** a weak-key tombstone left at `Finished` *without* this ID check would make pool mode strictly worse, because every recycled root would hit a closed tombstone. The ID check should land with, or before, any F2 tombstone fix. Add the woven reproducer above as a regression test.

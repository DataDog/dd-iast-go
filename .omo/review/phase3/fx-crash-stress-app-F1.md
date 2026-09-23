# fx-crash-stress-app-F1: verification of crash-stress-app-F1

## Verdict per finding
- **crash-stress-app-F1: CONFIRMED.** Adjusted severity: **High**. The mechanism is real at HEAD 2e23b46. I reproduced it independently through a woven server that uses dd-trace-go `contrib/net/http` and the DEFAULT IAST configuration. The real impact is larger than the finder's scenario suggests: under realistic low concurrency (2 background clients), 100% of analyzed requests lose their SQL injection report.

## Reproduction
My reproducer is `.omo/review/evidence/fx-crash-stress-app-F1/annrepro_main.go`. It was built in the private copy of `iast/integration/testapp` after adding `github.com/DataDog/dd-trace-go/contrib/net/http/v2@v2.11.0-rc.1` from the offline module cache:
```
GOTOOLCHAIN=go1.26.6 GOFLAGS='-p=4 -mod=mod' GOPROXY=off go tool orchestrion go build -o annrepro ./cmd/annrepro   # peak RSS 452 MB
env -u DD_IAST_REQUEST_SAMPLING -u DD_IAST_MAX_CONCURRENT_REQUESTS -u DD_IAST_DEDUPLICATION_ENABLED ./annrepro deterministic
DD_IAST_DEDUPLICATION_ENABLED=false LOAD_CLIENTS={0,2,8} ./annrepro load
```
The server is `httptest.NewServer(ddhttp.WrapHandler(mux,...))`, so every request gets an `http.request` root span, the way an ordinary traced customer app does. `/vuln` passes `r.URL.Query().Get("q")` to `db.ExecContext`. `/slow` has no sink.

Deterministic run, all defaults (30% sampling, 2 permits, dedup on), from `annrepro_deterministic.out`:
```
BUG phase: holding 2 in-flight NON-analyzed requests (found after 2 slow requests); 0 analysis permits in use
  victims sent=28 analyzed(active && query tainted)=10 reported=0
  victim root spans by (_dd.iast.enabled, hasPayload): map[[0 false]:28]
  orphan "vulnerability" spans: empty=10 withPayload=0
RECOVERY phase (holders released, same sink site): analyzed victim id=33 -> [1 true] (enabled, hasPayload)
```
Two sampled-out, in-flight requests hold no permit, yet they silence 10 out of 10 analyzed requests. Each lost report also emits an empty `vulnerability` span. The recovery report comes from the same call site with dedup on, which rules out dedup as the cause, because dropped reports never reach `set.Add`.

Load run (sequential victims plus C background clients on a 50 ms endpoint; dedup off only so that repeated reports can be counted), from `annrepro_load.out`:
```
LOAD clients=0: victims=300 analyzed=89 reported=89 analyzedButEnabled0=0 orphanEmpty=0
LOAD clients=2: victims=300 analyzed=90 reported=0  analyzedButEnabled0=90 orphanEmpty=90
LOAD clients=8: victims=300 analyzed=0  reported=0
```
With 2 background clients, 0 of 90 analyzed victims are reported. At 8 clients the permits are saturated, which is the intended bound and not this bug. I also read the finder's `annslot.out`, and it agrees. I did not rerun it, since my reproducer supersedes it.

## Reachability
- It is reachable under default configuration with Go 1.26.6. The only preconditions are request root spans, which dd-trace-go's net/http and orchestrion integrations create for every request, and at least `MaxConcurrentRequests` (default 2) other span-bearing requests in flight. Any production server with concurrency of 3 or more meets them. Occupants can be sampled-out, capacity-dropped, or even analyzed requests. The cap counts spans, not analyses, and permits and slots are acquired independently. A request can therefore win a permit while the slots are held by requests without permits.
- I did not try Go 1.27.0, because the woven build fails there (base-test-127-F1). The logic is independent of the toolchain.
- It is not documented. The README (lines 94-116) and `01-design-intent.md` (line 65) describe 30% sampling and a limit of 2 concurrent analyses. Nothing says that non-analyzed requests consume analysis capacity or that analyzed requests can lose reports. It violates rule 4 (provenance: false negative on a supported SQLi path). The empty orphan spans also add trace noise.

## Adjusted severity
**High (unchanged).** It is a deterministic false negative on the core supported source-to-SQL path under default configuration and ordinary concurrency, and in practice it can disable reporting almost completely. There is no crash, leak, or race, so it is not Critical.

## Root cause (file:line, HEAD 2e23b46)
- `internal/spans/annotation.go:198-207` (`BindScope`): computes `active := scope.Active()` and stores `&Annotation{Sampled: active}` even when `active == false`, which consumes a slot for a non-analyzed root span.
- `internal/spans/annotation.go:227-235` (`trimStore`): caps the map at `config.MaxConcurrentRequests`, the same number as the permit count (`internal/taint/request/scope.go:95`). Live-span entries are removed only by `Finished` (`internal/spans/orchestrion.go:28`) or after GC (`annotation.go:240`), so live non-analyzed spans hold their slots.
- `internal/spans/annotation.go:206-208`: when there is no space, `ann == nil` sets the tag `_dd.iast.enabled=0` on an analyzed request's root.
- `internal/vulnerability/tainted.go:110-126` then finds no annotation for the span or owner and falls back to `spans.NewOrphanTaintedSpan()`.
- `internal/spans/vulnerability.go:24-26` starts the orphan span before `trimStore()`. The capacity check fails, so the function returns `(span, nil)`, and `tainted.go:63-67` finishes an empty span and drops the report.

## Minimal fix
1. In `BindScope`, do not store an annotation when `!active`. Set `root.SetTag(SpanTagEnabled, 0)` and return nil. This keeps map occupancy at or below the analyses actually holding permits. If nested-scope precedence needs a negative marker, use a separate, uncapped marker, such as a tag check on the root.
2. Alternatively, or in addition, reserve annotation capacity per permit: size the cap by `config.MaxConcurrentRequests` plus a separate orphan budget, and let an active scope always bind, since its permit already bounds it.
3. In `NewOrphanTaintedSpan`, call `trimStore()` before `StartSpan` so that a capacity failure does not emit an empty `vulnerability` span.
4. Add a regression test: hold 2 non-analyzed traced requests, then assert that an analyzed request's SQLi is reported (the shape of `annrepro deterministic`).

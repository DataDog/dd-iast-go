# fx-life-spans-F1: verification of life-spans-F1 (negative sampling decisions crowd out active requests)

## Verdict per finding

### life-spans-F1 — CONFIRMED
The claimed mechanism is real at HEAD 2e23b46, reproduces independently through three
surfaces (finder's test, my internal-API reproducer at shipped defaults, and my own woven
orchestrion build with a real net/http server + database/sql SQLi sink), and is reachable
from ordinary customer code under default configuration. One nuance the finder's report
understates: the finding is not always *fully* dropped — when a store slot frees before the
sink hit, the event is displaced onto an orphan span (still reported, but detached from the
request trace). Full loss occurs when the store stays saturated through the sink hit; at
defaults my woven 400-request run lost 79/117 admitted requests' request-span event and
6/117 (~5%) produced no finding anywhere. This does not change the verdict or severity.

## Reproduction

All in the private copy `/tmp/ddiast-review/wt/fx-life-spans-F1` (removed after evidence
capture), Go 1.26.6, `GOFLAGS=-p=4`.

1. Finder's reproducer (re-run by me):
   `GOTOOLCHAIN=go1.26.6 go test -count=1 -v -run TestReviewNegativeDecisionsCrowdOutActiveRequest ./internal/vulnerability/`
   (with `.omo/review/evidence/life-spans/zz_review_lifespans_test.go` in internal/vulnerability)
   Key output (evidence/fx-life-spans-F1/repro_combined.out.txt):
   `active request: scope.Active()=true decision=3 BindScope annotation nil=true`,
   `ReportTainted first=false second(dedup)=false`, `weak-sink annotation sampled=false`,
   two `finished span name="vulnerability" ... has_iast_json=false`, `BUG: ... orphan spans=2`.

2. My internal-API reproducer at shipped defaults (30% sampling, capacity 2), driving the
   exact woven call sequence (`httpbridge.Begin` = serverHandler prepend advice;
   `StartSpanFromContext` + `spans.BindScopeFromContext` = woven BindStartSpan;
   `httpbridge.Finish`), 3 concurrent requests/trial, real 30% sampler decisions, realistic
   in-flight handler duration:
   `GOTOOLCHAIN=go1.26.6 go test -count=1 -v -run TestFxLifeSpansF1DefaultConfigCrowdOutDropsTaintedFinding ./internal/vulnerability/`
   (test file: evidence/fx-life-spans-F1/zz_fx_life_spans_f1_repro_test.go; PASS = bug present)
   Key output (repro_combined.out.txt), crowded trial:
   `request 2: decision=3 active=true bindNil=true stored=false attemptedSink=true taintedReported=false weakKept=false`,
   `crowded trial emitted 2 orphan spans named "vulnerability"` (2 sink hits, deduplicated),
   `crowded-out active request span _dd.iast.enabled tag=0`.
   Note: with zero handler duration the crowd-out window is microseconds and 300 trials
   show nothing — the loss window scales with in-flight request duration, i.e. it is a
   production-realistic regime, not a synthetic one.

3. My woven build (most realistic surface): real `httptest` server, woven scope creation,
   woven span binding, `db.ExecContext` with a tainted query parameter, woven Finish.
   `cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -count=1 -run 'TestReviewFxF1' .`
   (test file: evidence/fx-life-spans-F1/zz_review_fx_f1_test.go; output:
   woven_repro.out.txt; peak build RSS 359 MB)
   Key output:
   `inflight_sampled_out=2 ... _dd.iast.enabled=0 request_span_has_SQLi_event=false orphan_spans=1 orphan_spans_with_event=0`
   `BUG: admitted (permit-holding) request with a tainted SQL sink reported NOTHING`
   `default config: requests=400 admitted(active scope)=117 reported_on_request_span=38 lost_on_request_span=79 orphan_spans_with_event=73`
   `BUG: 6 admitted requests with a tainted SQL sink produced no finding anywhere`

## Reachability
Default config, no env vars, Go 1.26.6: any woven HTTP service with ≥3 concurrent requests.
Default sampling is 30% (config.go:66), so 70% of requests store `Sampled=false`
annotations; `MaxConcurrentRequests` defaults to 2 (config.go:67). Any active request
whose bind happens while two sampled-out requests are in flight is denied an annotation
while still holding an analysis permit and paying full tracking cost. NOT a documented
limitation: README:116 describes the env var as "maximum number of requests that IAST
processes concurrently" (an active-analysis bound), and neither README nor
phase1/01-design-intent.md documents negative decisions consuming that budget. It breaks
product rule 4 (lost taint on a supported path — false negative SQLi/CMDi) and rule 2
(full analysis cost paid, results discarded).

## Adjusted severity
High (unchanged). False-negative vulnerability on a supported, default-config path,
reproduced end-to-end in a woven build; not Critical (no crash/race/leak/unbounded
growth; capacity remains bounded).

## Root cause
One root cause: `internal/spans/annotation.go:182-208` — since 87ecf02 ("retain negative
sampling decisions"), `BindScope` stores `&Annotation{Sampled: active}` (line 204) for
sampled-out/capacity-dropped scopes, while `trimStore` (annotation.go:227-236, line 235)
bounds the store by `config.MaxConcurrentRequests` (default 2), the *active-analysis*
bound. Consequences: `BindScope` returns nil and tags `_dd.iast.enabled=0` (lines
206-208); no owner binding exists, so `selectTaintedAnnotation`
(internal/vulnerability/tainted.go:62-68) falls to `NewOrphanTaintedSpan`
(internal/spans/vulnerability.go:23-27), which starts a span and then returns a nil
annotation (`!trimStore()`), so `ReportTainted` finishes an *empty* orphan span and
returns false — once per sink hit, deduplicated hits included. Weak findings drop at
internal/vulnerability/report.go:51-52 via `AnnotationForContext` → `nonSampledAnnotation`
(annotation.go:170-178). Not a duplicate of life-spans-F2/F3/F5 (different mechanisms);
life-spans-F4 (orphan span per weak call) amplifies it by occupying slots.

## Minimal fix
Do not count negative decisions against the active bound: give `Sampled=false` entries a
separate fixed cache (they carry no event payload and are cheap to recreate), or in
`trimStore`/`BindScope` evict a non-sampled entry (re-checking liveness) rather than
denying an annotation to a scope that holds an analysis permit. Additionally, in
`NewOrphanTaintedSpan` check capacity *before* `tracer.StartSpan` so a dropped finding
does not emit an empty trace span.

## Checked and found correct
- 87ecf02's stated goal (span-decision precedence, independent release of negative
  entries on Finish) is implemented as described; the regression is only the shared bound.
- Negative entries are released on woven `Finish` (`spans.Finished` → `LoadAndDelete`,
  orchestrion.go:28-31), so the starvation is transient per request, not a permanent
  self-disable (unlike a leaked permit).
- Woven wiring verified statically: every request creates a scope
  (iast/net/http/orchestrion.yml serverHandler prepend / Handler fallback) and binds via
  `BindStartSpan` (StartSpanFromContext wrap) or `BindScopeContext`, so sampled-out
  requests do reach `BindScope` in production; confirmed behaviorally by the woven run.

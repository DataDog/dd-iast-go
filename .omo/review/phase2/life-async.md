# life-async: tainted values and request owners across goroutines and after request end
Verdict: Memory safety and isolation hold end to end: late goroutines, globals, detached contexts and a sink racing owner Finish produced no panic, no data race, no report on a wrong span, no cross-request taint, and store counters back at zero. Attribution is wrong in three request-copy and context shapes, though. After `http.StripPrefix` or `Request.Clone`, `URL.Query()` taint is lost (High). A middleware-detached context creates a second scope that drops reports (Medium). A sink context carrying a finished request's scope vetoes a live request's taint (Medium).
Scope covered: Read `internal/taint/request/{scope,owner,lookup,lazy,http}.go`, `internal/taint/store/{owner,lookup,value,root,store}.go`, `internal/spans/{owner,annotation,tainted,orchestrion,vulnerability}.go`, `internal/vulnerability/tainted.go`, `internal/taint/{httpbridge,sqlbridge}/bridge.go`, `iast/database/sql/sql.go`, and `iast/net/{http,url}/orchestrion.yml`. Ran 7 woven end-to-end reproducers in the integration testapp (`GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -race`, peak RSS about 385 MB), with the lifecycle tests at `-count=10`.

## Findings
### life-async-F1: `URL.Query()` loses request taint after `http.StripPrefix` or `Request.Clone`
- Severity: High
- Category: false-negative
- Location: internal/taint/request/lazy.go:31-46; internal/taint/request/http.go:74-77
- Claim: `ManageURLQuery` attributes a `URL.Query()` result only through the `*url.URL` object bound by `EagerHTTP` (`LookupObject(urlObject, store.BindingURL, ...)`; `count != 1` returns the values unmanaged). `http.StripPrefix` and `Request.Clone` both forward a new `*url.URL` copy. The context still carries the active scope, and the copied `RawQuery` is still the tainted managed clone, but the copied URL has zero bindings. So `r.URL.Query().Get(...)` returns clean values. The parsed values are substrings of `RawQuery`, which exact-key lookup does not cover, so no other path re-taints them. A supported source (`URL.Query`) reaching a supported sink (SQL) behind the stdlib's standard sub-router middleware is silently missed. `FormValue` and headers on the same request are still reported because they are attributed through the context.
- Evidence: `.omo/review/evidence/life-async/lifeasync_review_test.go` (`TestReviewMiddlewareURLCopy`) and `lifeasync_review.go`. Command: see `evidence/life-async/README.txt` (`go tool orchestrion go test -race -run '^TestReview' ...` in `iast/integration/testapp`). Output in `final-race.out.txt`:
  - control: `urlBoundOwners=1 URL.Query tainted=true ... RESULT control WithContext: reported=2 of 2`
  - `http.StripPrefix`: `scopeActive=true urlBoundOwners=0 URL.Query tainted=false RawQuery tainted=true FormValue tainted=true ... reported=1 of 2`
  - `Request.Clone`: the same, `reported=1 of 2`
- Fix: When the URL object has no binding, attribute through the provenance of `u.RawQuery`. It is an exact managed source clone, so look up its single live owner (`VisitString` on `RawQuery`) and manage the map for that owner. Keep the multi-owner ambiguity drop. Add a woven test for `StripPrefix` and `Clone`.

### life-async-F2: A middleware-detached context makes a nested woven handler open a second scope, which drops reports
- Severity: Medium
- Category: false-negative
- Location: iast/net/http/orchestrion.yml:81-121 (application.http.Handler: `BeginContext` at 106, `EagerHTTP` at 111-118); internal/taint/request/scope.go:79-104; internal/taint/request/lazy.go:33-35; internal/vulnerability/tainted.go:45-47
- Claim: If middleware forwards `r.WithContext(ctx)` where `ctx` does not derive from the request context, the next application-root handler finds no scope. It makes a fresh, independent sampling decision, takes a second permit, and re-runs `EagerHTTP` on the same `*http.Request` fields. This causes three problems. (a) If the inner scope is not active (capacity-dropped, or sampled-out 70% of the time at defaults), the sink context carries that scope, and `ReportTainted` returns early. Values still tainted by the outer, active owner are then never reported. (b) If the inner scope is active, the shared `*url.URL` is bound to two owners, so `ManageURLQuery` treats it as ambiguous and drops `URL.Query()` taint. (c) One request consumes two of the default two permits.
- Evidence: `TestReviewMiddlewareDetachedContext` in the same files. Output in `final-race.out.txt`:
  - control: `reported=2 of 2`
  - permits free: `inner scope=true active=true decision=3 urlBoundOwners=2 queryTainted=false headerTainted=true ... reported=1 of 2`
  - one permit: `inner scope=true active=false decision=2 ... queryTainted=true headerTainted=true ... reported=0 of 2`
  The sampled-out variant follows from the same line (tainted.go:45 rejects `Decision() != DecisionActive`); it was not run, to keep the test deterministic.
- Fix: When the request already carries an outer-owned source (for example, `RequestURI` is tainted by a live owner), let the fallback handler entry reuse that owner instead of opening a new scope. Otherwise, make the `ReportTainted` context-scope veto apply only when the snapshot's owners include that scope's own owner. At minimum, document that handlers must receive a context derived from the request.

### life-async-F3: A sink context that carries a finished request's scope vetoes taint from a live request
- Severity: Medium
- Category: false-negative
- Location: internal/vulnerability/tainted.go:45-47
- Claim: `ReportTainted` returns false whenever the sink context holds a scope that is not active. The check ignores which owner the evidence belongs to. Take a long-lived worker started by request A with the idiomatic `context.WithoutCancel(r.Context())`, or started lazily by the first request. After A ends, the worker receives a value from live request B and runs a query. The report is dropped even though the evidence is valid and B's span is resolvable through `ExistingForOwner`. The same value sent through `context.Background()` is reported on B's span, so the outcome depends on an unrelated stale context.
- Evidence: `TestReviewWorkerWithFinishedRequestContext`. Output: `worker: A-scope active=false valueTainted=true` / `evidence="SELECT request_b_worker FROM t -- bg"` (the background sink only) / `RESULT sink with finished-A ctx reported=false; same value via background ctx reported=true`.
- Fix: Treat a finished (or foreign) context scope like a missing one. Skip only the context-span candidate and continue with owner-based selection. If sampled-out-context semantics are intended, restrict the veto to scopes whose owner contributed to the snapshot.

### life-async-F4: Reports made after the root span finishes but before owner Finish become orphan traces
- Severity: Low
- Category: provenance
- Location: internal/vulnerability/tainted.go:110-126; internal/spans/owner.go:76; internal/spans/annotation.go:93
- Claim: The request's root span is often finished before the woven `serverHandler.ServeHTTP` deferred scope `Finish`. Between the two, a goroutine sink still sees live taint. Both span candidates are rejected as `Closed()`, so every such report creates a new ManualKeep `vulnerability` orphan span, detached from the request trace. Each orphan also briefly takes an annotation-map slot. No report went to a wrong request. With dedup enabled (the default), repeated orphans are mostly suppressed by hash. But if the first occurrence lands in this window, the finding is recorded on an orphan instead of the request.
- Evidence: `TestReviewConcurrentOwnerEndVsSink` (24 concurrent requests, each with a goroutine that keeps sinking and propagating while the request ends; dedup off). Output in `concurrent-race-x10.out.txt`: 10 runs, `orphanSpans` 27-191 per run, `foreignSources=0` every run, no race.
- Fix: When a snapshot owner is still live but its bound annotation is closed, drop the report (the request is ending) rather than open an orphan. Alternatively, document the behavior and count it in telemetry.

## Checked and found correct
- Late goroutine after request end (`TestReviewLateGoroutineAfterRequestEnd`): tainted strings, `ReviewDerive` (concat, `ToUpper`, Builder, `Sprintf`) and concat outputs are all untainted once the woven scope finishes. SQL sinks through the request context, `context.WithoutCancel`, and `context.Background()` report nothing. `ProcessCharged=0 ProcessValues=0`, `ActiveStore()==nil`. Reason: `Owner.Finish` marks finishing before `lifecycleMu.Lock` (store/owner.go:162-166), and lookups require `stateActive` (store/lookup.go:152).
- Globals across requests (`TestReviewGlobalAcrossRequests`): a global and its derivation from A are untainted and unreported in B, which reuses A's permit and owner slot. B reports exactly one finding with only B's source. A clean string that reused A's freed source address (`hits=1 tainted=0`) stayed clean. Stale index slots are rejected by `ownerGen`, state, and root generation (store/value.go:231-243; lookup.go:152-165).
- Late lazy sources during the next request (`TestReviewLateLazySourcesDuringNextRequest`, x3): `URL.Query`, `FormValue`, `Header.Get`, and `Cookie` on finished request A's `*http.Request`, called while B is live on the reused slot, are all clean, and neither span gets a report. The context scope has a zeroed analysis (scope.go:214-216), and bindings reset at Finish (store/owner.go:214).
- Owner end racing the sink, with propagation (`-race -count=10`): no data race, no panic, and 0 foreign sources on any request span across roughly 2,200 request-span findings. Owner IDs are process-unique, and `ExistingForOwner` checks id and generation (spans/owner.go:71-88). `bindOwnerSpan` undoes a CAS that raced Finish (owner.go:61-64). `copySources` revalidates under `sourceMu` (request/lookup.go:135-161).
- The snapshot holds ordinary GC strings, so using evidence after anchor release is memory-safe. `Analysis` handles are generation-captured, so a stale copy cannot finish or read a reused slot (request/owner.go:107-109,259-262).

## Not covered / open questions
- store-stress-F1 (torn `alive()` during slot reuse) can in principle be reached by a late goroutine's writer or binding operation. I did not reproduce it end to end, because the window is nanoseconds wide. See that report.
- Go 1.27.0 was not run (woven builds fail there per hooks-compile-matrix). HTTP/2 and hijacked connections were not exercised. Span-pool recycling and post-Finish span resurrection are covered by life-weak-gc-F2/F3.

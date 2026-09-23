# fx-life-owner-scope-F1: Finished context silently disables later requests

Verdict: CONFIRMED — `begin` reuses any context-embedded scope with no liveness check, so a retained finished request context permanently suppresses request-source taint for every later entry built on it, while admission capacity stays free.

Scope covered: `internal/taint/request/scope.go` (`begin`, `BeginServerContext`, `BeginContext`, `FinishContext`, `Finish`, `Active`, `Analysis`, `EnabledTagValue`), `internal/taint/request/{http,owner}.go`, `internal/taint/httpbridge/bridge.go`, `iast/net/http/orchestrion.yml` (server + handler advice), phase-1 architecture map and design-intent doc, README (no matching documented limitation).

## Findings

### fx-life-owner-scope-F1 (= phase-2 life-owner-scope-F1; single finding, no duplicates)
- Verdict: CONFIRMED
- Original severity: High | Adjusted severity: High
- Location: internal/taint/request/scope.go:83-84 (root cause), with scope.go:209-222 (`Finish`) and `iast/net/http/orchestrion.yml:30-45,95-110` (advice gates all source work on `created`).

## Reproduction (commands + key output lines)

1. Finder's reproducer, re-run in my private copy (evidence: `fx-finder-repro-go1.26.6-output.txt`, test in `finder_lifecycle_review_test.go`):
   `cd /tmp/ddiast-review/wt/fx-life-owner-scope-F1 && GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test -race -run '^TestReviewServerScopeReacquiredWhenContextContainsFinishedScope$' -count=1 -timeout 2m ./internal/taint/request`
   → `lifecycle_review_test.go:38: new request: created=false active=false; expected a fresh live scope`
2. My independent internal-API reproducer (evidence: `fx_scope_reuse_test.go`, output `fx-scope-reuse-internal-output.txt`), driving the exact callbacks the woven `serverHandler.ServeHTTP` advice calls — `httpbridge.Begin`/`httpbridge.Finish` plus `EagerHTTP`. After request 1 finishes, a fresh-context control reacquires the released permit, but 3 consecutive entries on the retained context each get `created=false`, an inactive scope, `_dd.iast.enabled=0`, and no analysis for `EagerHTTP`. Passes (buggy state asserted) on go1.26.6 AND go1.27.0 (`fx-scope-reuse-go1.27.0-output.txt`).
3. My woven end-to-end reproducer through a real `net/http` server (evidence: `fxwoven/fxwoven_test.go`, output `fxwoven-output.txt`; peak RSS 348 MB, build+test 252 s):
   `GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 DD_IAST_REQUEST_SAMPLING=100 go tool orchestrion go test -run '^TestFXWovenRedispatchOfStoredRequestLosesSourceTaint$' -count=1 ./fxwoven`
   First real request through the woven server entry: HTTP 200 (URI tainted by `EagerHTTP`). Re-dispatching the stored `*http.Request` (its context still holds the finished scope) to a woven handler: `fxwoven_test.go:55: re-dispatched request: status 417` — the `application.http.Handler` advice reused the finished scope, skipped `EagerHTTP`, and the request URI carries no live taint. Control fresh request: 200.

## Reachability
- Ordinary sequential HTTP requests are NOT affected: `net/http` derives a fresh `r.Context()` per request, so the server advice never sees a finished scope.
- Trigger: any customer code that retains a request context (or a stored `*http.Request`) and later enters a woven boundary with it — re-dispatching a stored request to a handler, retry/AB handler dispatch, async handler execution after the outer entry finished. This is legal Go and not forbidden by `net/http`; every customer `func(http.ResponseWriter, *http.Request)` is woven by the fallback advice, so the stale scope is honored wherever the request travels. No non-default configuration is needed (default Enabled=true, sampling 30% makes 70% of retained scopes sampled-out — those reuse paths are suppressed identically, since a non-active decision is also never re-evaluated).
- NOT a documented limitation: README "Propagation coverage"/"Sink coverage" and `phase1/01-design-intent.md` say nothing about reusing finished contexts; `Decision`'s doc comment ("callers must use Scope.Active") does not sanction reuse of a dead scope.
- Violates product rule 4 (accurate provenance; no lost taint on supported paths): the false negative is silent (no log/telemetry), persists for the lifetime of the retained context, and cannot recover — a permanent IAST self-disable for all requests sharing that parent context.

## Adjusted severity
High (unchanged). Justification: silent, permanent false-negative on a supported path, matching the scale's "wrong provenance on a SUPPORTED path" and "permanent IAST self-disable"; not Critical because it needs context/request retention rather than ordinary sequential requests, and it cannot crash, leak, or slow the host.

## Root cause
`internal/taint/request/scope.go:83-84`:
```go
if existing := FromContext(ctx); existing != nil {
    return ctx, existing, false
}
```
`Finish` (scope.go:209-222) empties `s.analysis` but leaves the scope in the context and leaves `decision == DecisionActive`; `begin` then trusts the stale scope forever and the woven advice's `if created` gate (orchestrion.yml) skips `EagerHTTP` and keeps the stale request context, so no source is ever tainted for those entries.

## Minimal fix
Track completion on the scope and stop reusing dead ones: add a `finished bool` field to `Scope` set under `s.mu` in `Finish`, and in `begin` reuse the existing scope only when it has not finished:
```go
if existing := FromContext(ctx); existing != nil && !existing.Finished() {
    return ctx, existing, false
}
```
Falling through creates a fresh scope whose `context.WithValue` shadows the stale one, restoring per-entry sampling/admission while keeping nested active-scope reuse (the intended design) intact. Nested handlers of a live request are unaffected because their scope has not finished.

## Checked and found correct
- Fresh-context control reacquires the released one-request permit after a finish (capacity bookkeeping is sound; the bug is purely the stale-reuse branch).
- Nested active reuse and ordinary first/finish lifecycle behave as designed (control paths in all three reproducers).
- Behavior identical on go1.26.6 and go1.27.0.

## Not covered / open questions
- The woven reproducer proves loss of eager source taint end-to-end, not a downstream sink report (no vulnerability is emitted either way once sources are lost).
- Whether any internal framework callers intentionally rely on finished-scope reuse was not audited.

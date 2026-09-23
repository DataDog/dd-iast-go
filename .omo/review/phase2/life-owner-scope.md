# life-owner-scope: Request owner and scope lifecycle
Verdict: Normal owner teardown and generation reuse are guarded, but a retained finished context can disable analysis for later requests, and concurrent callers can observe incomplete scope cleanup.
Scope covered: `internal/taint/request/{owner,scope,lookup,http}.go`, `internal/taint/scopebridge/bridge.go`, `internal/taint/store/{owner,lookup,binding}.go`, `internal/spans/{owner,annotation}.go`, `iast/net/http/orchestrion.yml`, and corresponding request lifecycle tests.

## Findings

### life-owner-scope-F1: Finished context silently disables later requests
- Severity: High
- Category: false-negative
- Location: internal/taint/request/scope.go:82-85
- Claim: `begin` unconditionally reuses any scope found in its input context, including one already finished. A later HTTP server request or handler whose parent context retains an earlier request's scope gets `created=false` and an inactive analysis. The woven entry advice consequently skips `EagerHTTP`, so no request sources are tainted. If that parent context is reused for subsequent requests, IAST stays disabled for all of them even though admission capacity is free. This is conditional on reusing a prior request context, not ordinary sequential HTTP requests with fresh contexts.
- Evidence: `.omo/review/evidence/life-owner-scope/lifecycle_review_test.go` (`TestReviewServerScopeReacquiredWhenContextContainsFinishedScope`) and `.omo/review/evidence/life-owner-scope/lifecycle-review-output.txt`. With the test copied to `internal/taint/request/lifecycle_review_test.go` in the private copy, run `cd /tmp/ddiast-review/wt/life-owner-scope && GOTOOLCHAIN=go1.26.6 go test -race -run '^TestReviewServerScopeReacquiredWhenContextContainsFinishedScope$' -count=1 -timeout 2m ./internal/taint/request` (captured combined run used `-run '^TestReview'`). Output: `new request: created=false active=false; expected a fresh live scope`. A fresh-context control successfully reacquired the released one-request permit.
- Fix: Track whether a scope has finished independently of its sampling decision; reuse only unfinished scopes, and make a fresh decision/analysis when a new entry receives a context containing a finished scope. Keep nested active and sampled-out scope reuse intact.

### life-owner-scope-F2: Second concurrent Finish returns before external cleanup
- Severity: Medium
- Category: race
- Location: internal/taint/request/scope.go:210-223
- Claim: `Scope.Finish` clears `s.analysis` and releases `s.mu` before `analysis.Finish` and `scopebridge.Finish` complete. A second concurrent `Scope.Finish` observes the zero analysis and returns immediately, while the first call can still be releasing owner resources or executing the span-binding cleanup callback. This makes the advertised synchronous teardown guarantee false for a caller that races another finish; the first caller eventually completes cleanup.
- Evidence: `.omo/review/evidence/life-owner-scope/lifecycle_review_test.go` (`TestReviewConcurrentScopeFinishWaitsForExternalCleanup`) and `.omo/review/evidence/life-owner-scope/lifecycle-review-output.txt`. With the test copied to the private request package, run `cd /tmp/ddiast-review/wt/life-owner-scope && GOTOOLCHAIN=go1.26.6 go test -race -run '^TestReviewConcurrentScopeFinishWaitsForExternalCleanup$' -count=1 -timeout 2m ./internal/taint/request` (captured combined run used `-run '^TestReview'`). Output: `second Scope.Finish returned before scopebridge.Finish completed`.
- Fix: Serialize concurrent finish callers through completion of both the analysis and bridge callback, without holding a lock used by their teardown paths; preserve exactly-once cleanup.

## Checked and found correct
- `Manager.Acquire` reserves one permit before acquiring a store owner, returns it on failed store acquisition, and publishes the directory only after assigning the owner identity; existing permit/capacity tests passed with `-race`.
- `Analysis.Finish` deactivates the captured generation, removes the owner directory entry, resets the source table, finishes the store owner and only then releases its permit. A stale handle cannot finish a reused permit; existing `TestManagerPermitAndFinish` and `TestOwnerDirectoryRejectsFinishedGeneration` passed with `-race`.
- `sourceMu` keeps source publication and reset from interleaving; `store.Owner.Finish` excludes in-flight writes with its lifecycle lock and drops anchors and bindings. Existing `TestAnalysisSourceWritesRaceFinish` passed with `-race`.
- Nested active handler entry reuses an existing scope without an extra permit, and an ordinary first/second finish is idempotent; `TestServerContextEntryAndNestedFinish` and `TestBeginActiveAndFinish` passed with `-race`.
- `scopebridge.Finish` supplies the captured owner ID and generation; `spans.finishOwnerSpan` compares both before removing a binding, so late cleanup cannot delete a newer owner's binding.

## Not covered / open questions
- The stale-context reproducer exercises the real `BeginServerContext` entry API rather than a woven HTTP server. It proves inactive analysis and the entry advice's `created=false` branch, but not a full sink report.
- No long-running fuzzing, whole-module weaving, or saturation benchmark was run. This review focused on owner/scope lifecycle and bounded, deterministic race tests.

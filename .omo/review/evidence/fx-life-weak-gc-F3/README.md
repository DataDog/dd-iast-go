# fx-life-weak-gc-F3 evidence

- `review_f3_pool_test.go`: my independent woven reproducer (package testapp_test). Drop it into `iast/integration/testapp/` in a private copy.
  Command: `cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -count=1 -timeout 10m -run 'TestReviewF3WovenSpanPool' -v .`
  Real tracer with `tracer.WithSpanPool(true)`, an httptest agent that decodes v0.4 msgpack payloads, and woven `serverHandler.ServeHTTP`, `tracer.StartSpanFromContext` (-> `BindStartSpan`), `database/sql` sink and `Span.Finish` hooks. Uses GOMAXPROCS(1) so that the per-P sync.Pool deterministically hands request A's root object to request B, and `config.MaxConcurrentRequests=2` (the shipped default).
  - `control-no-late-span`: PASS. The recycled root with no stale entry is analyzed normally.
  - `negative-after-request`: FAIL. A span started from request A's context after A ended leaves a `Sampled:false` entry on A's root. Request B reuses that object, and B's own SQLi is lost: there is no event on B's span and no orphan span.
  - `sampled-bleed`: FAIL. Request A's span finishes before the handler returns. A later child span plus an SQLi re-create a Sampled entry on A's root. Request B inherits it, and the agent receives B's span carrying A's finding (source `colA=aa_from_request_A`).
- `woven-go1266.log`: captured output of the final run.
- `woven-go1270-buildfail.log`: the go1.27.0 woven build fails on the pre-existing encoding/json v2 compile break (base-test-127-F1), which is unrelated to this finding.
- `finder-repro-go1266.log`: the finder's `review_pool_internal_test.go`, re-run in my private copy. Both variants FAIL, as reported.

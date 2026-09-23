# life-weak-gc evidence

Reproducers are internal tests of package `internal/spans`. They were run in a private copy (`/tmp/ddiast-review/wt/life-weak-gc`, since deleted) with both files dropped into `internal/spans/`.

Commands (repo root of a copy):

    cp review_gc_internal_test.go review_pool_internal_test.go internal/spans/
    GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -count=1 -timeout 12m -run 'TestReview' -v ./internal/spans/        # review-run.log (before pool test existed)
    GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -count=1 -timeout 5m  -run 'TestReviewSpanPool' -v ./internal/spans/  # review-pool.log
    GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -race -count=1 -timeout 12m -run 'TestReviewGCLifecycle|TestReviewContextOnly|TestReviewAbandoned|TestOwnerSpan' -v ./internal/spans/  # review-race.log
    GOFLAGS=-p=4 go test -count=1 -timeout 12m -run 'TestReview' -v ./internal/spans/   # go1.27.0 default, review-run-go127.log

A test that FAILs with a `BUG:` line reproduces a defect. A test that PASSes is a correctness check, or a measurement that only logs numbers.

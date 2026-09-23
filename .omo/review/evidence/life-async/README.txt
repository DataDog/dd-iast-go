Reproducers for life-async. Copy lifeasync_review.go and lifeasync_review_test.go into
iast/integration/testapp/ of a private copy, then:
  cd iast/integration/testapp
  GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -race -run '^TestReview' -count=1 -v -timeout 15m .
final-race.out.txt           : one run of all tests (expected FAILs = findings F1-F3)
concurrent-race-x10.out.txt  : -count=10 of the lifecycle/concurrency tests (all pass, no race)
late-lazy-x3.out.txt         : -count=3 of TestReviewLateLazySourcesDuringNextRequest
Peak RSS of the woven -race test build: ~385 MB.

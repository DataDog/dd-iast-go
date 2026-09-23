Reproducers for life-spans (HEAD 2e23b46), run in a private copy with GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4.
Place zz_review_lifespans_test.go in internal/vulnerability/ and zz_review_internal_test.go in internal/spans/.

F1/F2/F4: go test -count=1 -v -run 'TestReview(NegativeDecisions|LateBind|WeakReport)' ./internal/vulnerability/   -> repro.out.txt
F3 (race): go test -race -count=1 -v -run TestReviewDoubleFinishSetsMetaStructOnFinishedSpan ./internal/vulnerability/ -> race.out.txt (18 DATA RACE reports; real tracer + fake agent advertising span_meta_structs)
F5: go test -count=1 -v -run TestReviewStoreCapacityTOCTOU ./internal/spans/ -> toctou.out.txt
Note: the woven Span.Finish prologue is simulated by calling spans.Finished(span) right before span.Finish(), as the repository's own tests do.

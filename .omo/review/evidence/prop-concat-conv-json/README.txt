Reproducers for node prop-concat-conv-json (HEAD 2e23b46, GOTOOLCHAIN=go1.26.6).
Place each file at its package path inside a private rsync copy of the repo:
  zz_review_concat_conv_json_test.go -> internal/taint/propagation/
  zz_review_alloc_test.go            -> iast/propagation/
  zz_review_woven_test.go            -> zzreview/ (new root-module package, woven by orchestrion)
Commands:
  go test -count=1 -run TestReview -v ./internal/taint/propagation/ ./iast/propagation/   -> unit_reproducers.out
  go test -count=1 -run TestReviewWovenAllocs -v ./zzreview/                              -> unwoven baseline: 0/0/0 allocs
  go tool orchestrion go test -count=1 -run TestReviewWovenAllocs -v ./zzreview/          -> woven_allocs.out (1/1/0 allocs)
  go build -gcflags=-m=2 ./internal/taint/propagation/                                    -> escape_analysis.out
Trial fix (not in evidence files): replacing copy(inputs[:n], elements[:n]) in string_exact.go:56 with an index loop
made Concat operands non-escaping (woven Concat2("p", string(b)) dropped from 1 to 0 allocs); a hit-path clone in
conversion.go removed the heap leak of `result` but the generic wrapper iast/propagation.BytesToString (inline cost 131)
still returns string(value) from a non-inlined function, so the extra allocation remained.

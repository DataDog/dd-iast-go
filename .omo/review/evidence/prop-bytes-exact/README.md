# prop-bytes-exact evidence

Target: HEAD 2e23b4614320defd0d32177a69888dcab73f4d11.
All commands were run in the private copy; production files were not modified.

## Reproduce

Recreate the removed private copy and install the two preserved test files:

```sh
REPO=/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go
WT=/tmp/ddiast-review/wt/prop-bytes-exact
EVIDENCE="$REPO/.omo/review/evidence/prop-bytes-exact"
mkdir -p /tmp/ddiast-review/wt
rsync -a --exclude .git --exclude .omo "$REPO/" "$WT/"
cp "$EVIDENCE/zz_review_bytes_alias_test.go" "$WT/internal/taint/propagation/"
cp "$EVIDENCE/zz_review_bytes_woven_test.go" "$WT/iast/propagation/"
cd "$WT"
GOMAXPROCS=2 GOTOOLCHAIN=go1.26.6 go test -p=2 -count=1 -timeout=3m -run '^TestReview' -v ./internal/taint/propagation
GOMAXPROCS=2 GOTOOLCHAIN=go1.27.0 go test -p=2 -count=1 -timeout=3m -run '^TestReview' -v ./internal/taint/propagation
GOMAXPROCS=2 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -p=2 -count=1 -timeout=4m -run '^TestReviewWoven' -v ./iast/propagation
```

The regression tests assert correct behavior and therefore exit 1 on the
reviewed implementation. They are not expected-failure tests or weakened
assertions. The woven test requires built.WithOrchestrion and has a positive
in-length window control, so a missing instrumentation pass cannot silently
produce a false reproduction.

The internal test uses the existing beginScope, acquireOwner, taintBytes,
lookupByteRanges, and lookupRanges helpers from the original package tests.
The preserved woven test contains its own setup. Run it only with Orchestrion.

## Files

- baseline-go1.26.6.txt: complete existing propagation and store suites, before
  the new tests were added to the build. Exit 0.
- repro-go1.26.6.txt and repro-go1.27.0.txt: four reslicing failures, plus
  passing in-length, fresh-allocation, conversion, lifecycle, and mutation
  controls. Exact ranges, source ID, and secure marks are asserted.
- race-go1.26.6.txt: existing exact-byte tests and new passing controls with
  the race detector. Exit 0.
- zz_review_bytes_alias_test.go: copy to internal/taint/propagation/.
- zz_review_bytes_woven_test.go: copy to iast/propagation/.

The Buffer alias case is a characterization of README.md:43-46, not a separate
finding. It distinguishes store-root mutation from mutation through a later
bytes.Buffer alias. The direct store-mutation controls explicitly call
PublishBytesMutation; they do not claim that arbitrary copy/index operations
are instrumented.

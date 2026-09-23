# Replaying store-memory-bounds

Target: `2e23b4614320defd0d32177a69888dcab73f4d11`.
Measured with `go version go1.26.6 darwin/arm64` on September 23, 2026.
All commands completed with exit code 0. Tests assert reproduction of the
defects, so a passing reproducer means the defect was observed.

The main checkout was read-only except for this node's review deliverables.
The private directory contained an earlier saturation harness on arrival;
production sources were compared with the main checkout using `rsync -ain`
before running it. That inspected harness is preserved along with the new tests.
The only production-code change in the private copy was the scheduling-only
patch described below.

## Setup

Recreate a private copy, never run these tests in the main checkout:

```sh
R=/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go
E="$R/.omo/review/evidence/store-memory-bounds"
W=/tmp/ddiast-review/wt/store-memory-bounds
test ! -e "$W" || exit 1
mkdir -p "$W"
rsync -a --exclude .git --exclude .omo "$R/" "$W/"
rsync -a "$E/repro/" "$W/"
cd "$W"
patch -p1 < "$E/annotation-schedule.patch"
export GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4
export DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64
export DD_IAST_MAX_RANGE_COUNT=64 DD_IAST_VULNERABILITIES_PER_REQUEST=64
export DD_IAST_TRUNCATION_MAX_VALUE=250 DD_IAST_REDACTION_ENABLED=true
```

The patch pauses `AnnotationFor` between the real `trimStore` capacity read
and the real `LoadOrCompute`. It does not alter a comparison, result, map
operation, sampling decision, or limit. The test subscribes to all callers'
arrival using channels, releases them together, and joins them. This forces
one legal scheduling interleaving without sleeps or probabilistic retries.
The patch is inactive unless the admission test installs its callback.

## Run one command at a time

```sh
timeout 900 go test -count=1 -timeout 12m -v \
  -run '^(TestBounds|TestReviewStoreSaturation|TestReviewManagerSourcesSaturation)' \
  ./internal/taint/store ./internal/taint/request ./internal/spans ./internal/vulnerability/dedup
timeout 900 go test -count=1 -timeout 12m ./internal/taint/ranges
timeout 900 go test -race -count=1 -timeout 12m -v \
  -run '^TestBoundsAnnotationAdmission$' ./internal/spans
```

`timeout` is installed on the review workstation. The Go `-timeout` also bounds
each test process. `GOFLAGS=-p=4` limits build parallelism.

Individual proofs:

- F1: `TestBoundsRetainedAnchors`, in `repro/internal/taint/store/zz_review_anchor_test.go`.
  Uses real `bytes.Reader`, `bytes.Buffer`, `request.BindReader`, and
  `iast/propagation.BufferWriteString`. Output: `01-store-and-anchors.txt`.
- F2: `TestBoundsAnnotationAdmission`, in
  `repro/internal/spans/zz_review_annotation_admission_test.go`.
  Requires `annotation-schedule.patch`. Outputs: `03-annotation-admission.txt`
  and `04-ranges-and-race.txt`.
- F3: `TestBoundsEventEvidenceRetention`, in
  `repro/internal/taint/store/zz_review_event_retention_test.go`.
  Uses request source publication, the real join wrapper, evidence collection,
  `AnalyzeSQL`, `BuildWithSensitive`, span-map admission, and transactional event
  commit. Output: `06-sql-evidence.txt`. Unique hashes represent distinct finding
  locations; stack capture and a live SQL database are not part of this test.

`heapInuse` is in the preserved `zz_memory_bounds_review_test.go`; the other
packages have their own GC/read helper. Measurements are after `runtime.GC`;
the external-package helper also calls `debug.FreeOSMemory`. Tests do not
retain the adversarial reader/buffer after their noinline constructor returns.
Untracked controls and owner finish demonstrate that IAST is the retaining
reference. `runtime.KeepAlive` prevents collecting the store itself.

The logs include their exact original commands. `02-event-storage-exploration.txt`
includes an earlier 64-KiB collector-only experiment that did not run SQL
analysis. It is not the final SQL-path proof. The final evidence source and
`06-sql-evidence.txt` use the actual 32-KiB SQL analyzer limit and default
redaction. The source-budget, layout, and dedup results in log 02 remain valid.
Original commands were run at their respective stages of harness construction;
the combined command above is the replay command for the final source set.

After replay, preserve any desired output and remove only this private copy:

```sh
cd "$R"
rm -rf /tmp/ddiast-review/wt/store-memory-bounds
```

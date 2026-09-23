# Evidence: fx-store-memory-bounds-F1 (verification of store-memory-bounds-F1)

Target HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`, go1.26.6 darwin/arm64.

## Files produced by this node's own reproducers

- `zz_fx_anchor_repro_test.go` — independent reproducer written from scratch
  (private copy `internal/taint/store/`). Three subtests:
  `TestFxAnchorRetention/reader` (request.BindReader == the EagerHTTP advice
  body, request/http.go:75-76), `TestFxAnchorRetention/buffer`
  (wrappers.BufferWriteString == the injected bytes.Buffer.WriteString advice,
  iast/propagation/writer.go:107, orchestrion.yml:1281-1307), and
  `TestFxAnchorWovenSurface` (EagerHTTP body binding + woven io.LimitReader
  stdlib-body advice, iast/io/orchestrion.yml:12-27, with the LimitedReader
  binding asserted via store.LookupObjectValue).
- `fx-anchor-plain.txt` — output of:
  `cd /tmp/ddiast-review/wt/fx-store-memory-bounds-F1 && env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 DD_IAST_MAX_RANGE_COUNT=64 timeout 900 go test -count=1 -timeout 10m -v -run '^TestFxAnchorRetention$' ./internal/taint/store`
  Key lines: reader `delta=114925568 incrementalCharge=0`, finish
  `released=100663296`; buffer `delta=100663296 incrementalCharge=64`, finish
  `released=100663296`. Control (build-and-drop without binding) drift=0.
- `fx-woven-build.txt` — output of the woven build:
  `cd /tmp/ddiast-review/wt/fx-store-memory-bounds-F1 && env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 DD_IAST_MAX_RANGE_COUNT=64 timeout 1500 /usr/bin/time -l go tool orchestrion go test -count=1 -timeout 20m -v -run '^TestFxAnchorWovenSurface$' ./internal/taint/store`
  Key lines: `bodyBound=true limitedReaderBound=1 retained=117399552
  incrementalCharge=0`, `woven finish: heap=16736256 released=100663296
  charge=0`, peak woven-build RSS `351338496` bytes (well under 4 GB), 250s.
- `fx-woven-surface-plain.txt` — same subtest under plain `go test`:
  `limitedReaderBound=0` (io.LimitReader join point inactive without
  orchestrion), confirming the woven build is what activates the join point.
- `fx-anchor-finder.txt` — the finder's `TestBoundsRetainedAnchors` re-run in
  this node's private copy; identical numbers to `01-store-and-anchors.txt`.

## Pre-existing files from an earlier incarnation of this node (consistent)

- `01-independent-reproduction.txt` + `repro/` — woven reproducer through the
  production `request.EagerHTTP` callback and a woven `bytes.Buffer.WriteString`
  call site in the test-app package; 96 MiB retained with charge_delta=0
  (reader) / 64 (buffer), fully released at owner finish, default
  MaxConcurrentRequests=2.

## Reconstruction

Private copies are removed after the run. Recreate with:

```sh
mkdir -p /tmp/ddiast-review/wt && rsync -a --exclude .git --exclude .omo \
  /Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/ \
  /tmp/ddiast-review/wt/fx-store-memory-bounds-F1/
cp zz_fx_anchor_repro_test.go /tmp/ddiast-review/wt/fx-store-memory-bounds-F1/internal/taint/store/
```

then run the commands above from that directory.

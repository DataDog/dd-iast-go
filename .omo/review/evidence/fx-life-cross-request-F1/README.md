# fx-life-cross-request-F1 evidence (independent reproducer)

- `zz_fx_f1_app.go`: woven root-package "customer" code (package `testapp`): an application byte-buffer free list, handler A (`io.ReadAll(r.Body)` then recycle), handler B (`append` + `strconv.AppendInt` a server-side integer id into a pooled buffer, `query := string(buf)`, `db.ExecContext`).
- `zz_fx_f1_test.go`: two real requests through the woven `net/http` server with mocktracer root spans (package `testapp_test`).
- Place both in `iast/integration/testapp/` of a private copy of HEAD 2e23b46.

Command: `cd iast/integration/testapp && GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -count=3 -timeout 15m -run TestFxF1 -v .`

The test PASSES when the bug is present: it expects a bleed in `concurrent-same-length` and no bleed in the two controls.

Logs: `run-go1.26.6-count3.log` (bleed 3/3, controls clean 3/3, peak RSS 369 MB), `run-go1.27.0-buildfail.log` (the woven testapp does not build on 1.27.0 because of the known encoding/json weaving break, unrelated), `finder-R1-rerun-go1.26.6.log` (the finder's R1 re-run: same result).

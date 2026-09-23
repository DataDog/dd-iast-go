# base-test-127: Go 1.27.0 toolchain compatibility
Verdict: Critical incompatibility: Go 1.27.0's active encoding/json JSON-v2 implementation makes the unconditional JSON weaving fail to compile, blocking instrumented customer builds.
Scope covered: Go 1.27.0 root plain and Orchestrion test commands; Go 1.27.0 Orchestrion tests in all four nested modules; bootstrap builds in the three testapp modules; Go 1.25.9 and Go 1.26.6 integration bootstrap builds; `iast/encoding/json/json_test.go`, `iast/encoding/json/orchestrion.yml`, Go 1.27.0 `encoding/json/v2_stream.go`, and module files.

## Findings
### base-test-127-F1: Go 1.27 JSON v2 instrumentation prevents customer builds
- Severity: Critical
- Category: compile-break
- Location: iast/encoding/json/orchestrion.yml:28-117
- Claim: Go 1.27.0 selects JSON-v2 source files for `encoding/json`. Its `Decoder` exposes `dec` and `opts`, not `r` and `d`, and it no longer uses the private `decodeState` hooks that the advice targets. The unconditional advice therefore emits invalid field references and prevents the woven standard library from compiling. This is a compile break for valid instrumented customer applications.
- Evidence: `.omo/review/evidence/base-test-127/go127-jsonv2-compile-break.txt`; `cd /tmp/ddiast-review/wt/base-test-127 && GOTOOLCHAIN=local go tool orchestrion go test -shuffle=on -timeout 20m ./...`; generated `encoding/json` fails with `dec.r undefined` and `dec.d undefined`. `.omo/review/evidence/base-test-127/json-source-selection.txt` records the Go 1.27 source selection and changed shape. The identical integration testapp test fails for the same compiler error. The declared Go 1.26.6 integration bootstrap build succeeds (`go126-bootstrap.txt`).
- Fix: Gate the legacy private-stdlib advice to the compatible encoding/json implementation, and add a supported Go 1.27 JSON-v2 implementation or explicitly reject Go 1.27 before weaving. Keep the source-shape test aligned with each supported implementation.

### base-test-127-F2: Go 1.25.9 is rejected by the declared minimum Go version
- Severity: Info
- Category: config
- Location: go.mod:3
- Claim: The integration testapp declares `go 1.26.6`; Go 1.25.9 rejects it before Orchestrion runs. No source-level build tag or runtime-version guard was found; the module directive is the effective old-toolchain guard.
- Evidence: `.omo/review/evidence/base-test-127/go125-bootstrap.txt`; `cd /tmp/ddiast-review/wt/base-test-127/iast/integration/testapp && GOTOOLCHAIN=go1.25.9 go tool orchestrion go build ./cmd/bootstrap`; `go.mod requires go >= 1.26.6`.
- Fix: None required for Go 1.25.x. Document the supported range and add an explicit upper-bound guard only if supporting Go 1.27 is intentionally deferred.

## Checked and found correct
- Go 1.27.0 plain root `go test ./...` ran all packages; its only failure was the deliberate source-shape compatibility test at `iast/encoding/json/json_test.go:40`, which accurately detected the JSON-v2 drift.
- Go 1.27.0 nested `iast/database/sql/testapp` and `iast/os/exec/testapp` Orchestrion tests passed, and both corresponding `go tool orchestrion go build ./cmd/bootstrap` commands passed.
- The Go 1.26.6 integration bootstrap build passed, confirming the observed customer-build break is a Go 1.27.0 compatibility delta rather than a general bootstrap failure.
- The Go 1.25.9 integration bootstrap build is blocked safely by the module's `go 1.26.6` minimum requirement.

## Not covered / open questions
- The Go 1.27.0 integration bootstrap build returned Orchestrion's internal `nats: maximum payload exceeded` on the matrix invocation, a serial retry, and a fresh-private-cache retry. It is not reported as a product finding because the integration test independently reproduces the definitive JSON compiler break; the transport error needs separate Orchestrion investigation.
- No Go 1.27-compatible JSON-v2 propagation design was assessed beyond the compile blocker.

# base-static: Static analysis results
Verdict: No correctness or security defect surfaced; two low-severity production-code quality findings remain.
Scope covered: `gofmt -l` across all Go files; `go vet ./...` in the root module and all four nested modules; root `checklocks`, `golangci-lint`, `staticcheck`, `govulncheck`, and `deadcode`; targeted review of reported source locations and relevant Orchestrion configurations.

## Findings
### base-static-F1: Remove the unused root publication charge parameter
- Severity: Low
- Category: quality
- Location: internal/taint/store/root.go:323
- Claim: `(*Owner).publishRoot` accepts `charge` but never reads it. Callers already use the charge for reservation and rollback, so this parameter is inert and obscures ownership of the accounting operation.
- Evidence: `.omo/review/evidence/base-static/linter-excerpts.txt`; `GOTOOLCHAIN=go1.26.6 $HOME/go/bin/golangci-lint run ./... --enable=gosec,errorlint,bodyclose,nilerr,unparam,gocritic,prealloc,unconvert,wastedassign`; captured `unparam` diagnostic: `(*Owner).publishRoot - charge is unused`.
- Fix: Remove `charge` from `publishRoot` and its call sites; keep reservation and rollback accounting in the callers.

### base-static-F2: Remove the always-true writer release parameter
- Severity: Low
- Category: quality
- Location: internal/taint/store/writer.go:498
- Claim: `(*Owner).removeWriterLocked` accepts `release`, but all current call sites pass `true`; its conditional accounting branch cannot be disabled.
- Evidence: `.omo/review/evidence/base-static/linter-excerpts.txt`; `GOTOOLCHAIN=go1.26.6 $HOME/go/bin/golangci-lint run ./... --enable=gosec,errorlint,bodyclose,nilerr,unparam,gocritic,prealloc,unconvert,wastedassign`; captured `unparam` diagnostic: `(*Owner).removeWriterLocked - release always receives true`.
- Fix: Remove the `release` parameter and simplify the charged-byte check to run whenever `entry.charged != 0`.

## Checked and found correct
- `gofmt -l` found no unformatted Go files. `go vet ./...` exited 0 in the root module, `iast/database/sql/testapp`, `iast/os/exec/testapp`, `iast/integration/testapp`, and `benchmarks/overhead`. Root `go tool checklocks ./...` exited 0.
- The requested `golangci-lint` configuration completed and reported 89 diagnostics. The requested flags were accepted; the defaults fallback was therefore not needed. The two production `unparam` reports are the findings above. Remaining reports are test fixtures, style suggestions, or conversions with explicit bounds or modulo/hash semantics. Its three `open /path/to` messages correspond to synthetic `//line /path/to/file.go` locations in the cipher and hash tests.
- Standalone `staticcheck` exited 1 with eight test-only diagnostics. The weak-cipher/hash imports intentionally exercise those detections; the `bytes.Replace(..., 0)` case asserts the zero-replacement behavior, and the nil-context case tests the capacity-dropped request path. The remaining warnings concern deprecated test APIs or test-only path/context patterns.
- `govulncheck` exited 0 and reported no known vulnerabilities.
- `deadcode -test ./...` exited 0 with 88 unreachable-function reports. These are instrumentation entry points referenced by `iast/crypto/cipher/orchestrion.yml`, `iast/crypto/hash/orchestrion.yml`, `iast/encoding/json/orchestrion.yml`, `iast/net/http/orchestrion.yml`, and `iast/propagation/orchestrion.yml`; static reachability does not include Orchestrion's configured advice and replacements.
- The reported integer conversions were checked against their bounds. In particular, JSON reader cloning rejects inputs larger than `store.MaxRootBytes` before the bridge stores its `uint32` length, and the existing conversion sites in range, source-index, and store accounting paths are bounded by their declared limits.

## Not covered / open questions
- This node ran the standalone analyzers and `checklocks` at the root module, as specified; `go vet` covered every module. Instrumentation-enabled tests, builds, and runtime behavior were not part of this static-check assignment.

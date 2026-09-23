# light-wiring: Orchestrion imports and vulnerability table
Verdict: Pass — all 10 packages under `iast/` with an `orchestrion.yml` are imported, no stale `iast` imports were found, and the README lists every implemented vulnerability type with its instrumentation package path.
Scope covered: `orchestrion.tool.go`; all 12 repository `orchestrion.yml` files (`iast/**`, `taint/`, and `internal/spans/`); `iast/net/http/http.go`; cipher/hash report wrappers; README.md; private-copy `go generate orchestrion.tool.go`.

## Findings
No findings.

## Checked and found correct
- Enumerated all 12 manifests. The ten `iast` manifest packages are each present as blank imports in `orchestrion.tool.go`; none of those imports is stale. `taint` is also imported. `internal/spans` is imported transitively by `iast/net/http` and is outside the direct-import rule in `iast/AGENTS.md`.
- The README marks Command injection, SQL injection, Weak cipher, and Weak hash as implemented and gives the corresponding `iast/os/exec`, `iast/database/sql`, `iast/crypto/cipher`, and `iast/crypto/hash` import paths.
- The pre-work main-checkout status was clean. The scoped generation command in the private copy exited 0; its output and limitations are captured in `../evidence/light-wiring/audit.txt`.

## Not covered / open questions
- `go generate orchestrion.tool.go` emitted a warning about the missing dd-trace-go replacement directory `../../contrib/99designs/gqlgen` while processing a transitive Orchestrion tool package. It also added `github.com/DataDog/dd-trace-go/orchestrion/all/v2` to the private copy's tool imports. This does not change the reviewed `iast` manifest/import correspondence, but the generated delta was not resolved as part of this audit.
- No full application build or test suite was run; the assignment was limited to Orchestrion import and README vulnerability-table wiring.
- Go printed module download messages during generation, so the shared Go module cache may have been written outside the authorized paths. Those cache entries were not inspected or removed.

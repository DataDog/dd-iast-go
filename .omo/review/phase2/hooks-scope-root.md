# hooks-scope-root: propagation root and bootstrap scope
Verdict: Incorrect: root-package sink bootstrap advice matches valid Go plugins, contradicting the documented exclusion and causing an instrumented plugin build to fail; propagation's workspace-module boundary is also under-documented.
Scope covered: `README.md`; every `orchestrion.yml` under `iast/` and `taint/`; `internal/spans/orchestrion.yml`; `orchestrion.tool.go`; commit `24c35ec`; Orchestrion `package-filter` and `test-main` implementations; isolated Go 1.26.6 builds for workspace, `replace`, vendor, plugin, and test-main cases.

## Findings
### hooks-scope-root-F1: Root-module plugins match sink bootstrap and cannot compile
- Severity: Critical
- Category: compile-break
- Location: iast/database/sql/orchestrion.yml:16-31
- Claim: The SQL, command, and JSON bootstrap aspects select any `main` function in a root module with `test-main: false`; they do not exclude `-buildmode=plugin`. A valid root-module plugin therefore receives the SQL bootstrap import (and likewise the command/JSON imports), despite README.md:88-90 stating that plugins do not activate request-scoped sinks. With the full documented integration set, Orchestrion aborts compilation while resolving `github.com/DataDog/dd-iast-go/iast/database/sql` with `internal error: nats: maximum payload exceeded`. The equivalent plain Go plugin build succeeds.
- Evidence: `.omo/review/evidence/hooks-scope-root/plugin-compile-break.md` + `GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -buildmode=plugin -gcflags=all=-l -o ../app-plugin.so ./cmd/plugin` + `resolving "github.com/DataDog/dd-iast-go/iast/database/sql": internal error: nats: maximum payload exceeded`; the paired non-instrumented `go build -buildmode=plugin` exits 0.
- Fix: Add an Orchestrion build-mode predicate (or equivalent driver-provided plugin marker) and exclude plugins from all three root bootstrap aspects; lock it with a Go 1.26.6 plugin build regression that uses the complete integration set.

### hooks-scope-root-F2: README leaves the module boundary of “application root” ambiguous
- Severity: Medium
- Category: doc
- Location: README.md:38-39
- Claim: README says direct propagation applies in “the application root,” but the actual `package-filter: {root: true}` contract is one Go module: Orchestrion derives a single `RootModulePath` from its current working directory and rejects all other import-path prefixes. In a `go.work` workspace, a sibling local module reached through `replace` is therefore not propagation-instrumented; vendoring preserves that boundary. The README already uses the more precise phrase “root module” for sink bootstrap, so the propagation wording can reasonably be read as covering an entire workspace application.
- Evidence: `.omo/review/evidence/hooks-scope-root/scope-matrix.md` + the member and `-mod=vendor` builds show `example.com/app/own.Upper` calling `iast/propagation.StringsToUpper`, while the sibling replaced `example.com/dep.Upper` calls `strings.ToUpper` directly.
- Fix: Define “application root” as the Go module selected for the Orchestrion invocation. Explicitly state that sibling `go.work` modules and replaced/vendored dependency modules are not direct-call propagation targets, while the global stdlib hooks remain woven.

## Checked and found correct
- Direct propagation advice consistently uses `package-filter: {root: true, pattern: "**"}` across concatenation, windows, direct stdlib calls, and writer calls in `iast/propagation/orchestrion.yml`; it instruments packages below the selected module, not just its `main` package. The isolated `cmd/app` case confirmed a call in `example.com/app/own` was rewritten.
- A local dependency, including one selected by `replace` and then represented in a workspace vendor tree, stays outside the direct-call propagation root. This matches Orchestrion’s `isInRootModule` implementation and was reproduced in both normal and `-mod=vendor` builds.
- Dependencies and the standard library are still woven where aspects target explicit import paths: `net/http`, `database/sql`, `os/exec`, `encoding/json`, `io`, `bufio`, `net/url`, `bytes`, and tracer hooks have import-path/function-body selectors rather than the propagation root filter. Direct-call propagation itself is intentionally not dependency-wide.
- Synthetic Go test mains are excluded by the explicit `test-main: false` predicate. The focused regression introduced by `24c35ec` passed under Orchestrion and verified that an ordinary production executable whose package path ends in `.test` still receives SQL, command, JSON, and span bootstrap symbols.
- Invoking `go tool orchestrion` at a bare `go.work` directory without a package/tool file fails loudly while loading configuration; it does not silently run an uninstrumented build.

## Not covered / open questions
- The plugin failure prevents a runtime `plugin.Open` check; compilation already violates the host-compatibility contract.
- This review used the branch-required Go 1.26.6. A separate initial Go 1.27 build failed because `encoding/json.Decoder` fields expected by the pinned advice differ; that toolchain compatibility issue is outside this node’s root-scope remit.

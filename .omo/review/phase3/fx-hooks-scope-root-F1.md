# fx-hooks-scope-root-F1: verification of hooks-scope-root-F1

## Verdict per finding
**hooks-scope-root-F1: CONFIRMED (the symptom is real, but the root cause is misattributed and the scope is understated). Adjusted severity: Critical (unchanged).**

- Confirmed: the SQL, command, and JSON bootstrap selectors (`iast/database/sql/orchestrion.yml:16-31`, `iast/os/exec/orchestrion.yml:15-30`, `iast/encoding/json/orchestrion.yml`, same shape) have no build-mode predicate. They match the `func main` of a root-module `-buildmode=plugin` package, and also of a `c-shared` package. This contradicts README.md:88-90. A valid plugin that builds with plain Go fails to build under Orchestrion with the reported `nats: maximum payload exceeded` error.
- Refuted in part: the bootstrap is a *sufficient* trigger, not the *necessary* cause. With the full root integration set, a plugin that has **no** `func main` (so no bootstrap aspect can match) also fails (E3). dd-trace-go's own `func main` tracer aspect fails the same way with no dd-iast-go code in the build (E6). The actual defect is Orchestrion's link-time dependency resolution for `plugin` and `c-shared` build modes. The finder's fix (exclude plugins from the three bootstraps) would not make the full-set plugin build pass.

## Reproduction
Setup: private copy of HEAD 2e23b46, standalone fixture modules (no go.work; this differs from the finder's workspace), `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4`, Orchestrion `v1.12.2-0.20260828141217-23afa71d6dcb`. The script is at `evidence/fx-hooks-scope-root-F1/repro.sh`, the table at `summary.md`, and raw outputs in `E*.txt` and `E1-E2-E4-log.md`. The plugin source is `package main; import "strings"; [func main() {}]; func Upper(v string) string { return strings.ToUpper(v) }`.

| Run | Integration set | Target | Exit | Key output |
|---|---|---|---|---|
| E1 | plain `go build` | plugin with main | 0 | - |
| E4 | full root set (13 imports of `orchestrion.tool.go`) | ordinary exe | 0 | woven exe control passes |
| E2 | full root set | plugin with main | 1 | `resolving "github.com/DataDog/dd-iast-go/iast/crypto/cipher": internal error: nats: maximum payload exceeded` |
| E3 | full root set | plugin **without** main | 1 | `resolving "github.com/DataDog/dd-iast-go/iast/propagation": ... cannot find package "github.com/tinylib/msgp/msgp" ... (from $GOPATH)`; `go env GOMOD: in ".../go-build.../b001/exe": go env GOMOD returned a blank string` |
| E5 | orchestrion + `iast/database/sql` only | plugin with main | 1 | `resolving "github.com/DataDog/dd-iast-go/iast/database/sql": internal error: nats: maximum payload exceeded` (the finder's exact error) |
| E5b | same | plugin without main | 0 | - |
| E7a/E7b | plain / sql-only | `-buildmode=c-shared` (func main required) | 0 / 1 | E7b: `resolving "github.com/DataDog/dd-iast-go/iast/database/sql": internal error: nats: maximum payload exceeded` |
| E6 | orchestrion + dd-trace-go tracer only | plugin with main | 1 | `resolving "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer": -: cannot find package ... (from $GOPATH)` |
| E6b | same | plugin without main | 0 | - |

Comparing E5 with E5b isolates the finder's selector claim. The plugin imports only `strings`, so `iast/database/sql` can only enter the build through the root-`main` bootstrap, and removing `func main` makes the build pass. Peak RSS was at most 2.7 GB (E2), so there is no build-memory finding.

## Reachability
- The customer surface is `go tool orchestrion go build -buildmode=plugin` or `-buildmode=c-shared` on valid code, with the default integration set, on Go 1.26.6 (reproduced). On Go 1.27.0, cmd/go has the same plugin/c-shared link-cwd code (`src/cmd/go/internal/work/gc.go:665-667`). A woven 1.27 build was not run because the finder reports an unrelated JSON advice break on 1.27.
- With the full set, **every** plugin fails (E2, E3). Every `c-shared` library that pulls in a bootstrap or any link-time bridge fails too (E7b); c-shared always has `func main`. c-shared (Go libraries for Python, Java, or C hosts) is a more common customer shape than plugins, so the impact is wider than the finding states.
- Documentation: README.md:88-90 and 01-design-intent.md:117-119 say plugin builds "do not activate" sinks. They do not say plugins or c-shared are unsupported, so this is not a documented limitation. The docs are also wrong: the bootstrap does match plugin and c-shared `main`. Product rule 1 (no compile failure on valid customer code) is violated.
- Mitigating factor: dd-trace-go + Orchestrion already breaks plugins that declare `func main` (E6), with no dd-iast-go involved. dd-iast-go widens the break to plugins without `main` (E3 vs E6b) and to c-shared.

## Adjusted severity
Critical (unchanged). The scale defines a compile failure on valid customer code as Critical, reachable under the default configuration and the pinned toolchain. The root cause lives in the pinned Orchestrion revision, but this repo's integration set triggers it for all plugin builds.

## Root cause (file:line)
- `go1.26.6 src/cmd/go/internal/work/gc.go:660-672`: for `plugin` and `c-shared`, cmd/go runs the linker (and so `orchestrion toolexec link`) with cwd = `$WORK/b001/exe/`.
- Orchestrion `23afa71d6dcb` `internal/toolexec/aspect/onlink.go:96` calls `resolvePackageFilesForTest`, which builds `NewResolveRequest(os.Getwd(), ...)` (`internal/toolexec/aspect/resolve.go:34,44`). The child `go list` therefore runs outside the module in GOPATH mode ("go env GOMOD returned a blank string"). When the joined error text is large, `jobserver/common/handler.go` `respond()` replaces it with `internal error: nats: maximum payload exceeded`, which hides the real cause.
- Triggers in this repo: the root-`main` bootstrap imports (`iast/database/sql/orchestrion.yml:16-31`, `iast/os/exec/orchestrion.yml:15-30`, `iast/encoding/json/orchestrion.yml:~12-26`), plus any link-time bridge dependency such as `iast/propagation` and `iast/crypto/cipher`.

## Minimal fix
1. In Orchestrion (the real fix), resolve link-time dependencies from the invoking module directory instead of the link step's cwd. For example, propagate the root go command's working directory (the jobserver already knows it) into `resolvePackageFilesForTest`, or fall back to it when `os.Getwd()` is inside `$WORK`. Add plugin and c-shared build tests to Orchestrion.
2. In dd-iast-go: add Go 1.26.6 `-buildmode=plugin` (with and without `func main`) and `-buildmode=c-shared` regression builds that use the full integration set. Until Orchestrion is fixed, either document that plugin and c-shared builds are unsupported, or add a build-mode predicate to Orchestrion and use it in the three bootstraps. The predicate is needed for README.md:88-90 to be true, but it is **not sufficient** on its own (E3).
3. Correct README.md:88-90: today, bootstrap advice does match plugin and c-shared `main` packages.

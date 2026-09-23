# fx-hooks-scope-root-F1 evidence summary

All runs: private copy $WT=/tmp/ddiast-review/wt/fx-hooks-scope-root-F1 (rsync of HEAD 2e23b46),
standalone fixture modules (no go.work), GOTOOLCHAIN=go1.26.6, GOFLAGS=-p=4, orchestrion
v1.12.2-0.20260828141217-23afa71d6dcb. Script: repro.sh. Raw outputs: E*.txt / E1-E2-E4-log.md.

| Run | Fixture / integration set | Target | Result | Key line |
|---|---|---|---|---|
| E1 | app / none (plain go) | plugin, has func main | exit 0 | - |
| E4 | app / full root set | ordinary exe | exit 0 | control: woven exe builds |
| E2 | app / full root set | plugin, has func main | exit 1 | `resolving "github.com/DataDog/dd-iast-go/iast/crypto/cipher": internal error: nats: maximum payload exceeded` (peak RSS 2.7 GB) |
| E3 | app / full root set | plugin, NO func main | exit 1 | `resolving "github.com/DataDog/dd-iast-go/iast/propagation": ... cannot find package "github.com/tinylib/msgp/msgp" in any of: ... (from $GOPATH)`; `go env GOMOD: in ".../go-build.../b001/exe": go env GOMOD returned a blank string` |
| E5 | sqlonly / orchestrion + iast/database/sql | plugin, has func main | exit 1 | `resolving "github.com/DataDog/dd-iast-go/iast/database/sql": internal error: nats: maximum payload exceeded` |
| E5b | sqlonly | plugin, NO func main | exit 0 | bootstrap cannot match -> build OK |
| E7a | sqlonly / none (plain go) | c-shared (func main required) | exit 0 | - |
| E7b | sqlonly | c-shared | exit 1 | `resolving "github.com/DataDog/dd-iast-go/iast/database/sql": internal error: nats: maximum payload exceeded` |
| E6 | traceronly / orchestrion + dd-trace-go tracer (no dd-iast-go) | plugin, has func main | exit 1 | `resolving "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer": -: cannot find package ... (from $GOPATH)` |
| E6b | traceronly | plugin, NO func main | exit 0 | - |

Interpretation:
- E5 vs E5b: with only the SQL integration, the plugin source imports only `strings`; the sole way
  `iast/database/sql` enters the build is the root `main` bootstrap aspect. So the bootstrap does match
  a plugin `func main` (finder's selector claim holds) and is a sufficient trigger.
- E3: the full set fails even when no bootstrap can match (no func main) -> the bootstrap is not a
  necessary cause; excluding plugins from the bootstrap would not fix the full-set build.
- E6: dd-trace-go's own `func main` aspect fails identically without any dd-iast-go code.
- Mechanism: go1.26.6 src/cmd/go/internal/work/gc.go:660-672 runs the linker with cwd = the output dir
  (`$WORK/b001/exe/`) for `-buildmode=plugin` and `c-shared`. Orchestrion OnLink
  (internal/toolexec/aspect/onlink.go:96) calls resolvePackageFilesForTest (resolve.go:34,44), which builds
  the ResolveRequest from os.Getwd(); the child `go list` then runs outside the module (GOPATH mode,
  "go env GOMOD returned a blank string"). When the error text is large, jobserver respond()
  (common/handler.go) replaces it with "internal error: nats: maximum payload exceeded".
  Go 1.27.0 has the same cmd/go code (gc.go:665-667).

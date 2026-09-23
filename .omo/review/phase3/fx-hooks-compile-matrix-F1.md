# fx-hooks-compile-matrix-F1: verification of hooks-compile-matrix-F1

## Verdict per finding
- **hooks-compile-matrix-F1: CONFIRMED, Critical (unchanged).** A customer module that resolves Orchestrion to any released version (v1.12.2 or v1.13.0, the only releases that exist) cannot build with dd-iast-go at all. The injector configuration fails to load (`unknown injection point type "string-concat"`) before any package compiles. This follows on the canonical `dd-trace-go/orchestrion/all/v2 v2.11.0-rc.1` setup, and also when a customer simply runs `go get github.com/DataDog/orchestrion@latest`. It fails the same way on Go 1.26.6 and Go 1.27.0.
- Small corrections to the finder: the only released versions above the pin are v1.12.2 and v1.13.0. There is no v1.13.x/v1.14.x release in the up-to-date clone, so "every v1.13.x/v1.14.x" is hypothetical. The claim that "the only workaround downgrades orchestrion/all to v2.11.0-dev.1" is broadly right: forcing the pin removes (offline) or downgrades (online) `orchestrion/all`, so it cannot coexist with the rc.1 release train that dd-iast-go itself requires (`dd-trace-go/v2 v2.11.0-rc.1`).

## Reproduction
My own reproducers live in `evidence/fx-hooks-compile-matrix-F1/`, run against a private rsync copy of HEAD 2e23b46 through `replace`, with `GOPROXY=off` (module cache only).

1. `app-with-orchestrion-all/`: a minimal net/http `main` with one concat and one slice. `orchestrion.tool.go` imports `github.com/DataDog/dd-iast-go` and `dd-trace-go/orchestrion/all/v2`, and go.mod requires orchestrion/all `v2.11.0-rc.1`. `go mod tidy` silently selects `github.com/DataDog/orchestrion v1.13.0` with no warning.
   `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go build -o /dev/null .` gives, in `repro-released-v1.13.0.go1.26.6.log`:
   ```
   loading injector configuration: in "github.com/DataDog/dd-iast-go" ... in "github.com/DataDog/dd-iast-go/iast/propagation" ...:
   yaml.Decode ".../iast/propagation/orchestrion.yml": unknown injection point type "string-concat"
   exit status 1          (3.9 s, 66 MB RSS)
   ```
   The same command with `GOTOOLCHAIN=local` (go1.27.0) prints the identical error, exit 1 (`repro-released-v1.13.0.go1.27.0.log`).
2. `app-orchestrion-latest/`: dd-iast-go only, with no orchestrion/all. After tidy, the pin `v1.12.2-0.20260828141217-23afa71d6dcb` is selected. `go get github.com/DataDog/orchestrion@v1.13.0` prints `upgraded ... v1.12.2-0.2026... => v1.13.0`, which is exactly what a user sees when upgrading to the latest release. The build then fails with the identical error (`repro-orchestrion-latest-no-all.go1.26.6.log`).
3. Forcing the pin inside app 1: `go get github.com/DataDog/orchestrion@v1.12.2-0.20260828141217-23afa71d6dcb` prints `removed github.com/DataDog/dd-trace-go/orchestrion/all/v2 v2.11.0-rc.1` and `downgraded github.com/DataDog/orchestrion v1.13.0 => v1.12.2-...` (`forced-pin-downgrades-orchestrion-all.log`).
4. Positive control: app 2 back on the pin builds woven with exit 0 (220 s, 0.44 GB RSS). The binary contains `iast/propagation.concat2Result`, `concat3Result` and `StringSliceHigh` instantiated from the reproducer's own `+` and `[:1]`, and it runs (`control-pinned-pseudo-version.go1.26.6.log`, `control-woven-symbols.log`). So the Orchestrion version alone decides the outcome.

Static confirmation (Orchestrion clone at /Users/eliott.bouhana/go/src/github.com/DataDog/orchestrion, tags current after `fetch --dry-run`):
- `git merge-base --is-ancestor 23afa71d6dcb v1.12.2` and `... v1.13.0` are both false, and `git tag --contains 23afa71d6dcb` is empty.
- `git grep string-concat v1.13.0 -- internal` finds nothing, while at `23afa71d6dcb` the join point exists in `internal/injector/aspect/join/string_concat.go` and `config/schema.json`.
- In the module cache, `dd-trace-go/orchestrion/all/v2@v2.11.0-rc.1.mod:53` reads `github.com/DataDog/orchestrion v1.13.0`, while `v2.11.0-dev.1` and `v2.10.x` require v1.11.0.

## Reachability
- Default configuration and a supported toolchain: yes, on Go 1.26.6 and 1.27.0. It needs no special code. Any package tree that loads the aggregate `github.com/DataDog/dd-iast-go` integration (root `orchestrion.tool.go` imports `iast/propagation`) or `iast/propagation` directly fails at configuration load. Sub-integrations imported alone (for example `iast/database/sql`, which only pulls `internal/spans`) do not load the operator aspects.
- Triggers: (a) the documented Orchestrion customer setup `dd-trace-go/orchestrion/all/v2` at v2.11.0-rc.1, the same release train dd-iast-go's `dd-trace-go/v2 v2.11.0-rc.1` requirement implies; (b) `go get github.com/DataDog/orchestrion@latest` or `orchestrion pin` to a release; (c) any other dependency requiring Orchestrion >= v1.12.2. MVS picks the release silently, and the failure only appears at build time.
- Documented? Only partially, and only internally. `phase1/01-design-intent.md:130-133` and `_docs/plans/taint-tracking-net-http-sqli-cmdi*.md` note that PR #881 is pinned by pseudo-version and pending a release. Neither they nor the README (line 10-11 only says "requires ... orchestrion") say that customers on a released Orchestrion get a hard build failure, or give a minimum or maximum Orchestrion version. Either way it violates product rule 1 (no compile failure on valid customer code).

## Adjusted severity
**Critical (unchanged).** The severity scale lists "compile failure on valid customer code" as Critical, and this failure is deterministic, happens on the canonical setup with Go 1.26.6 and 1.27.0, and has no workaround that keeps the matching dd-trace-go Orchestrion integrations. Two things mitigate it: it fails loudly at build time, never silently at runtime, and it is a known release gate (PR #881) rather than a logic bug.

## Root cause (file:line)
- `go.mod:14`: `github.com/DataDog/orchestrion v1.12.2-0.20260828141217-23afa71d6dcb`. This is a pseudo-version off an unmerged branch. It sorts as a prerelease of v1.12.2, so MVS replaces it with any released v1.12.2+, none of which contain its commit.
- `iast/propagation/orchestrion.yml:21` (`string-concat`) and 17 more `string-concat`/`slice-expression`/`type-conversion` join points in the same file (the only yml using them). Older injectors reject unknown join-point types as a hard YAML decode error, and an integration has no way to declare them optional or version-gated.
- Loaded through the root `orchestrion.tool.go` aggregate import of `iast/propagation`.

## Minimal fix
1. Release gate: do not ship until orchestrion#881 is in a tagged release. Then require that release (>= the version the current `dd-trace-go/orchestrion/all` requires) in `go.mod`, which MVS will honour.
2. Until then, document the exact Orchestrion requirement and the incompatibility with `orchestrion/all` v2.11.0-rc.1 in the README install section. Optionally keep the operator aspects out of the default aggregate (an opt-in `iast/propagation` import) so the sinks, sources and call-site propagation still work with released Orchestrion.
3. Add a CI lane that weaves a module requiring dd-iast-go together with the latest `dd-trace-go/orchestrion/all` and `orchestrion@latest`.

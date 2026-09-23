# fx-hooks-compile-matrix-F3: import-free root packages crash the Orchestrion weaver

## Verdict per finding

**hooks-compile-matrix-F3: CONFIRMED.** I wrote my own customer-shaped module. Three realistic import-free root packages make the pinned weaver panic with `assignment to entry in nil map` at `oncompile.go:195`: a build-info package (one non-constant `+`), a truncate helper (string slicing only) and a key helper (`string(b)` only). The panic happens on Go 1.26.6 and on Go 1.27.0 with `GOEXPERIMENT=nojsonv2`, with `DD_IAST_ENABLED` unset. It also fails `go build ./cmd/shop` for the application binary that imports them. Adding one import to each package fixes the build, and the woven binary's output is byte-identical to plain Go.

The finder slightly overstates one point. "Conversions" covers only the instrumented direction, `[]byte`→`string` (`iast/propagation/orchestrion.yml:336`, the only `type-conversion` join point). An import-free package whose only operation is `[]byte(id)` (string→bytes) is not woven and builds fine. An import-free `package main` with a concat was woven (the concat became `iastprop.Concat2`) and also built fine. So the crash affects non-main root packages. This does not change the verdict.

**Duplicates:** this has the same root cause as hooks-yml-operators-F3 (already CONFIRMED in `phase3/fx-hooks-yml-operators-F3.md`). This finding only adds realistic package shapes.

## Reproduction

Sources: `.omo/review/evidence/fx-hooks-compile-matrix-F3/src/app/` (import-free) and `src/app-withimports/` (control). The module replaces `github.com/DataDog/dd-iast-go` with an rsync copy of HEAD 2e23b46 and imports the aggregate in `orchestrion.tool.go`.

Packages in `src/app/internal/`:
- `buildinfo`: `var Version = "dev"; func UserAgent() string { return "shop/" + Version }`
- `textutil`: `return s[:n]`
- `bconv`: `func Key(b []byte) string { return string(b) }`
- Negative controls: `conv` (`[]byte(id)`), `pure` (int `+`), and `buildinfo2` (the same concat as `buildinfo`, plus `import "strings"`).

```sh
cd app && export GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4; unset DD_IAST_ENABLED
for p in $(go list ./...); do /usr/bin/time -l timeout 900 go tool orchestrion go build -o /dev/null $p; done
```

Captured in `woven-build-go1266.txt` and `bconv-woven-go1266.txt`:
- `internal/buildinfo`, `internal/textutil`, `internal/bconv`: `panic: assignment to entry in nil map` ... `orchestrion@v1.12.2-0.20260828141217-23afa71d6dcb/internal/toolexec/aspect/oncompile.go:195 +0x17ac`, `exit=1`.
- `cmd/shop` (application binary importing them): the same panic, `exit=1`.
- `internal/buildinfo2`, `internal/conv`, `internal/pure`, `cmd/mini`: `exit=0`.
- Plain `go build ./... && go run ./cmd/shop` succeeds.
- Peak RSS was at most 433 MB, well below the 4 GB threshold.

Go 1.27.0 check (`GOTOOLCHAIN=local GOEXPERIMENT=nojsonv2`, `woven-build-go1270-nojsonv2.txt`): `buildinfo`, `textutil` and `bconv` panic at `oncompile.go:195 +0x173c`, `exit=1`; `buildinfo2` gives `exit=0`.

Control (`control-withimports-go1266.txt`): I added `import "strings"; var _ = strings.ToUpper` to the three failing packages. `go tool orchestrion go build -o woven ./cmd/shop` gives `wovenbuild=0`, and both binaries print `shop/dev shop/dev hello id-1 k-2 3`, followed by `IDENTICAL`. `go tool nm woven` shows `iast/propagation` operator symbols are linked, so the control really was woven.

`mini-woven-source-excerpt.txt` shows that `cmd/mini`, an import-free main package, was woven (`__orchestrion_iastprop.Concat2("hello ", name)`) without crashing.

## Reachability

This triggers under the default configuration on the supported toolchain (Go 1.26.6) and also on Go 1.27.0. The operator aspects apply to every root-module package (`package-filter: {root: true, pattern: "**"}`, `iast/propagation/orchestrion.yml:13-31`, 330-356, 375-385). They need no request, taint or env var: one non-constant string `+`, one `string([]byte)`, or one string/bytes slice in a non-main package with no imports is enough. The shapes are ordinary: version/build-info packages, small text helpers and generic constraint helpers. `go build ./...` and any binary depending on such a package fail. Dependencies outside the root module are not woven by these aspects, so the risk is limited to the customer's own packages.

The README and `phase1/01-design-intent.md` do not document this (a grep for import-free/no imports/importcfg/nil map found nothing). It violates product rule 1 (no compile failure on valid customer code).

## Adjusted severity

**Critical (unchanged).** Valid customer code fails to compile under the default woven build on the supported toolchain, as the brief's scale defines Critical.

## Root cause (file:line)

- The `wrap-expression` advice adds `imports: iastprop: github.com/DataDog/dd-iast-go/iast/propagation` (`iast/propagation/orchestrion.yml:24-26`, 339-340, 355-356, 384-385). This creates an `ImportStatement` reference, so the weaver must add the package and its transitive closure to the compile importcfg.
- Orchestrion@23afa71 `internal/toolexec/importcfg/importcfg.go:80-83` allocates `PackageFile` lazily, on the first `packagefile` line. The importcfg of an import-free package has no such line, so the map stays nil.
- `internal/toolexec/aspect/oncompile.go:172-195` resolves the synthetic dependency, then runs `imports.PackageFile[dep] = archive` without allocating the map, and panics.
- Upstream is not fixed: `origin/main` and `v1.13.0` have the same unguarded write at `oncompile.go:212`.

## Minimal fix

Fix this in Orchestrion: after `importcfg.ParseFile`, or at `oncompile.go:195`, add `if imports.PackageFile == nil { imports.PackageFile = map[string]string{} }`. Or make `parse` always return non-nil maps. Then bump the pin in dd-iast-go `go.mod`. In dd-iast-go, add an import-free, non-main root-package fixture (concat, `string(b)` and slicing) to the woven CI build as a regression guard. There is no clean workaround on the dd-iast-go side alone, because the advice must import `iast/propagation`.

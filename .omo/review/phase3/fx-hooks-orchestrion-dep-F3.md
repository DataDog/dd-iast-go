# fx-hooks-orchestrion-dep-F3: verification of hooks-orchestrion-dep-F3

## Verdict per finding
- **hooks-orchestrion-dep-F3: CONFIRMED.** Adjusted severity: **Critical** (unchanged).
  A woven build of valid customer code fails whenever a root-module package has no imports and contains a matched operator (a string concat, a string or `[]byte` slice, or a byte-to-string conversion). Orchestrion panics with `assignment to entry in nil map` inside `Weaver.OnCompile`. I reproduced this independently through a customer-style module and a real `go tool orchestrion go build` on both Go 1.26.6 and Go 1.27.0. A control where the package has one import builds and runs correctly.
- Duplicate: `hooks-yml-operators-F3` (phase 2) reports the same panic. It has the same root cause (the nil `PackageFile` map written at `oncompile.go:195`).

## Reproduction
My reproducer is independent of the finder's `review_operator_noimports` package. Its sources are in `.omo/review/evidence/fx-hooks-orchestrion-dep-F3/customer-app/`, and the captured output is in `.../run-output.txt`.
- It is a separate module `example.com/customer`, placed at `iast/reviewf3app` in the private copy. It replaces `github.com/DataDog/dd-iast-go => ../..`. Its `orchestrion.tool.go` imports only `iast/propagation` plus the tracer, which is the customer onboarding shape.
- `greet/greet.go` is an ordinary helper package with no imports: `func Hello(name string) string { return "Hello, " + name + "!" }`. `cmd/app/main.go` (which imports `fmt`, `os`, and `greet`) prints `greet.Hello(arg)`.

Commands (run from the module directory):
```
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go build -o app-plain ./cmd/app && ./app-plain there
  -> Hello, there!   exit 0
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l go tool orchestrion go build -o app-woven ./cmd/app
  -> # example.com/customer/greet
     panic: assignment to entry in nil map
     github.com/DataDog/orchestrion/internal/toolexec/aspect.Weaver.OnCompile(...)
         .../orchestrion@v1.12.2-0.20260828141217-23afa71d6dcb/internal/toolexec/aspect/oncompile.go:195
     exit status 1   (peak RSS ~315 MB)
GOTOOLCHAIN=go1.27.0 GOFLAGS=-p=4 go tool orchestrion go build -o app-woven27 ./cmd/app
  -> identical panic at oncompile.go:195
CONTROL: greet.go gains `import "strings"` (return "Hello, " + strings.TrimSpace(name) + "!")
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go build -o app-control ./cmd/app && ./app-control there
  -> build exit 0; prints "Hello, there!"; `strings app-control | grep -c iast/propagation.Concat3` = 1
```
The control shows that the operator weaving itself works: the concat is rewritten to `Concat3`, and the program's behavior is unchanged. The only trigger is that the package has no imports. I did not re-run the finder's reproducer, because my own reproduction covers the same surface more realistically.

## Reachability
- **Default configuration, supported toolchains: yes.** Every `operator ...` aspect in `iast/propagation/orchestrion.yml` (for example lines 12-31) uses `package-filter: {root: true, pattern: "**"}`. That means every package in the customer's main module is eligible. The aspects add the `iastprop` import, and weaving happens regardless of the runtime IAST enable flag. Real codebases often contain small import-free packages (string helpers, constants plus formatting helpers, generated code) that do string concat or slicing. One such package is enough to make the whole `go build`/`go test` fail.
- **Documented limitation: no.** README, `_docs/`, and `.omo/review/phase1/*` contain no mention of import-free packages, `importcfg`, or this panic.
- **Is it pre-existing in Orchestrion?** The bug is. Orchestrion `main` (5c24783) has the same unguarded write (at `oncompile.go:212` there), and the pinned branch changes nothing in `internal/toolexec` except compile/link flags. Before this branch it was effectively unreachable, because call-site advice needs a call into an imported package, so a package with zero imports had no join points. The new expression-level operator join points (`string-concat`, `slice-expression`, `type-conversion`) are the first that can match in such packages. So the dd-iast-go branch is what makes it reachable. I also checked that the finder's claim that `+` alone triggers it holds (`greet.go` above is exactly that).

## Adjusted severity
**Critical** (unchanged): the brief lists "compile or link failure on valid customer code" as Critical. This is a toolchain panic on valid code, under default config, on both supported Go versions, and a customer has no workaround short of dropping `iast/propagation` or adding a dummy import.

## Root cause (file:line, pinned Orchestrion 23afa71d6dcb)
- `internal/toolexec/importcfg/importcfg.go:52,79-82`: `parse` returns a zero `ImportConfig` and allocates `reg.PackageFile` lazily, only when it sees the first `packagefile` line. For a package with no imports, the compiler's `importcfg` has no `packagefile` lines, so `PackageFile` stays `nil`.
- `internal/toolexec/aspect/oncompile.go:57` parses that file. Reads at lines 149, 184, and 190 are safe on a nil map. Line 195 (`imports.PackageFile[dep] = archive`) writes the woven dependency's archive (`iast/propagation` and its transitive closure) into the nil map, which panics.

## Minimal fix
In Orchestrion, initialize the maps unconditionally in `parse` (`reg := ImportConfig{PackageFile: map[string]string{}, ImportMap: map[string]string{}}`), or guard with `if imports.PackageFile == nil { imports.PackageFile = make(map[string]string) }` in `OnCompile` before the loop at line 147. `CombinePackageFile` (importcfg.go ~line 105) has the same latent nil-receiver-map write and is fixed by the same `parse` change. Add an Orchestrion integration fixture that weaves an import-free root package whose only join point is an operator. Then repin dd-iast-go's `go.mod` and add a woven dd-iast-go test containing an import-free package.

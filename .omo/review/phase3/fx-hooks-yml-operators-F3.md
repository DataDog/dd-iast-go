# fx-hooks-yml-operators-F3: import-free operator package fails woven build

## Verdict per finding

**hooks-yml-operators-F3: CONFIRMED.** My separate, single-concatenation
package builds and passes its test with plain Go 1.26.6, but the pinned
Orchestrion weaver panics while compiling it. This is a compile-time failure
of valid application code, not an application runtime panic. No duplicate
finding was supplied; F1's unevaluated expressions and F2's index inference
are different mechanisms.

## Reproduction

Original reproducer and import-bearing control:
`.omo/review/evidence/fx-hooks-yml-operators-F3/reviewfximportless/` and
`reviewfximported/`. To reconstruct the private copy from the main repository:

```sh
mkdir -p /tmp/ddiast-review/wt/fx-hooks-yml-operators-F3
rsync -a --exclude .git --exclude .omo ./ /tmp/ddiast-review/wt/fx-hooks-yml-operators-F3/
cp -R .omo/review/evidence/fx-hooks-yml-operators-F3/reviewfximportless /tmp/ddiast-review/wt/fx-hooks-yml-operators-F3/
cp -R .omo/review/evidence/fx-hooks-yml-operators-F3/reviewfximported /tmp/ddiast-review/wt/fx-hooks-yml-operators-F3/
cd /tmp/ddiast-review/wt/fx-hooks-yml-operators-F3
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -timeout 3m -count=1 ./reviewfximportless ./reviewfximported
/usr/bin/time -l env -u DD_IAST_ENABLED GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -timeout 3m -count=1 ./reviewfximportless
/usr/bin/time -l env -u DD_IAST_ENABLED GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -timeout 3m -count=1 ./reviewfximported
```

Plain output: `ok .../reviewfximportless`; import-bearing woven output:
`? .../reviewfximported [no test files]`. Import-free woven output, repeated
twice: `panic: assignment to entry in nil map`, `Weaver.OnCompile ...
oncompile.go:195`, `FAIL .../reviewfximportless [build failed]`.
The failing run's peak RSS was 122,191,872 bytes (below 4 GiB). Captured
lines are in `woven-go1266.txt` and `controls.txt` under the evidence
directory above.

## Reachability

Default `DD_IAST_ENABLED` was **unset**, not forced on. A root application
package needs no dependencies or taint values to trigger this: a single
nonconstant string `+` matches the default aspect. The README explicitly
advertises root-application string concatenation; neither its coverage
limitations nor `.omo/review/phase1/01-design-intent.md` exempts import-free
packages. This violates the product rule against breaking customer builds.

On Go 1.27.0 the same fixture passes plain `go test`, but its woven build
stops earlier: injected `encoding/json` references nonexistent `Decoder.r` and
`Decoder.d` fields. That run does not establish whether F3 also manifests
after the separate Go 1.27.0 failure is fixed; see `controls.txt`.

## Adjusted severity

**Critical (unchanged).** A supported, valid customer package fails to
compile with the default woven build on Go 1.26.6.

## Root cause (file:line)

`iast/propagation/orchestrion.yml:13-31` wraps the concatenation and requests
the `iast/propagation` import. In pinned Orchestrion
`internal/toolexec/importcfg/importcfg.go:52-81`, `parse` creates
`PackageFile` only after seeing a `packagefile` directive, so an empty
importcfg leaves the map nil. `internal/toolexec/aspect/oncompile.go:173-195`
resolves that synthetic import then writes `imports.PackageFile[dep] =
archive` without allocating the map. The import-bearing control makes this
map non-nil and succeeds, isolating the cause.

## Minimal fix

Initialize `PackageFile` for empty importcfg inputs in the pinned Orchestrion
dependency before synthetic dependencies are inserted; update this module's
Orchestrion pin. Keep an import-free root-package woven build fixture (and an
import-bearing control) in the regression suite.

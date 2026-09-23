# hooks-orchestrion-dep: Pinned operator join points and release readiness

Verdict: Not release-ready: the pinned Orchestrion integration changes valid program behavior, breaks two valid build shapes, and misses provenance for legal generic constraints; PR #881 is still open with changes requested.

Scope covered: `main...23afa71` across all 19 changed Orchestrion files, especially `internal/injector/{typed/coretype.go,aspect/{concat/*,join/{string_concat,slice_expression,type_conversion}.go,advice/code/dot_{concat,slice}.go,context/context.go},config/schema.json}`, the operator fixture/snapshot, and changed compiler/linker flags. Followed injected imports into pinned `internal/toolexec/{aspect/oncompile.go,importcfg/importcfg.go}`. Compared with dd-iast-go HEAD `go.mod:13`, `iast/propagation/orchestrion.yml:12-405`, `operators.go:13-305`, and its existing woven operator tests. Applied digest checks 13-16 and shadow scenarios S8-S10, S18. Commands below ran only in `/tmp/ddiast-review/wt/hooks-orchestrion-dep` with Go 1.26.6 on darwin/arm64; captured output and fixtures are in `.omo/review/evidence/hooks-orchestrion-dep/run-results.txt`.

## Findings

### hooks-orchestrion-dep-F1: Operator advice evaluates expressions Go leaves unevaluated
- Severity: Critical
- Category: behavior-change
- Location: `iast/propagation/orchestrion.yml:343-370`; pinned Orchestrion `internal/injector/aspect/join/slice_expression.go:63-94`, `internal/injector/aspect/join/string_concat.go:83-95`
- Claim: The matchers recognize a typed operator but do not reject an enclosing constant `len`/`cap` on an array. Go does not evaluate an array operand to `len` if its expression contains no channel receive or nonconstant function call. Instrumenting `len([1]string{value[99:]})` introduces `StringSliceLow`, so a valid program that returns 1 without evaluating the slice now panics. The same mechanism can turn a previously constant array length into a compile error. This holds when IAST is disabled because the changed evaluation happens before the runtime activity gate.
- Evidence: `.omo/review/evidence/hooks-orchestrion-dep/arraylength_test.go` and `.omo/review/evidence/hooks-orchestrion-dep/run-results.txt` (case 1). Run `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 go test -timeout 4m -count=1 -run '^TestArrayLengthLeavesSliceUnevaluated$' -v ./review_operator_arraylength`, then the same command via `go tool orchestrion go test` in the private copy. Plain: `--- PASS`; woven: `panic: runtime error: slice bounds out of range [99:3]`, frame `StringSliceLow` at `operators.go:218`.
- Fix: Exclude operator expressions inside enclosing unevaluated array operands, including constant `len`/`cap` and array-range contexts, before applying any expression wrapper. Add constant-expression and runtime non-evaluation fixtures.

### hooks-orchestrion-dep-F2: Legal integral floating slice index produces a generic type error
- Severity: Critical
- Category: compile-break
- Location: pinned Orchestrion `internal/injector/aspect/join/slice_expression.go:69-77`; `iast/propagation/orchestrion.yml:360-370`, `iast/propagation/operators.go:13-15,213-220`
- Claim: Go permits an untyped floating constant representing an integer as a slice bound. The join-point guard checks the *resolved* `types.Basic` kind against `UntypedFloat`/`UntypedComplex`, but `go/types` has already contextualized `1.0` as `int` in `value[1.0:]`. The generated generic `StringSliceLow(value, 1.0)` infers `float64`, outside the helper's `integer` constraint. Valid customer code therefore stops compiling; the same failure applies to byte slices and integral untyped complex bounds.
- Evidence: `.omo/review/evidence/hooks-orchestrion-dep/zz_review_floatbounds_test.go` and `.omo/review/evidence/hooks-orchestrion-dep/run-results.txt` (case 2). Run `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 go test -timeout 4m -count=1 -run '^TestReviewIntegralUntypedFloatBound$' -v ./iast/propagation`, then its `go tool orchestrion go test` equivalent. Plain: `--- PASS`; woven: `<generated>:1: float64 does not satisfy ... integer`.
- Fix: Preserve the contextual integer type when generating bound arguments, or inspect the original constant syntax/value and reliably exclude bounds generic inference cannot accept. Test integer-valued float and complex constants in both string and byte slice forms.

### hooks-orchestrion-dep-F3: Injected operator import panics on import-free packages
- Severity: Critical
- Category: compile-break
- Location: `iast/propagation/orchestrion.yml:12-31`; pinned Orchestrion `internal/toolexec/aspect/oncompile.go:190-195`, `internal/toolexec/importcfg/importcfg.go:52-83`
- Claim: Adding the propagation import to an otherwise import-free root package exercises an uninitialized import-configuration map. `importcfg.parse` allocates `PackageFile` only after seeing an existing `packagefile` entry, while `OnCompile` writes a synthetic dependency into it unconditionally. An import-free file containing only `return left + right` therefore fails to build with `panic: assignment to entry in nil map`. This is an existing importer defect made reachable for common valid source packages by the new import-requiring join points.
- Evidence: `.omo/review/evidence/hooks-orchestrion-dep/noimports.go` and `.omo/review/evidence/hooks-orchestrion-dep/run-results.txt` (case 3). Run `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 go test -timeout 4m -count=1 ./review_operator_noimports`, then its `go tool orchestrion go test` equivalent. Plain: `[no test files]`, exit 0; woven: `panic: assignment to entry in nil map`, `Weaver.OnCompile ... oncompile.go:195`, exit 1.
- Fix: Initialize `PackageFile` before any synthetic dependency insertion (preferably in import-configuration parsing or construction), and cover weaving an import-free root package before updating the dd-iast-go pin.

### hooks-orchestrion-dep-F4: Core-type resolution loses valid intersected generic constraints
- Severity: High
- Category: provenance
- Location: pinned Orchestrion `internal/injector/typed/coretype.go:60-104`; `iast/propagation/orchestrion.yml:12-31,343-405`
- Claim: `interfaceCoreType` rejects a union with differing underlying types *before* intersecting it with the remaining embedded constraints. A valid parameter constrained by `interface{ ~string | ~int; ~string }` has only string types in its final set and admits `+` and slicing, but the resolver returns nil. Likewise `interface{ ~[]byte | ~[]int; ~[]byte }` has a byte-slice core. All three operator aspects miss these expressions. The resulting values are correct but taint is dropped on supported concat/string-slice/byte-slice paths, causing false-negative downstream vulnerability detection.
- Evidence: `.omo/review/evidence/hooks-orchestrion-dep/zz_review_coretype_test.go` and `.omo/review/evidence/hooks-orchestrion-dep/run-results.txt` (case 4). Run `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 go tool orchestrion go test -timeout 4m -count=1 -run '^TestReviewIntersectionCoreTypeRetainsProvenance$' -v ./iast/propagation`. It compiles, passes the `built.WithOrchestrion` preflight and exact-result checks, then all three subtests fail with `expected: true; actual: false` when querying their expected source ranges. Existing `TestOperatorConcatAndSlices` passes in the same private copy for ordinary named and `~string`/`~[]byte` constraints.
- Fix: Compute the intersection of type-set terms before deciding whether the final set has a unique underlying type. Add a `go/types` unit fixture for intersected unions plus woven provenance cases.

### hooks-orchestrion-dep-F5: Production dependency is pinned to a changes-requested PR
- Severity: Medium
- Category: config
- Location: `go.mod:13`; `_docs/plans/taint-tracking-net-http-sqli-cmdi-phase-6.md` (external-join-point dependency); pinned Orchestrion `23afa71d6dcb`
- Claim: The Go module references an immutable pseudo-version on an unmerged feature branch rather than a reviewed Orchestrion release. At the September 23, 2026 check, upstream PR #881 was `OPEN`, `CHANGES_REQUESTED`, with `mergedAt:null` and head exactly `23afa71d6dcb13cc221c6461745229779e7674b4`. Fixes to the above defects will not reach this pinned commit automatically. Publishing dd-iast-go against this pin before updating and revalidating it would ship known host-safety regressions.
- Evidence: `.omo/review/evidence/hooks-orchestrion-dep/run-results.txt` (case 5), `gh pr view 881 -R DataDog/orchestrion --json state,reviewDecision,headRefOid,mergedAt,url --jq '{state,reviewDecision,headRefOid,mergedAt,url}'`; local `git branch -r --contains 23afa71` lists only the feature branch, and `merge-base --is-ancestor 23afa71 main` exits 1. This is a release gate, not a claim that pseudo-versions cannot be fetched.
- Fix: Land and release the Orchestrion corrections, repin dd-iast-go to that reviewed release, then rerun woven fixtures on the exact pinned revision and both supported Go toolchains.

## Checked and found correct
- `string-concat` selects the maximal nonconstant chain, folds constant subtrees, counts 2-16 operands and exposes operands in source order; dd-iast-go chooses one fixed-arity `ConcatN` template per count. Normal named and generic operator tests, including byte full-slice capacity and two-source ranges, pass in the private woven run.
- `type-conversion` matches only direct assignment, declaration, and return contexts for supported byte-to-string conversions; dd-iast-go's template retains `.AST.Fun` and evaluates its argument once. String-to-byte conversion is not configured by dd-iast-go. Optimized contexts, `+=`, mutable byte writes, and chains over 16 operands are documented safe misses, not findings.
- The slice matcher intentionally covers `string` and `[]byte` core types, not arrays or slices of defined byte element types. The templates cover omitted bounds and three-index byte slicing; the existing woven `TestOperatorConcatAndSlices` passes all ordinary listed shapes. F2 concerns its *constant-bound* exclusion, not these standard bounds.
- Schema entries and fixture snapshots include all three new join points and helpers; no missing schema registration was observed. Compiler/linker flag changes were read, with no separate regression reproduced.

## Not covered / open questions
- Focused Go 1.26.6 darwin/arm64 runs only; no Go 1.27, whole-suite, race, or platform matrix run. The private copy was necessary to keep the main checkout read-only. No independent full Orchestrion package suite was run.
- Parenthesized blanks, deeply nested (>16) constraint hierarchies, and overlapping third-party aspect advice were not exercised. The depth limit can miss valid types but is explicitly bounded and not reported without impact evidence.
- F1-F3 overlap the operator-integration node's independently reported defects; this node locates their causes in the pinned dependency and includes its own bounded reproductions. F4 is the additional core-type defect.

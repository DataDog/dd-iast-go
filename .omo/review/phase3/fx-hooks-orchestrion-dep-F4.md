# fx-hooks-orchestrion-dep-F4: verification of "Core-type resolution loses valid intersected generic constraints"

Verdict: CONFIRMED (High). `interfaceCoreType` in the pinned Orchestrion rejects a mixed
union before intersecting the remaining embedded constraints, so valid type parameters whose
final type set is string-only or `[]byte`-only are not advised; taint is silently dropped on
supported operator paths. Reproduced independently through a woven build; the finder's own
reproducer also reproduces verbatim.

Scope covered: pinned Orchestrion `internal/injector/typed/coretype.go` (git show at
`23afa71d6dcb`), `internal/injector/aspect/join/{slice_expression,string_concat}.go`,
`internal/injector/aspect/concat/concat.go`; dd-iast-go HEAD `2e23b461`
`iast/propagation/orchestrion.yml:12-31,343-405`, `operators_concat_test.go`,
`operators_slices_test.go`, `native_provenance_test.go`; README and
`.omo/review/phase1/01-design-intent.md` for documented limitations.

## Verdict per finding

### hooks-orchestrion-dep-F4 — CONFIRMED
- Claim as stated is accurate: `interfaceCoreType` (pinned
  `internal/injector/typed/coretype.go:87-97`) iterates embedded elements and returns
  `(nil, false)` at the *first* pair of differing underlying types (lines 93-95), before any
  remaining embedded constraint is examined. Go's interface type set is the *intersection* of
  its embeddeds, so `interface{ ~string | ~int; ~string }` has type set `~string` and a
  legitimate `string` core type; the resolver wrongly returns nil. Same for
  `interface{ ~[]byte | ~[]int; ~[]byte }` → `[]byte` core.
- Consequence verified end-to-end through the realistic surface (woven build):
  `string-concat` (`orchestrion.yml:12-31`, matcher at `concat/concat.go:63` →
  `typed.IsStringCore`), `slice-expression operand string` (`yml:343-370`, matcher at
  `slice_expression.go:86`), and `operand bytes` (`yml:372-405`, matcher at
  `slice_expression.go:89`) all miss the expression; the wrapped operation never happens, and
  the result carries no taint. Result *values* are correct — this is purely lost provenance.
- Adversarial checks that passed:
  - The constraint is legal Go on both supported toolchains (standalone build exits 0 under
    GOTOOLCHAIN=go1.26.6 and go1.27.0). `v[1:]`/`v + "!"` compiling proves the final type set
    is string-only.
  - Not a harness artifact: the positive control in my reproducer (`[T ~string]` generic
    concat) retains taint woven, and the repo's own `operators_slices_test.go:134-142`
    (`genericConcat[T ~string]`, `genericByteSlice[T ~[]byte]`) shows generic core-type
    propagation is an intended, supported path.
  - Not a documented limitation: no mention of generics/core types/constraint shapes in
    README "Propagation coverage" or `phase1/01-design-intent.md`; the README's operator
    matrix ("2-16 operand string concatenation, supported string/byte slicing") covers these
    expressions.
  - No overstatement found in the finder's claim; the only refinement is a secondary facet
    of the same root cause (below).

## Reproduction
Private copy `/tmp/ddiast-review/wt/fx-hooks-orchestrion-dep-F4` (removed afterwards).
Commands and full captured output: `.omo/review/evidence/fx-hooks-orchestrion-dep-F4/run-results.txt`.

1. Plain pass (legality + skip):
   `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -timeout 4m -count=1 -run 'TestReviewIntersectionCoreTypeRetainsProvenance|TestF4IntersectedCoreTypeKeepsProvenance' -v ./iast/propagation`
   → both SKIP (`requires woven operator advice`), exit 0.
2. Woven pass (mine + finder's together):
   `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l go tool orchestrion go test -timeout 4m -count=1 -run '...same...' -v ./iast/propagation`
   Key lines:
   - `control_plain_~string_generic_concat_is_advised` → `control tainted: true`, PASS.
   - `intersected_~string|~int_&_~string_concat` → `intersected concat tainted: false`, FAIL.
   - `intersected string slice tainted: false`; `intersected byte slice tainted: false`, FAIL.
   - Finder's three subtests: `expected: true; actual: false` each.
   Build: 169 s real, peak RSS ~335 MB (no build-memory concern).
   My reproducer: `evidence/fx-hooks-orchestrion-dep-F4/zz_f4verify_test.go`; the finder's was
   run verbatim from `evidence/hooks-orchestrion-dep/zz_review_coretype_test.go`.
3. Toolchain legality: `GOTOOLCHAIN=go1.26.6|go1.27.0 go build` of `legality-main.go` both exit 0.

## Reachability
- Customer code in the woven application (root package, not under dd-iast-go/internal) using
  a generic helper whose constraint narrows to a string/`[]byte` core via intersected
  embeddeds loses taint at `+`/slicing under default configuration. Weaving is
  unconditional at build time; no config disables it. The store/taint machinery is bypassed
  entirely (no advice is generated), so runtime sampling/config cannot rescue it.
- Realistic shapes: composed constraint interfaces (e.g. a library's
  `~string | ~int` union intersected with the app's `~string`), any order (the early return
  fires on the mixed union regardless of position). Frequency is low — this is an uncommon
  constraint style — but each occurrence is a silent false negative of SQLi/CMDi downstream.
- Documented limitation: NO (README/01-design-intent say nothing about generic constraints or
  core types; existing tests treat `~string`/`~[]byte` generics as supported).

## Adjusted severity
- High (unchanged). Justification: lost taint (false-negative vulnerability reporting) on a
  supported propagation path — operator concat/slice advice exists, is enabled by default,
  and is tested for generic `~string`/`~[]byte` constraints — triggered by legal customer
  code on both supported toolchains. This is exactly the brief's High definition ("wrong
  provenance on a SUPPORTED path"). Not Medium: it is not an unknown-shape miss but a
  resolver defect on shapes the design already claims; not Critical: no crash, no behavior
  change, values stay correct.

## Root cause
- Pinned Orchestrion `internal/injector/typed/coretype.go:93-95` (within 60-104): early
  `return nil, false` on the first two differing underlying types across embedded terms,
  instead of intersecting all embeddeds' term sets before deciding. Secondary facet, same
  cause: `coretype.go:78-81` silently *ignores* a nested interface with no unique core
  (`continue`), losing its narrowing contribution as well.
- Affected dd-iast-go surfaces at HEAD 2e23b46: `iast/propagation/orchestrion.yml:12-31`
  (string-concat), `:343-370` (string slice), `:372-405` (byte slice); byte-to-string
  conversions are unaffected (no core-type matcher).

## Minimal fix
In `interfaceCoreType`, first compute each embedded element's term set (expanding nested
interfaces recursively; a method-only/comparable interface contributes no terms), then
intersect the term sets across all embeddeds (a term survives only if present in every
set that has terms; an empty intersection yields no core), and only then require the
survivors to share one underlying type. Add `go/types` unit fixtures for
`{~string|~int; ~string}`, `{~[]byte|~[]int; ~[]byte}`, nested variants, and empty
intersections, plus woven provenance cases; repin dd-iast-go (ties into F5: fixes will not
reach the pinned pseudo-version automatically).

## Duplicates
Single finding under test; no duplicate items in the input array. F1-F3 from the same
originating report are distinct root causes (evaluation order, constant bounds, importcfg),
not duplicates of F4.

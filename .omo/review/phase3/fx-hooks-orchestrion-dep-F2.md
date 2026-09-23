# fx-hooks-orchestrion-dep-F2: verify "Legal integral floating slice index produces a generic type error"

## Verdict per finding

### hooks-orchestrion-dep-F2 — CONFIRMED
The claimed mechanism is real, exactly as described. Go legally accepts an
untyped integral float constant (`1.0`) — and even an integral untyped complex
constant (`1.0+0i`) — as a slice bound, because the spec converts it to `int`.
`go/types` therefore records the bound's **resolved** type as `int`, so the
pinned Orchestrion guard at `internal/injector/aspect/join/slice_expression.go:69-77`
(comparing `ctx.ResolveType(bound).Kind()` against `UntypedFloat`/`UntypedComplex`)
never fires for these bounds: the untyped kind has already been erased by
contextual typing. The `operator string slice` / `operator byte slice` aspects
(`iast/propagation/orchestrion.yml:343-405`) then re-emit the raw bound into a
generic call such as `iastprop.StringSliceLow(value, 1.0)`; outside the slice
context, the untyped constant defaults to `float64`, which does not satisfy the
helper's `integer` constraint (`iast/propagation/operators.go:13-15,217`), so
**valid customer code stops compiling** under the woven build.

Only one finding was supplied; no duplicate set to collapse. It is a distinct
root cause from hooks-orchestrion-dep-F1 (unevaluated operands) even though
both live in the same `slice_expression.go` guard: F1 is about *where* the
operand appears (enclosing unevaluated `len`/`cap`), F2 is about *what type
information survives* for the bound. F3 (import-free packages) is unrelated.

## Reproduction (commands + key output lines)

All commands ran in the private copy `/tmp/ddiast-review/wt/fx-hooks-orchestrion-dep-F2`
(HEAD 2e23b46), sequentially, `GOTOOLCHAIN=go1.26.6`, `GOFLAGS=-p=4`, woven runs
under `/usr/bin/time -l` (peak RSS 72–119 MB, well under the 4 GB threshold).
Sources and full captured output: `.omo/review/evidence/fx-hooks-orchestrion-dep-F2/`.

My own reproducers (customer-shaped woven test packages, not the finder's):

1. Plain-Go legality (`probe_f2_legality/probe.go`): `s[1.0:]`, `s[:2.0]`,
   `s[1.0:2.0]`, `b[1.0:]`, `b[1.0:2.0:3.0]`, `s[1.0+0i:]`, and a named
   `const lo = 1.0` bound all compile: `go build ./probe_f2_legality` → `EXIT=0`.
2. `go test -v ./review_f2_str ./review_f2_bytes ./review_f2_complex` → all
   `--- PASS`, `EXIT=0` (these are valid, passing Go tests).
3. `go tool orchestrion go test -v ./review_f2_str` →
   `<generated>:1: float64 does not satisfy "github.com/DataDog/dd-iast-go/iast/propagation".integer (float64 missing in ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr)`
   → `[build failed]`, `EXIT=1`.
4. Same for `./review_f2_bytes` (identical `float64 does not satisfy ... integer`)
   and `./review_f2_complex` (`complex128 does not satisfy ... integer`), both
   `[build failed]`, `EXIT=1`.
5. Direct mechanism check, no orchestrion (`review_f2_direct/main.go`: the exact
   call the template generates, `iastprop.StringSliceLow(value, 1.0)`), plain
   `go build` on both supported toolchains: identical
   `main.go:14:40: float64 does not satisfy ... integer` on go1.26.6 **and**
   go1.27.0.
6. Woven go1.27.0 run of `./review_f2_str` fails *earlier and for an unrelated
   reason* (`encoding/json` weave: `dec.r undefined ...`) — see Reachability.

I also re-ran the finder's own reproducer verbatim in my private copy
(`zz_review_floatbounds_test.go` in `iast/propagation`):
`GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 go tool orchestrion go test -count=1 -run '^TestReviewIntegralUntypedFloatBound$' -v ./iast/propagation`
→ the same `<generated>:1: float64 does not satisfy ... integer`,
`[build failed]`, exit 1. The finder's report is fully reproducible.

Empirical proof of the guard-passes-it premise: had `ctx.ResolveType(bound)`
returned `UntypedFloat` for `1.0`, the join point would have rejected the match
and the woven build would have succeeded; instead every woven build fails at the
generated generic call — the bound was resolved to `int`, exactly as claimed.

## Reachability

- Default configuration: the `operator string slice` / `operator byte slice`
  aspects are in the shipped `iast/propagation/orchestrion.yml` and apply to all
  root packages of the customer module; there is no runtime gate that prevents
  this — the failure is a *compile* failure, so it fires with IAST sampling at
  0% and even in library/plugin builds. Any customer application whose root
  package slices a string or `[]byte` with an integral untyped float/complex
  constant bound fails to build the moment they adopt `go tool orchestrion`.
  `reachable_default: true`.
- Supported toolchain: confirmed on Go 1.26.6 (the pinned target) end-to-end.
  On Go 1.27.0 the woven build fails even earlier for an unrelated reason (the
  `iast/encoding/json` weave uses `dec.r`/`dec.d`, which Go 1.27's
  `encoding/json` no longer has), which masks F2 in woven 1.27 builds; the
  direct-call check shows the F2 type-inference failure itself is identical on
  1.27.0 (the default type of an untyped float constant is still `float64`).
  The 1.27 json incompatibility belongs to the operator-integration /
  toolchain-compat nodes, not to F2.
- Documentation: neither the README ("Propagation coverage" lists *string
  slicing* and two-/three-index `[]byte` slicing as supported) nor
  `.omo/review/phase1/01-design-intent.md` documents any constant-bound
  exclusion. This is not a documented trade-off; it violates product rule 1
  ("no compile failure on valid customer code"). `documented_limitation: false`.
- Realism caveat: writing `s[1.0:]` instead of `s[1:]` is rare in hand-written
  code, but the severity scale makes any compile failure on valid customer code
  Critical regardless of frequency, and it is trivially reachable (a single
  constant expression anywhere in a root package).

## Adjusted severity

**Critical (unchanged).** Compile failure on valid customer code under the
default woven build, on the pinned target toolchain, with no configuration
escape hatch — squarely the brief's Critical definition.

## Root cause (file:line)

- Primary: pinned Orchestrion `23afa71d6dcb`, `internal/injector/aspect/join/slice_expression.go:69-77`
  — the constant-bound exclusion inspects the *resolved* `types.Basic` kind, but
  `go/types` has already contextualized integral untyped float/complex slice
  bounds to `int`, so `UntypedFloat`/`UntypedComplex` never appear and the guard
  is vacuous for exactly the cases it was written to exclude.
- Secondary (dd-iast-go side): `iast/propagation/orchestrion.yml:360-370,390-404`
  re-emit `{{ .AST.Low }}`/`High`/`Max` verbatim into generic helpers whose
  bounds parameters are constrained to `integer` (`iast/propagation/operators.go:13-15,216-245,276-305`),
  which infers `float64`/`complex128` for these constants.

## Minimal fix

Fix the join point, not the templates: in `sliceExpression.Matches` (and the
analogous guard in `string_concat.go` if it shares the pattern), decide on the
bound's *constant syntax*, not the resolved type — e.g. reject when any
`dst.BasicLit` in the bound has `Kind != INT` (covers `1.0`, `1e3`, `1+0i`),
since `go/types` erases the untyped kind before the matcher runs. That is a
conservative miss (dropped provenance on a rare shape) rather than a break.
A provenance-preserving alternative: when the resolved bound type is exactly
`int` (true for every untyped-constant bound), have the advice emit
`int({{ .AST.Low }})` — for a constant this is an exact constant conversion
and for a typed `int` bound an identity conversion — but note the naive
`int(...)` must not be applied to typed `int8`/`uint64`… bounds, where a
runtime conversion could wrap. Add woven fixtures covering integral float and
complex constant bounds in both string and byte forms (my three reproducer
packages can serve as the fixture), then repin dd-iast-go per F5.

## Checked and found correct (adjacent behavior)

- Plain typed integer bounds (`s[i:]`, `s[:n]`, `b[i:j:k]` with any integer
  type) infer fine through the same helpers — only the untyped-constant
  defaulting breaks; the existing woven `TestOperatorConcatAndSlices` passing
  (finder's run) corroborates ordinary bounds are unaffected.
- The high bound (`s[:9.0]`) and both-bounds / three-index byte forms break
  through the same mechanism — confirmed individually, so the defect is in the
  shared bound guard, not one template branch.
- Woven-build peak RSS across all runs: 72–119 MB — no build-time memory issue
  for these shapes.

## Open questions

- Whether upstream intends to fix this via the join point or the dd-iast-go
  template before PR #881 lands; either location works, but both pinned sides
  need a regression fixture.
- Go 1.27.0 woven validation of F2 end-to-end is blocked by the unrelated
  `encoding/json` weave incompatibility (out of scope here).

# fx-hooks-yml-operators-F1: Hooks evaluate array operands that Go leaves unevaluated

## Verdict per finding

**hooks-yml-operators-F1: CONFIRMED.** The slice-hook path alone reproduces
both a valid constant expression becoming non-constant and new runtime panics.
The compile-time and runtime failures share one cause: rewriting an expression
that Go is permitted to leave unevaluated into a function call.

## Reproduction

I created the independent fixtures under
`.omo/review/evidence/fx-hooks-yml-operators-F1/fixtures/` and ran them in the
required private copy. With `DD_IAST_ENABLED=false`, plain Go 1.26.6 passed
both runtime tests and compiled the typed-string constant-length package.
Woven Go 1.26.6 failed both runtime tests:

```text
len evaluated the array element: runtime error: slice bounds out of range [:99] with length 3
range evaluated the array element: runtime error: slice bounds out of range [:99] with length 3
```

The woven constant-length build failed with
`len([1]string{…}) (value of type int) is not constant`. The same plain-versus-
woven results reproduced on Go 1.27.0 using a propagation-only Orchestrion
tool configuration. The full tool configuration on Go 1.27.0 stopped earlier
in the separate JSON aspect (`dec.r` and `dec.d` undefined); that unrelated
blocker and the isolated rerun are both recorded in the evidence directory.

Primary commands, run from
`/tmp/ddiast-review/wt/fx-hooks-yml-operators-F1`:

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 DD_IAST_ENABLED=false go test -timeout 3m -count=1 -v ./reviewfxoperators ./reviewfxoperators/constantlen
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 DD_IAST_ENABLED=false REVIEW_WOVEN=1 go tool orchestrion go test -work -timeout 3m -count=1 -v ./reviewfxoperators
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 DD_IAST_ENABLED=false REVIEW_WOVEN=1 go tool orchestrion go test -work -timeout 3m -count=1 -v ./reviewfxoperators/constantlen
```

Captured outputs are in `go1266-plain.txt`,
`go1266-woven-runtime.txt`, `go1266-woven-constantlen.txt`,
`go1270-woven-runtime-isolated.txt`, and
`go1270-woven-constantlen-isolated.txt` under the evidence directory. The
initial untyped-string-constant control stayed native; the final compile
fixture uses `var text string`, which the pinned join point matches.

## Reachability

Ordinary customer root packages are in scope: the YAML uses
`package-filter: {root: true, pattern: "**"}` and wraps matching expressions
without a runtime-configuration condition. The regression reproduced even
with IAST disabled, so the activity gate cannot protect the host operation.
`DD_IAST_ENABLED` defaults to `true`.

This is not a documented limitation. The README's intentional misses concern
optimized byte/string conversion contexts, mutable aliases, and other named
safe misses; it does not exclude operator expressions inside unevaluated array
`len`/`cap` or `range` operands. The design intent explicitly requires
preserving host evaluation and panic behavior.

## Adjusted severity

**Critical (unchanged).** Valid customer code can fail to compile, and code
that compiled before weaving can newly panic at runtime.

## Root cause

`iast/propagation/orchestrion.yml:12-31,343-370` wraps concat and string-slice
AST nodes in calls. In pinned Orchestrion `23afa71`,
`internal/injector/aspect/join/string_concat.go:83-95` checks the maximal
concat node and arity, while `slice_expression.go:63-94` checks the slice
node's operand and bound types; neither matcher excludes nodes under an
unevaluated array context. `iast/propagation/operators.go:226-232` evaluates
`value[:high]` before checking `operatorbridge.HasValues`, so the disabled
runtime path still panics once the wrapper call forces evaluation.

No separate duplicate is present in this assignment. The compile and runtime
symptoms are the same root cause.

## Minimal fix

Make both operator join points aware of enclosing unevaluated array contexts
and leave those expressions untouched when Go would omit their evaluation.
Add woven regressions for constant `len`/`cap` and zero/one-variable array
`range`, alongside the runtime and compile fixtures captured here.

# fx-hooks-yml-strings-F1: method-expression calls break woven compilation

Verdict: both findings CONFIRMED, same root cause, Critical confirmed. Independently
reproduced in a nested customer-style module (`testapps/integration`) on Go 1.26.6:
valid Go using method expressions on `*strings.Builder`, `*bytes.Buffer` and
`*strings.Replacer` compiles unwoven and fails to compile under `go tool orchestrion`.

Scope: `iast/propagation/orchestrion.yml:1057-1552` (32 `method-call` join points, the only
`method-call` uses in the repo), orchestrion `internal/injector/aspect/join/method_call.go`
and `internal/injector/aspect/context/context.go` at pinned `23afa71d6dcb`, README:30-45,
phase1 design-intent notes.

## Verdict per finding
- `hooks-yml-strings-F1`: **CONFIRMED**. `strings.Builder.WriteString.pointer`
  (`orchestrion.yml:1089-1103`) and `strings.Replacer.Replace.pointer` (`:1521-1535`) match
  method expressions and emit a type in receiver position. Reproduced with my own fixture,
  including through an import alias (`(*str.Replacer).Replace(r, s)`), which the finder did
  not test.
- `hooks-fidelity-bytes-F1`: **CONFIRMED** and the SAME ROOT CAUSE (duplicate). One matcher
  defect, `methodCall.Matches`, reached by all 16 `pointer-only` aspects. The `bytes.Buffer`
  variants (`Grow`, `WriteString`, `String`) fail identically.
- Mechanism verified by reading the code, not just the failure: `Matches` (method_call.go:63-76)
  takes `call.Fun.(*dst.SelectorExpr)`, checks `selector.Sel.Name`, and then
  `ctx.ResolveType(selector.X)`. `ResolveType` (context.go) returns `c.typeInfo.Types[astExpr].Type`,
  and `types.Info.Types` records *type* expressions as well as values (`TypeAndValue.IsType()`
  distinguishes them, and is never consulted). So `(*bytes.Buffer)` in
  `(*bytes.Buffer).WriteString(&b, s)` resolves to `*bytes.Buffer` and satisfies `pointer-only`.
  The `wrap-expression` template then substitutes `{{ .AST.Fun.X }}` (the type) as the receiver
  and `{{ index .AST.Args 0 }}` (the real receiver) as the data argument; the trailing real
  argument is dropped. There is no `MethodExpr`/`Selections` check anywhere in the pinned tree
  (`git grep MethodExpr|IsType()|Selections 23afa71d6dcb -- internal` is empty), and
  `method_call_test.go` only unit-tests `matchesType` on synthesized types, never a real
  method-expression AST, which is why this shipped.

## Reproduction (my own fixture, independent of the finder's)
Private copy `/tmp/ddiast-review/wt/fx-hooks-yml-strings-F1`, packages installed at
`iast/integration/testapp/zzfx/{builder,buffer,replacer,control}` (the nested module that
already carries `orchestrion.tool.go` with the full IAST tool set, i.e. default configuration).
Fixtures and outputs: `.omo/review/evidence/fx-hooks-yml-strings-F1/zzfx__*`.

Unwoven control (`plain-go1.26.6.txt`):
```
cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -timeout 10m -count=1 -v ./zzfx/...
ok  .../zzfx/buffer  ok .../zzfx/builder  ok .../zzfx/control  ok .../zzfx/replacer   (exit 0)
```
Woven (`woven-go1.26.6.txt`, 55s, peak RSS 0.3 GB):
```
cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -timeout 15m -count=1 -v ./zzfx/...
zzfx/buffer/buffer.go:9: (*bytes.Buffer) (type) is not an expression
zzfx/buffer/buffer.go:9: cannot use &b (value of type *bytes.Buffer) as int value in argument to __orchestrion_iastpropagation.BufferGrow
zzfx/builder/builder.go:10: cannot use &b (value of type *strings.Builder) as byte value in argument to __orchestrion_iastpropagation.BuilderWriteByte
zzfx/replacer/replacer.go:10: (*str.Replacer) (type) is not an expression
zzfx/replacer/replacer.go:10: cannot use r (variable of type *strings.Replacer) as string value in argument to __orchestrion_iastpropagation.ReplacerReplace
FAIL .../zzfx/buffer [build failed]   FAIL .../zzfx/builder [build failed]   FAIL .../zzfx/replacer [build failed]
ok   .../zzfx/control  0.490s
```
The `control` package is a deliberate negative control: direct receiver calls, a method
expression stored in a variable (`f := (*strings.Replacer).Replace`) and a parenthesized
method expression called through a variable all weave and pass. So the break is specific to a
method expression in direct call position, exactly as the mechanism predicts, and the advice
is otherwise healthy.

Go 1.27.0 (`woven-go1.27.0-blocked-by-json.txt`): the woven build stops earlier on the
pre-existing `encoding/json` v2 break (phase1 `base-test-127`), so 1.27 is INCONCLUSIVE as a
run, but the matcher is toolchain-independent and the unwoven code is valid on both.

## Reachability
Reachable in default configuration: yes. No env var, sampling or opt-in gates weaving; the
`package-filter {root: true}` guard means exactly the customer's own root-module packages are
affected, which is the normal case. Any root-module file containing
`(*bytes.Buffer).WriteString(&b, s)`, `(*strings.Builder).Grow(&b, n)`,
`(*strings.Replacer).Replace(r, s)` and so on fails the build; the failure is total for that
package, not a lost-taint edge case, and the customer's only workaround is to rewrite valid Go.
Method expressions on these types are uncommon but legitimate (table-driven tests, generic
helpers, `f := (*bytes.Buffer).WriteString` passed as a function — note the *stored* form is
safe, only the direct call form breaks).

Not a documented limitation. README:39-40 says "Calls through function or method values do not
propagate input taint", which promises a silent no-op for indirect calls; a *compile failure*
for method expressions is neither stated nor implied, and phase1 `01-design-intent.md` has no
such carve-out. Even if it were documented, it violates product rule 1 (never break the host
application, no compile failure on valid customer code).

## Adjusted severity
Critical (unchanged) for both: the brief lists "compile or link failure on valid customer code"
as Critical, and the failure is unconditional, build-breaking, and not opt-out.
`hooks-fidelity-bytes-F1` should be recorded as a duplicate of the same defect rather than a
second issue.

## Root cause (file:line)
- orchestrion `internal/injector/aspect/join/method_call.go:63-76` (`Matches`:
  `recvType := ctx.ResolveType(selector.X)` with no type-expression rejection) at pinned
  `v1.12.2-0.20260828141217-23afa71d6dcb` / `23afa71d6dcb`.
- Enabled by `internal/injector/aspect/context/context.go` `ResolveType`, which returns
  `typeInfo.Types[astExpr].Type` and discards `TypeAndValue.IsType()`.
- Exposed by every `method-call` aspect in `iast/propagation/orchestrion.yml:1057-1552`
  (16 `pointer-only` aspects; the `value-only` twins are unreachable here because all hooked
  methods have pointer receivers). The native `bytes.Buffer` invalidation aspects
  (`:1553-1680`) use `function-body` and are unaffected.

## Minimal fix
In orchestrion, expose the type/value distinction and use it in the matcher:
```go
// context.go: add IsTypeExpression(dst.Expr) bool -> c.typeInfo.Types[astExpr].IsType()
// method_call.go Matches, before ResolveType:
if ctx.IsTypeExpression(selector.X) { return false } // method expression, not a method call
```
Equivalently, match only `typeInfo.Selections[sel].Kind() == types.MethodVal`, which rejects
`MethodExpr` by construction. Add a unit test with a real method-expression AST (the current
`method_call_test.go` only exercises `matchesType`), then bump the dd-iast-go pin and add
`iast/integration/testapp/zzfx`-style woven compile fixtures for Builder, Buffer and Replacer
method expressions plus the direct-call and method-value controls. Nothing can be fixed inside
`iast/propagation/orchestrion.yml` alone: the YAML has no join point that can exclude a type
receiver.

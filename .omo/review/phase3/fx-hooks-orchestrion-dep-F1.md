# fx-hooks-orchestrion-dep-F1: verification of "Operator advice evaluates expressions Go leaves unevaluated"

## Verdict per finding
- **hooks-orchestrion-dep-F1: CONFIRMED.** Adjusted severity: **High** (the original was Critical).
  The mechanism is real and wider than claimed. It covers `len`, `cap`, and single-variable `range` over array operands, slice-to-array-pointer conversions, and string concatenation as well as slices. It produces both runtime panics and compile failures in constant contexts.

## Reproduction
Private copy `/tmp/ddiast-review/wt/fx-hooks-orchestrion-dep-F1` of HEAD 2e23b46, darwin/arm64, `GOFLAGS=-p=4`. My reproducers and captured output are in `.omo/review/evidence/fx-hooks-orchestrion-dep-F1/` (`unevaluated_test.go`, `constctx.go`, `constctx_test.go`, `run-results.txt`).

1. Runtime cases. `unevaluated_test.go` sits in `./fxunevaluated`, and each case recovers from its own panic so a single run reports every case.
   - Plain run: `GOTOOLCHAIN=go1.26.6 go test -timeout 4m -count=1 -v ./fxunevaluated` passes all 5 tests.
   - Woven run: `GOTOOLCHAIN=go1.26.6 /usr/bin/time -l go tool orchestrion go test -timeout 10m -count=1 -v ./fxunevaluated` exits 1 with peak RSS about 311 MB:
     - `len([1]string{short[99:]})`: `PANIC ... slice bounds out of range [99:3]`
     - `cap([2][]byte{shortBytes[5:], nil})`: `PANIC ... slice bounds out of range [5:2]`
     - `len((*[4]byte)(shortBytes[1:]))`: `PANIC ... cannot convert slice with length 1 to array or pointer to array with length 4`
     - `for i := range [2]string{short[99:], ""}`: `PANIC ... slice bounds out of range [99:3]`
     - Control `unsafe.Sizeof(short[99:])`: `--- PASS`. Sizeof stays constant even when its argument contains a call.
2. Compile-break cases in `./fxconstctx`.
   - Plain run: `go vet` and `go test` both pass.
   - Woven run: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 10m -count=1 -v ./fxconstctx` fails:
     - `fxconstctx/constctx.go:7: len([1]string{…}) (value of type int) is not constant` (`const n = len([1]string{s[1:]})`)
     - `fxconstctx/constctx.go:12: len([1]string{…}) (value of type int) is not constant` (the concat form, `a + b`)
     - `fxconstctx/constctx.go:17: array length len([1][]byte{…}) (value of type int) must be constant`
3. The finder's reproducer, re-run woven on Go 1.26.6, gives `panic: runtime error: slice bounds out of range [99:3]` in `propagation.StringSliceLow` at `operators.go:218`. That matches the finder's output.
4. The Go 1.27.0 woven run cannot reach F1. The whole build fails earlier in `encoding/json` weaving (`dec.r undefined`, `dec.d undefined`). That is a separate, unrelated failure; see section E of `run-results.txt`.

## Reachability
- **Default configuration: reachable.** The operator aspects apply to every root-module package (`orchestrion.yml:343-405`, and the concat aspects at `:12-325`). No configuration can turn them off.
- **Independent of whether IAST is active.** The helper slices first and checks the activity gate only afterwards. `operators.go:218` does `result := value[low:]` before `if !operatorbridge.HasValues()`, so the panic happens whether or not IAST is enabled.
- **Spec basis.** "The expressions len(s) and cap(s) are constants if the type of s is an array or pointer to an array and the expression s does not contain channel receives or (non-constant) function calls; in this case s is not evaluated." The `range` exception has the same effect: with at most one iteration variable and a constant `len(x)`, the range expression is not evaluated. Wrapping inserts a non-constant call, which flips both rules.
- **Realism.** The code shapes are valid but uncommon. The panic needs a slice that native Go never evaluates and that would be out of range. The compile break needs `len`/`cap` of an array operand, containing a string slice, byte slice, or concat, used in a constant context. `len((*[N]byte)(b[off:]))` and `for i := range [N]T{...}` are the least exotic forms, and I found no idiomatic library pattern that relies on them.
- **Not documented.** Nothing in the README ("Propagation coverage") or `phase1/01-design-intent.md` mentions unevaluated or constant contexts. It violates product rule 1: no panic, no behavior change, no compile failure on valid code.

## Adjusted severity
**High.** This is a real rule-1 violation, a panic or compile break on valid Go, reachable under default configuration and independent of the IAST gate. By the letter of the scale it is Critical-class. I downgraded it one step because every trigger is an unusual construct that relies on constant or unevaluated operands, and the compile variant fails loudly at build time rather than corrupting results silently. Keep it a release blocker for the Orchestrion pin.

## Root cause (file:line)
- Pinned Orchestrion `internal/injector/aspect/join/slice_expression.go:63-94` (`Matches`) checks only the node's own type and bounds. It never looks at the enclosing context.
- The concat matcher has the same gap: `internal/injector/aspect/join/string_concat.go:83-95` (per the finder; I confirmed the behavior through the concat compile case at `constctx.go:12`).
- dd-iast-go `iast/propagation/orchestrion.yml:343-370` (string slice), `:372-405` (byte slice), and `:12-325` (concat) apply `wrap-expression`, turning an operator expression into a call.
- `iast/propagation/operators.go:216-223` (with siblings for bytes and concat) evaluates the operation unconditionally.

## Minimal fix
In Orchestrion, make the operator join points (`slice-expression`, `string-concat`, and for safety `type-conversion`) reject a node when any ancestor expression is constant. That means `types.Info.Types[ancestor].Value != nil`, which covers constant `len`/`cap` of arrays and `unsafe.Sizeof`/`Alignof`/`Offsetof`. Also reject nodes inside the range expression of a `RangeStmt` that has at most one iteration variable over an array or pointer-to-array with constant length. Add fixtures for each case in this report, both runtime (no panic, same result) and compile (a constant stays constant), before repinning dd-iast-go.

## Duplicates
There is a single finding with a single root cause: enclosing evaluation and constness context is ignored. The operator-integration node's overlapping array-length report (noted in `hooks-orchestrion-dep.md` "Not covered") has the same root cause.

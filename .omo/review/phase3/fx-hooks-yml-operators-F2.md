# fx-hooks-yml-operators-F2: integral float/complex slice bounds break the woven build

## Verdict per finding
- **hooks-yml-operators-F2 - CONFIRMED (Critical).** Independently reproduced with my own
  fixtures on Go 1.26.6: valid customer code using an integral untyped float or complex
  constant as a slice bound fails to compile once woven. Every element of the claim holds,
  including the sub-claim that the matcher's untyped-kind rejection is dead code, and the
  claim that two-index string, two-index byte and three-index full byte slices are all hit.
  Single finding, no duplicates to merge.

## Reproduction
Private copy of HEAD `2e23b46` at `/tmp/ddiast-review/wt/fx-hooks-yml-operators-F2` (now removed);
fixtures and captured output copied to `.omo/review/evidence/fx-hooks-yml-operators-F2/`.

My reproducer is a non-test, production-shaped package (`reviewf2/limits.go`), not a test-only
literal: a `const maxLen = 1e3` size cap used as `s[:maxLen]`, plus `b[0:2.0]`,
`s[complex(1,0):3]` and the three-index `b[0:2:4.0]`.

Plain control (`plain-go1266.txt`):
```
$ GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -timeout 3m -count=1 ./reviewf2
ok  	github.com/DataDog/dd-iast-go/reviewf2	0.306s
```
Woven (`woven-go1266.txt`):
```
$ GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -timeout 3m -count=1 ./reviewf2
reviewf2/limits.go:10: float64 does not satisfy ".../iast/propagation".integer (float64 missing in ~int | ...)
reviewf2/limits.go:17: float64 does not satisfy ".../iast/propagation".integer
reviewf2/limits.go:21: complex128 does not satisfy ".../iast/propagation".integer
reviewf2/limits.go:24: float64 does not satisfy ".../iast/propagation".integer
FAIL	github.com/DataDog/dd-iast-go/reviewf2 [build failed]
```
The error points at the customer's own source line, so the user sees a nonsensical type error in
code they never wrote. Emitted source (`generated-limits.go`, via `go build -work`) shows the
transfer out of index context:
```go
return __orchestrion_iastprop.StringSliceHigh(s, maxLen)   // was: s[:maxLen]
return __orchestrion_iastprop.StringSliceBounds(s, complex(1, 0), 3)
```
Independent mechanism probe (`typeprobe2/main.go`, `typeprobe-go1266.txt`) - `go/types` has already
converted the bounds, so the matcher's untyped guard can never fire:
```
bound=maxLen resolved-type=int value=1000
bound=complex(1, 0) resolved-type=int value=1
```
Go 1.27.0: not testable end to end. `woven-go1270.txt` shows the woven build dying earlier in the
`encoding/json` aspect (`dec.r undefined (type *Decoder has no field or method r)`), a separate
defect outside this node. Nothing in this mechanism is version-specific: the index-context type
loss is language semantics, not a 1.26 quirk.
Woven build peak RSS 338 MB - no build-memory finding.

## Reachability
Reachable under default configuration on a supported toolchain. Weaving happens at compile time,
so `DD_IAST_ENABLED` is irrelevant: the customer's build fails before any runtime gate. Triggering
only needs an untyped float constant (`const maxBody = 1e6`, `1e3`, `2.0`) used as a slice bound -
a legal and reasonably idiomatic way to write size limits. `complex(1,0)` is exotic and can be
ignored for prioritization, but the `1e3`/`2.0` forms carry the finding on their own. There is no
workaround short of editing customer source, and the failure is total for the package.
Not a documented limitation: README "Propagation coverage" and
`.omo/review/phase1/01-design-intent.md` say nothing about untyped-constant slice bounds; the
guard in `slice_expression.go:69-77` shows the intent was to support them, so this is a broken
mitigation, not an accepted trade-off.

## Adjusted severity
**Critical** (unchanged): compile failure on valid customer code is Critical on the brief's scale,
and it violates product rule 1 (never break the host application) with no runtime opt-out.

## Root cause (file:line)
Two halves, both required:
1. `iast/propagation/orchestrion.yml:355-360` (string) and `:384-400` (bytes): the `wrap-expression`
   templates splice `{{ .AST.Low }}/{{ .AST.High }}/{{ .AST.Max }}` verbatim into generic call
   arguments, which discards the index context that forced the constant to `int`. Inference then
   re-defaults it to `float64`/`complex128` against
   `iast/propagation/operators.go:13-15` (`integer` constraint) at the wrappers
   (`operators.go:237 StringSliceHigh`, `:251 StringSliceBounds`, `:287 BytesSliceBounds`,
   `BytesSliceFull`).
2. orchestrion `23afa71 internal/injector/aspect/join/slice_expression.go:69-77`: the intended
   exclusion tests `ctx.ResolveType(bound)` for `types.UntypedFloat`/`types.UntypedComplex`, but
   `go/types` records the *converted* type `int` for an index expression, so the branch is
   unreachable and the join point matches anyway.

## Minimal fix
Preserve the bound's resolved type at the call site instead of re-inferring it: when a bound is a
constant expression, have the advice emit `T(expr)` using the type `go/types` resolved for that
bound (`int(maxLen)`, `int(complex(1, 0))`), leaving nonconstant bounds untouched so named and
unsigned variable bounds keep their own type and their exact panic-message formatting (covered by
the existing `uint64`-max tests). If the orchestrion-side change is undesirable, make the
exclusion actually work - reject any bound whose *declared/default* type (not its index-context
type) is float or complex - and accept the lost propagation for those slices. The dead
`UntypedFloat`/`UntypedComplex` branch should not be left in place either way; it currently
advertises a protection that does not exist.

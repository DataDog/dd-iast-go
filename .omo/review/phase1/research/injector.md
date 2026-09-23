# Orchestrion PR #858: injector lessons for dd-iast-go

This is a comparison, not a proposal to import PR #858. The research branch
`eliottness/iast-testing` explores both source rewriting plus a runtime taint
registry and a patched compiler/runtime with byte-level shadow labels. The
product uses the former kind of instrumentation with its own bounded,
request-scoped propagation engine; the patched compiler is not its toolchain.
The product pins Orchestrion `23afa71d6dcb`, **not** the research branch.

## Expression shapes and advice

- The research `value-operation` join point recognizes nonconstant string
  `BinaryExpr` additions, string/byte/rune conversion calls, explicit
  two-index string and byte slices, indexed-byte-to-string conversion calls,
  built-in `append`, `copy`, and `clear`, and particular byte-index assignments.
  Its scalar cases match only narrow AST forms: local, single-target assignments,
  eligible one-argument calls, and local map/channel operations. It checks
  built-ins by type resolution rather than spelling, so a shadowed `copy` or
  `append` is not woven. See
  `internal/injector/aspect/join/value_operation.go:105-230` and
  `value_operation_ast.go:20-120,180-345` on that branch.
- Research `method-value` matches a captured `receiver.Method` selector;
  `method-expression` matches a captured `(*Type).Method` selector after
  checking `types.MethodExpr`. Both exclude a selector directly used as a
  call target, leaving direct calls to `method-call`. The captured receiver's
  evaluation time differs from an eventual invocation; interception at call
  time alone does not cover a saved method value. See `method_value.go:27-42`,
  `method_expression.go:28-44`, and the matching fixture configs.
- `wrap-expression` substitutes an expression and can pass original AST
  operands into a wrapper. Research `replace-statement` requires exactly one
  output statement; `insert-statements-after` requires a statement in a list,
  compiles a block and inserts its statements in reverse traversal order to
  preserve template order (`advice/replace.go:24-37`,
  `advice/insert_after.go:25-40`). The latter can instrument a local scalar
  extraction after the assignment without reevaluating the *result*, but a
  template referring again to source or index must guard against repeated
  effects. The fixture uses `defer ReleaseByte` and the matcher restricts
  operands to repeatable identifiers, constant expressions or conversions of
  those, excludes loop ancestry, and rejects assignments to nonlocal targets.
- Research templates show what additional coverage would cost:
  `runtime/taint/instrument/orchestrion.yml:47-283` replaces byte writes and
  wraps append/copy/conversions; lines 983-1252 cover scalar lifetime and local
  map/channel transport. These are research-specific runtime APIs, not
  available to dd-iast-go. The product README explicitly excludes creation of
  mutable tainted roots through `[]byte(s)`, `append`, `copy`, `+=` and direct
  byte writes; do not report their absence as an accidental regression.

## Rewriting hazards

1. **Evaluation and panics.** Preserve original operand order and exactly-once
   evaluation of each expression, including slice receiver, low/high/max,
   indexed source and destination, and map key. Capturing an indexed byte in
   a second expression after a mutation may read a *different* byte. A wrapper
   that recomputes a slice or conversion after a side effect may change which
   panic occurs first. In Go, function arguments evaluate before the wrapper
   body: do not move the native operation across that boundary accidentally.
2. **Constants and types.** Compile-time constant `+` expressions cannot be
   turned into runtime calls in a `const` declaration or an array length. A
   helper accepting typed parameters can change defaulting or overflow
   behavior for untyped integer, float, rune, and string constants. Research
   `IsConstant` uses `types.Info.Types[expr].Value`, and product concat uses
   the richer constant-aware `concat.Root`/`Flatten`; the product slice matcher
   deliberately rejects untyped float/complex bounds that its generic integer
   helper cannot accept. Check named types, `~string`/`~[]byte` constraints and
   type parameter inference before rewriting.
3. **Compiler lowering.** The Go compiler combines maximal string-addition
   chains; rewriting each binary subtree independently can create new
   allocations and lose the overall result's provenance. Research
   `string-concat` matches individual additions; the pinned production
   `join/string_concat.go:83-96` instead matches the maximal root and only
   chains of 2-16 operands. Conversions from `[]byte` to string can be elided
   or use temporary storage in comparisons, map keys, calls, concatenations
   and ranges; the pinned `type_conversion.go:44-77` deliberately limits
   eligible contexts to assignment/declaration/return and excludes
   string-to-byte assignments. Preserve representation, lifetime and type
   (including defined result types) if replacing a conversion.
4. **Addressability and scope.** `x[i]` is not automatically addressable if
   `x` is a string, and taking `&value` is invalid for many expression forms.
   Research scalar transport demands addressable arguments and owned local
   targets, and excludes select statements, nested captures and escaping
   local map/channel values (`value_operation_ast.go:180-216,273-395`).
   Injecting metadata by a local variable's address without a reliable
   lifetime/escape policy risks stale taint or cross-owner attribution.
5. **Configuration contract.** Research schema enumerates operation names and
   its test compares the enum with `allValueOperations`
   (`value_operation_test.go:18-64`); product config instead uses
   `string-concat`, `slice-expression` and `type-conversion` from its *pinned*
   Orchestrion version. A research-only join point or advice type is not a
   supported product configuration merely because its YAML parses elsewhere.

## CHECKS for `iast/propagation/orchestrion.yml`

1. Match the exact pinned Orchestrion revision from `go.mod` against each
   `string-concat`, `slice-expression` and `type-conversion` spelling, schema
   and template variable. Never assume PR #858's `value-operation` exists
   there.
2. For concat arities 2 through 16, check that only the maximal nonconstant
   chain is wrapped once, nested/parenthesized and folded constant operands
   remain ordered, and 17+ operands are an explicit coverage limit rather
   than partial propagation. Compare to `operators_concat_test.go` and README.
3. Test named strings and generic `T ~string` with untyped literals; prove
   `ConcatN` returns the original type and calls each effectful operand once.
   Include an inactive request to check that the native result is unchanged.
4. Verify the `bytes -> string` conversion advice preserves the target
   conversion `{{ .AST.Fun }}` and applies only in the assignment, declaration
   and return contexts the pinned matcher permits; separately exercise call
   arguments, map keys and comparisons as documented unsupported contexts.
5. Test string slices with omitted low/high, byte slices with omitted
   low/high/max and three-index capacity, defined types, generic operands,
   non-`int` integer bounds, out-of-range panics and bounds with side effects;
   verify value, panic, length, capacity and exact taint window.
6. Keep product propagation/taint/internal package exclusions consistent
   across all operator aspects so wrappers never advise their own helpers.
   Check `package-filter` root behavior in an instrumented consumer.
7. Check that wrappers do not retain input roots or allocate taint metadata
   on the no-taint fast path; enforce the request/owner limits when active.
   Compare each result's source identity and range across two independent
   requests, not just its string content.
8. Do not copy research `insert-statements-after`/`replace-statement`,
   scalar map/channel or method-value rules into product YAML without
   implementing their runtime contract and testing evaluation order,
   addressability, cleanup, and escape behavior on both supported Go
   toolchains.

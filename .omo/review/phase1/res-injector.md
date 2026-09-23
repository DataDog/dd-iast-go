# res-injector: PR #858 injector lessons
Verdict: No actionable defect established in the reviewed product operator configuration; research branch features are not the pinned product injector.
Scope covered: Orchestrion research `internal/injector/aspect/join/value_operation*.go`, `method_expression.go`, `method_value.go`, `advice/insert_after.go`, `advice/replace.go`, `context/context.go`, `config/schema.json`, scalar and method fixtures, and `runtime/taint/instrument/orchestrion.yml`; pinned Orchestrion `join/string_concat.go`, `slice_expression.go`, `type_conversion.go`, `concat/concat.go`; dd-iast-go `iast/propagation/orchestrion.yml`, `operators.go`, `operators_contexts_test.go`, `operators_concat_test.go`, `operators_slices_test.go`, README and go.mod. Static review only.

## Findings
No findings. Research-only value operations and scalar transport are not product capabilities; documented product exclusions are not defects. See `research/injector.md` for the actionable review checklist.

## Checked and found correct
- The product's 2-16-operand concat aspect definitions correspond to the pinned join point's 2-16 range and maximal-chain selection (`iast/propagation/orchestrion.yml:11-289`; pinned `internal/injector/aspect/join/string_concat.go:22-29,83-96`). Existing instrumented tests cover every advertised arity, two independent sources, and the unsupported 17-operand case. This is a static comparison of rules and tests, not a fresh test run.
- The product conversion rule retains the original target type in `{{ .AST.Fun }}(iastprop.BytesToString(...))` (`iast/propagation/orchestrion.yml:296-308`), while the pinned matcher excludes contexts prone to optimized conversions (`internal/injector/aspect/join/type_conversion.go:44-77`). README describes those excluded contexts; the conversion tests exercise named and generic target types.
- Product slice aspects dispatch separately for omitted bounds and three-index byte slicing (`iast/propagation/orchestrion.yml:310-361`); the pinned join checks string versus byte core types and skips untyped float/complex bounds (`internal/injector/aspect/join/slice_expression.go:63-93`). Existing tests cover the ordinary omitted/full bounds and named/generic operands.
- Research `insert-statements-after` checks list membership and preserves block order on insertion (`internal/injector/aspect/advice/insert_after.go:25-40` on `eliottness/iast-testing`); `replace-statement` rejects a template producing any number of statements other than one (`advice/replace.go:24-37`).

## Not covered / open questions
- No instrumented build or runtime reproducer was run; this review extracts research lessons and compares source/contracts rather than certifying all operator behavior.
- The research branch's modified compiler/runtime, taint registry, and scalar transport semantics are outside product scope. Runtime evaluation-order, panic-order, generic inference, and optimizer differences across Go 1.26.6 and Go 1.27.0 remain subjects for the numbered CHECKS in `research/injector.md`.

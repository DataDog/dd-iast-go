# hooks-yml-operators: Operator semantic preservation

Verdict: Disproved on Go 1.26.6: three Critical defects break valid customer programs, and one High defect adds disabled-path heap allocations.

Scope covered: `iast/propagation/orchestrion.yml:12-405`,
`iast/propagation/operators.go`, `internal/taint/operatorbridge/bridge.go`,
operator tests, `internal/taint/propagation/{operator_concat,conversion}.go`,
`JoinString`, and window/fast-gate paths. Read the pinned Orchestrion concat,
slice, conversion, core-type, template, context-resolution, and import-rewrite
implementation at `23afa71`; inspected its `main...23afa71` changes relevant to
these mechanisms. Applied digest checks 13-16, 23-24 and shadow scenarios
S8-S10, S18, S31, S35.

Target is dd-iast-go HEAD `2e23b46`; runs used Go 1.26.6 on darwin/arm64.
The main checkout was not used for builds or modified outside review output.
No production fixes are included.

## Findings

### hooks-yml-operators-F1: Hooks evaluate array operands that Go leaves unevaluated

- Severity: Critical
- Category: behavior-change
- Location: `iast/propagation/orchestrion.yml:12-31,343-370`;
  pinned Orchestrion `internal/injector/aspect/join/string_concat.go:83-95`
  and `slice_expression.go:63-94`.
- Claim: A nonconstant operator expression can occur inside an unevaluated
  array operand of constant `len`/`cap` or a zero/one-variable array range.
  These matchers examine the operator but do not exclude its unevaluated
  enclosing context. Introducing a function call changes whether Go evaluates
  that enclosing expression. For example, `s := "abc"; high := 99;
  n := len([1]string{s[:high]})` normally returns 1 without slicing.
  Woven code calls `StringSliceHigh` and panics. `for range [1]string{s[:high]}`
  acquires the same new panic. The same cause makes valid
  `const n = len([1]string{text + "x"})`,
  `const n = len([1]string{text[1:3]})`, and an equivalent array length fail
  compilation. This occurs with IAST disabled. Excluding constant *concat
  nodes* does not exclude nonconstant children of a constant `len`.
- Evidence: Sources are
  `.omo/review/evidence/hooks-yml-operators/fixtures/reviewoperators/operators_test.go`
  (`TestUnevaluatedArrayOperands`),
  `fixtures/internal/reviewoperatornative/native.go`, and
  `fixtures/reviewoperators/constantlen/constant.go` under the same evidence
  directory. The exact combined command is
  `REVIEW_WOVEN=1 GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 DD_IAST_ENABLED=false go tool orchestrion go test -work -timeout 3m -count=1 -v ./reviewoperators ./reviewoperators/constantlen ./reviewoperators/floatbounds ./reviewoperators/noimports`,
  run in the private-copy root.
  `isolated-plain-go1266.txt` passes; `isolated-woven-go1266.txt` records both
  `len([1]string{...}) ... is not constant` and
  `array length ... must be constant`. Runtime tests report
  `got=0 want=1 panic="runtime.boundsError: runtime error: slice bounds out of range [:99] with length 3"`
  for both `len` and range. `generated/constantlen/constant.go` and
  `generated/operators_test.go` preserve the emitted calls.
- Fix: Make expression matching aware of unevaluated ancestor contexts and
  leave their entire operands untouched. Preserve the original constant
  `len`/`cap` and array-range evaluation decision, not just the constant value
  of the immediate operator. Add both compile and runtime fixtures.

### hooks-yml-operators-F2: Integral floating-point and complex slice bounds stop compiling

- Severity: Critical
- Category: compile-break
- Location: `iast/propagation/orchestrion.yml:360,389`;
  `iast/propagation/operators.go:13-15,237,287`;
  pinned Orchestrion `internal/injector/aspect/join/slice_expression.go:69-77`.
- Claim: Go permits integral untyped constants such as `1.0`, `3.0`, and
  `complex(1, 0)` as slice indices. Advice transfers them from an index
  context into generic function arguments without retaining their contextual
  `int` type. Type inference consequently chooses `float64` or `complex128`,
  which cannot satisfy the wrapper's `integer` constraint. The matcher's
  attempted rejection of `types.UntypedFloat`/`types.UntypedComplex` does not
  work: `go/types` has already assigned `int` to those index expressions.
  Both string and full byte slicing are affected.
- Evidence:
  `.omo/review/evidence/hooks-yml-operators/fixtures/reviewoperators/floatbounds/float_test.go`
  contains `s[1.0:3.0]`, `s[complex(1, 0):3]`, and `b[1.0:3.0:4.0]`.
  Run the combined command above, or
  `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 3m -count=1 ./reviewoperators/floatbounds`.
  The final plain run passes; `isolated-woven-go1266.txt` captures
  `float64 does not satisfy ... integer` and
  `complex128 does not satisfy ... integer`.
  `fixtures/reviewoperators/typeprobe/main.go`, executed with
  `GOTOOLCHAIN=go1.26.6 go run ./reviewoperators/typeprobe`, produces
  `resolved-type=int constant=1` and `resolved-type=int constant=3`
  in `typeprobe-go1266.txt`. The emitted erroneous calls are in
  `generated/floatbounds/float_test.go`.
- Fix: Preserve each constant bound's resolved index type when generating
  arguments, rather than letting generic inference default it again.
  Preserve the original types of nonconstant signed/unsigned bounds.
  Alternatively, reliably exclude these constant shapes before rewriting.

### hooks-yml-operators-F3: Operator instrumentation crashes the weaver on import-free packages

- Severity: Critical
- Category: compile-break
- Location: `iast/propagation/orchestrion.yml:13-31`;
  pinned Orchestrion `internal/toolexec/aspect/oncompile.go:195` and
  `internal/toolexec/importcfg/importcfg.go:52-81`.
- Claim: A valid root package with no imports now needs the injected
  propagation import as soon as it contains one of these operators.
  Orchestrion parses its empty import configuration into a nil
  `PackageFile` map. After resolving the injected dependency, `OnCompile`
  assigns into that nil map. Thus even a small import-free string helper
  package cannot be built with the pinned instrumentation.
  This is a pinned-dependency integration defect, not a runtime taint panic;
  the brief still classifies valid-program compile failures as Critical.
- Evidence:
  `.omo/review/evidence/hooks-yml-operators/fixtures/reviewoperators/noimports/noimports.go`
  is an import-free package containing concat, slicing, and conversion.
  The final plain command succeeds. The combined woven command above, or
  `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 3m -count=1 ./reviewoperators/noimports`,
  fails. `isolated-woven-go1266.txt` captures
  `panic: assignment to entry in nil map`, with
  `Weaver.OnCompile ... oncompile.go:195`, followed by
  `reviewoperators/noimports [build failed]`.
  `generated/noimports/noimports.go` records the injected import and calls.
- Fix: Initialize the import configuration's `PackageFile` map before adding
  synthetic imports, and update the dependency pin with that fix. Add an
  import-free root-package fixture; packages already importing libraries do
  not exercise this case.

### hooks-yml-operators-F4: Disabled operator wrappers force avoidable heap allocations

- Severity: High
- Category: perf
- Location: `iast/propagation/operators.go:18-26,198-204`;
  `iast/propagation/orchestrion.yml:23-31,337-341`.
- Claim: The activity gate is too late to preserve native escape behavior.
  `Concat2` computes `a+b` and passes the result to a propagation-capable
  helper; `BytesToString` similarly passes `string(value)` to code that can
  retain its result. Nonescaping customer expressions that need no heap
  allocation natively allocate once per operation even when
  `operatorbridge.HasValues()` is false and IAST is disabled. This affects
  ordinary `len(a+b)`, `a+b == "abcdef"`, and a locally assigned conversion
  used only by `len`. The allocation contract is explicit in the Phase 6
  plan at lines 129-131 and 344-346. This is a hot-path allocation regression,
  not a noisy wall-clock comparison or the accepted writer-escape trade-off.
- Evidence:
  `.omo/review/evidence/hooks-yml-operators/fixtures/reviewoperators/operators_test.go`
  (`TestInactiveAllocations`) compares woven expressions against identical
  excluded native helpers in `fixtures/internal/reviewoperatornative/native.go`.
  It first asserts that the activity gate is false and uses
  `testing.AllocsPerRun(100, ...)`.
  Run the combined woven command above, or
  `REVIEW_WOVEN=1 GOTOOLCHAIN=go1.26.6 DD_IAST_ENABLED=false go tool orchestrion go test -timeout 3m -count=1 -v -run 'Test(WeavingPreflight|InactiveAllocations)' ./reviewoperators`.
  `isolated-woven-go1266.txt` records
  `native=0 woven=1 allocations/op` for `concat_len`, `concat_compare`, and
  `conversion_local`. The corresponding plain run records 0/0.
  Direct comparison and map-key conversion controls remain 0/0, showing
  their documented exclusion works. `generated/operators_test.go` records
  precisely which expressions became calls.
- Fix: Preserve a native nonescaping fast path at the application call site,
  before passing results to retaining propagation code, or narrow the
  join-point allowlist to contexts demonstrated to preserve allocation
  behavior. Require zero additional allocations for nonescaping disabled
  concat and conversion fixtures, not only escaping global-result benchmarks.

## Checked and found correct

- `TestWeavingPreflight` confirms `woven=false` in the plain run and
  `woven=true` in the instrumented run. Generated sources independently
  confirm the matches; the native control package remains outside the
  eligible scope.
- Ordinary constant concatenation remains constant in `const`, array-size,
  and switch-case uses. A folded `"x" + "y"` subtree stays a single operand
  of the surrounding three-operand generic concat. F1 concerns enclosing
  unevaluated contexts, not ordinary constant folding.
- Custom tests preserve once-only lexical call order for
  `f(1)+(f(2)+f(3))` and a full byte slice with side-effecting base, low,
  high, and max expressions. Named strings/bytes, `T ~string`, `T ~[]byte`,
  and a named `uint16` bound compile and return the expected types/values.
- Thirty-five native/woven slice comparisons cover negative bounds,
  high beyond length/capacity, low greater than high, high greater than max,
  max beyond capacity, and `uint64` maximum. Recovered panic types and exact
  messages agree, including unsigned formatting. Full-slice capacity is
  preserved. F1 creates evaluation where none existed; it does not change
  the error text of an already evaluated slice.
- Custom active-source checks preserve exact offsets, lengths, source name,
  and full source value through substring-to-concat and named byte-to-string
  conversion. Byte-identical clean literals remain clean. The 17-operand
  chain and `+=` remain safe misses.
- Existing woven operator tests pass with exit 0:
  `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=2 DD_IAST_ENABLED=false go tool orchestrion go test -timeout 5m -count=1 -v -run 'Test(Operator|NativeOperator|NativeBytesToString|UnsupportedNativeOperator)' ./iast/propagation`.
  `existing-operators-go1266.txt` covers all 2-16 concat arities, two-source
  offsets and marks, all omitted-bound/full-slice shapes, named/generic
  conversion assignment/declaration/return forms, and unsupported-context
  controls. These tests do not cover the four regressions above.
- The bridge itself is one atomic counter load. Operator aspect exclusions
  are consistent for propagation implementation, public taint, and internal
  packages. These observations do not resolve the escaping-result overhead.

## Not covered / open questions

- No universal proof is claimed: executed coverage is Go 1.26.6 darwin/arm64,
  not Go 1.27, 32-bit, or every constraint hierarchy. Imported inaccessible
  defined types were not added to this node's executable fixtures.
- No wall-clock benchmark or latency multiplier was measured on the shared
  machine. F4 is supported by deterministic allocation counts. The full
  repository suite, race/checkptr suite, and sustained contention were not
  rerun; this node ran the focused existing and added operator tests.
- LSP diagnostics were unavailable because its daemon could not be reached.
  Actual compiler output and test execution supplied the evidence.
- Documented misses for mutable aliases, optimized conversion contexts,
  `+=`, and long concatenation chains are not reported as bugs.
- Evidence setup, exact reproduction commands, toolchain revisions, original
  fixtures, and emitted code are preserved in
  `.omo/review/evidence/hooks-yml-operators/README.md` and its sibling files.

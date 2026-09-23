# Operator review evidence

Target: dd-iast-go `2e23b4614320defd0d32177a69888dcab73f4d11`.
Pinned Orchestrion: `23afa71d6dcb13cc221c6461745229779e7674b4`.
Executed toolchain: `go version go1.26.6 darwin/arm64`.

All compilation and testing ran in
`/tmp/ddiast-review/wt/hooks-yml-operators`, not the main checkout.
The private copy is removed at review completion.

## Reproduce

Restore the fixtures into a new private copy of the target:

```sh
repo=/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go
work=/tmp/ddiast-review/wt/hooks-yml-operators
mkdir -p "$work"
rsync -a --exclude .git --exclude .omo "$repo/" "$work/"
cp -R "$repo/.omo/review/evidence/hooks-yml-operators/fixtures/." "$work/"
mkdir -p "$work/tmp"
cd "$work"
export TMPDIR="$work/tmp"
export GOTOOLCHAIN=go1.26.6 GOMAXPROCS=2 GOFLAGS=-p=2 DD_IAST_ENABLED=false

# Passes: exit 0.
go test -timeout 3m -count=1 -v \
  ./reviewoperators ./reviewoperators/constantlen \
  ./reviewoperators/floatbounds ./reviewoperators/noimports

# Fails as documented: exit 1.
REVIEW_WOVEN=1 go tool orchestrion go test -work -timeout 3m -count=1 -v \
  ./reviewoperators ./reviewoperators/constantlen \
  ./reviewoperators/floatbounds ./reviewoperators/noimports

# Contextual type probe: exit 0, both bound types print int.
go run ./reviewoperators/typeprobe

# Existing operator coverage: exit 0.
go tool orchestrion go test -timeout 5m -count=1 -v \
  -run 'Test(Operator|NativeOperator|NativeBytesToString|UnsupportedNativeOperator)' \
  ./iast/propagation
```

The comparison package `internal/reviewoperatornative` is deliberately excluded
by the existing `internal/**` aspect filter. It provides native operations in the
same instrumented test binary. `TestWeavingPreflight` requires
`built.WithOrchestrion` to agree with `REVIEW_WOVEN`, so the woven run cannot
silently pass as a plain build. All allocation measurements use
`testing.AllocsPerRun(100, ...)`, not wall-clock timings.

## Files and outcomes

- `isolated-plain-go1266.txt`: final fixture layout; all four packages pass.
- `isolated-woven-go1266.txt`: the same sources produce compile failures in
  `constantlen` and `floatbounds`, a weaver panic in `noimports`, new runtime
  panics in `TestUnevaluatedArrayOperands`, and three allocation regressions in
  `TestInactiveAllocations`. The remaining runtime checks pass.
- `typeprobe-go1266.txt`: `go/types` resolves the integral floating-point and
  complex slice-bound constants to `int`, explaining why the pinned matcher's
  untyped-type exclusion fails.
- `existing-operators-go1266.txt`: seven existing top-level operator tests pass,
  including all 15 concatenation arities, precise ranges and marks, slice
  shapes, conversion contexts, and unsupported-path controls.
- `fixtures/`: complete final reproducer sources, with their original relative
  paths. No production code was changed.
- `generated/`: emitted source from the final woven build, copied before
  scratch cleanup. This is evidence, not source to restore into the application.
- `plain-go1266.txt`, `woven-go1266.txt`: first exploratory run. At that point
  the floating-point/complex bounds were still in the main test package and
  `constantlen` had no imports. The final run splits these into independent
  packages so one compile failure does not hide the runtime regressions.

LSP diagnostics could not run because the local LSP daemon was unreachable.
The compiler and executed tests supplied validation. No wall-clock benchmark,
full repository suite, race suite, or Go 1.27 comparison was run by this node.

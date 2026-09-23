# Independent reproduction: hooks-yml-operators-F1

Target: dd-iast-go HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.
All commands ran in the private copy
`/tmp/ddiast-review/wt/fx-hooks-yml-operators-F1`, with `GOFLAGS=-p=2`,
`DD_IAST_ENABLED=false`, and temporary/build caches under that copy.

## Fixtures

- `fixtures/reviewfxoperators/operators_test.go` checks that array `len` and
  array `range` skip evaluation of an out-of-range string slice.
- `fixtures/reviewfxoperators/constantlen/constant.go` checks that a valid
  constant array length remains constant when its array element contains a
  string slice. The package imports `strings` blankly to avoid the unrelated
  import-free-package weaver failure.

The first constant-length probe used `const text = "abcd"` and stayed
uninstrumented: the pinned matcher excludes untyped string constants. The final
fixture uses a typed `var text string`; plain Go still accepts the constant
length, while weaving introduces a function call and rejects it.

## Results

- `go1266-plain.txt`: Go 1.26.6 passes the runtime tests and compiles the
  constant-length package without instrumentation.
- `go1266-woven-runtime.txt`: Go 1.26.6 woven tests fail because both `len`
  and `range` evaluate `s[:high]` and panic.
- `go1266-woven-constantlen.txt`: Go 1.26.6 woven build rejects the constant
  array length.
- `go1270-plain.txt`: Go 1.27.0 plain tests pass.
- `go1270-full-config-blocker.txt`: the first full-config Go 1.27.0 woven
  attempt stops in the separate JSON aspect before reaching the fixture.
- `fixtures/go1270-propagation-only/orchestrion.tool.go` is the private
  propagation-only tool configuration used for the isolated Go 1.27.0 retry.
- `go1270-woven-runtime-isolated.txt` and
  `go1270-woven-constantlen-isolated.txt` capture the same failures under
  Go 1.27.0.

Each output file records its command and the relevant captured output. Woven
commands used `/usr/bin/time -l`; all recorded maximum RSS values were below
4 GB.

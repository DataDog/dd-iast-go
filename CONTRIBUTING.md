# Contributing to Datadog IAST for Go

Thank you for your interest in contributing. Bug fixes are welcome. Before you
start a new feature or change existing behavior, open an
[issue](https://github.com/DataDog/dd-iast-go/issues) so that the design and
scope can be agreed on before implementation.

## Development setup

This repository requires the Go version declared in [`go.mod`](go.mod). Clone
the repository, then download the dependencies for the main module and the
overhead benchmark module:

```console
go mod download
go -C benchmarks/overhead mod download
```

The tools used by this repository are declared in `go.mod`. Go installs and
runs them when you use commands such as `go tool orchestrion` and
`go tool checklocks`.

## Design requirements

This module is added to customer applications at compile time with
[Orchestrion](https://github.com/DataDog/orchestrion). Its code can run in hot
loops and on critical application paths. Changes must follow these rules:

- Never cause the host application to panic.
- Keep runtime and allocation overhead as low as practical.
- Do not retain memory longer than needed.
- Keep accurate provenance during taint propagation.
- Bound all data storage. When a limit is reached, drop data instead of blocking
  the host application.
- Put a cheap eligibility check before expensive work when possible.

Add tests for new behavior and for bug fixes. Consider error paths, concurrency,
memory bounds, and behavior under excessive load.

## Formatting and generated code

Run `gofmt` on every modified Go file:

```console
gofmt -w <modified-go-files>
```

Do not edit files that contain a `Code generated` header. Change their source
files and regenerate them instead. For MessagePack model changes, run:

```console
go generate ./internal/model/...
```

Commit the generated files with their source changes.

## Testing

Some tests require compile-time instrumentation. Run the main test suite through
Orchestrion:

```console
go tool orchestrion go test -shuffle=on ./...
```

Run the tests for the separate overhead benchmark module as well:

```console
go -C benchmarks/overhead test -shuffle=on ./...
```

A test that depends on injected instrumentation must clearly skip when it was
not built with Orchestrion:

```go
import "github.com/DataDog/orchestrion/runtime/built"

func TestName(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}

	// ...
}
```

This skip is not needed for unit tests that do not require instrumentation.

### External test packages for injectable code

Orchestrion can fail to link a coverage-instrumented for-test package variant
when tests use the same Go package as injectable production code. If the error
asks for a dedicated `*_test` package, use Go's external test package pattern:

- keep the `*_test.go` files in the same directory as the tested package;
- change their package clause from `package example` to
  `package example_test`; and
- do not create a separate directory named `example_test` or move the tests to
  an unrelated package.

An external test package can access only exported symbols. If a test needs
unexported logic, move that logic to an appropriate package under `internal/`
and export it from that internal package. Import the internal package from both
the production package and its external tests. Do not expand the original
package API only for tests.

```console
go tool orchestrion go test \
  -shuffle=on \
  -covermode=atomic \
  -coverpkg=./... \
  ./...
```

Before you submit a pull request, run the same static checks as CI:

```console
go tool checklocks ./...
go -C benchmarks/overhead vet ./...
```

CI also checks formatting, licenses, test coverage, runtime overhead benchmarks,
and system tests.

## Instrumentation changes

Instrumentation definitions are stored in `orchestrion.yml` files. When you add
or remove one under `iast`:

1. Update the imports in the repository-root
   [`orchestrion.tool.go`](orchestrion.tool.go). It must import every Go package
   under `iast` that contains an `orchestrion.yml` file, and no package whose
   definition was removed.
2. Update the vulnerability table in [`README.md`](README.md), including the
   package import path for implemented vulnerability types.
3. Add tests that prove the instrumentation is injected and reports the expected
   result when built with Orchestrion.

Keep aspect advice small. Avoid adding work to instrumented application paths
unless it is required for the detection.

## Performance changes

Use the overhead benchmark runner when a change can affect runtime cost or
allocations:

```console
go -C benchmarks/overhead run ./runner
```

For a quick smoke run:

```console
go -C benchmarks/overhead run ./runner -count=2 -benchtime=100ms
```

See [`benchmarks/overhead/README.md`](benchmarks/overhead/README.md) for the
available workloads, output files, and guidance for interpreting results.

## Pull requests

Keep each pull request focused. Its title must use
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) format:

```text
<type>(<scope>): <description>
```

For example:

```text
fix(taint): preserve ranges after string concatenation
```

In the pull request description:

- explain the problem and why the change is needed;
- describe the chosen approach and important trade-offs;
- link related issues;
- state how you tested the change; and
- include benchmark results when performance can change.

All required CI checks must pass before a pull request can be merged. Reviewers
may request changes to preserve application safety, bounded memory use, taint
provenance, compatibility, or runtime performance.

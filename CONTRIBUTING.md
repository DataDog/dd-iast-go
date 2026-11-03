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
runs them when you use commands such as `go tool orchestrion`,
`go tool otelc`, and `go tool checklocks`.

## Design requirements

This module is added to customer applications at compile time with
[Orchestrion](https://github.com/DataDog/orchestrion) or with
[otelc](https://github.com/open-telemetry/opentelemetry-go-compile-instrumentation).
Its code can run in hot loops and on critical application paths. Changes must
follow these rules:

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

Some tests require compile-time instrumentation. These tests must pass with
both tools. CI runs them with both.

Run the main test suite through Orchestrion:

```console
go tool orchestrion go test -shuffle=on ./...
```

Run the tests that require instrumentation through otelc:

```console
scripts/otelc-test.sh -shuffle=on
```

The script gives all the otelc rule files of this module to otelc, and runs
`go tool otelc go test` one time for each package that requires
instrumentation. A plain `go tool otelc go test ./...` does not work in this
module. Read the comments in [`scripts/otelc-test.sh`](scripts/otelc-test.sh)
for the reasons. The script uses a separate Go build cache
(`$(go env GOCACHE)-otelc`; set `OTELC_TEST_GOCACHE` to an absolute path to use a
different directory), because otelc and Orchestrion must not share a build cache.

Run the end-to-end tests in `_integration/otelc` with both tools. The modules
in `_integration/otelc/setups` import only a part of this module, and only
otelc supports them. Use a separate `GOCACHE` for each tool (see
[`_integration/otelc/doc.go`](_integration/otelc/doc.go)):

```console
go -C _integration/otelc tool orchestrion go test -shuffle=on . ./internal/...
go -C _integration/otelc tool otelc go test -shuffle=on . ./internal/...
go -C _integration/otelc/setups/hashonly tool otelc go test -shuffle=on ./...
go -C _integration/otelc/setups/rootandhash tool otelc go test -shuffle=on ./...
```

Run the tests for the separate overhead benchmark module as well:

```console
go -C benchmarks/overhead test -shuffle=on ./...
```

A test that depends on injected instrumentation must clearly skip when it was
not built with Orchestrion or otelc. Use `build.Instrumented()` from
`internal/build`. It is true for both tools. Do not use
`built.WithOrchestrion`: it is false when the test is built with otelc.

```go
import "github.com/DataDog/dd-iast-go/internal/build"

func TestName(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("the build is not instrumented, use `go tool orchestrion go test` or `scripts/otelc-test.sh` to run this test suite")
	}

	// ...
}
```

This skip is not needed for unit tests that do not require instrumentation.

`scripts/otelc-test.sh` finds the packages to test from this import: it tests
each package whose tests import `internal/build`. A test that requires
instrumentation, but does not import `internal/build`, does not run with
otelc.

Do not use features that only one tool has in a test that requires
instrumentation. For example, do not use the `//dd:span` directive (an
Orchestrion feature). Start the span explicitly with
`tracer.StartSpanFromContext`, and finish it.

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

CI also checks formatting, licenses, test coverage, end-to-end tests with both
tools, runtime overhead benchmarks, and system tests.

## Instrumentation changes

Each instrumentation is defined two times: one time for Orchestrion
(`orchestrion.yml`) and one time for otelc (`otelc.yml`, with an
`otelc_decl_<package>.go` file for each target package when necessary). The two
definitions must give the same detections (feature parity): the same targets,
the same sinks, the same sink counts, and the same reported data. Reviewers
must check this. Do not add, change, or remove an aspect for one tool only.

Put the detection logic in shared Go code in the package (for example
`hash.ReportWeakHash`), and call it from both definitions. Keep the code that
is specific to one tool (the YAML rules and the injected code) as small as
possible.

When you add or remove an instrumentation package under `iast`:

1. Add or remove both `orchestrion.yml` and `otelc.yml`.
2. Update the imports in the repository-root
   [`orchestrion.tool.go`](orchestrion.tool.go). It must import every Go package
   under `iast` that contains an `orchestrion.yml` file, and no package whose
   definition was removed. Do not import `iast` packages from
   [`otel.instrumentation.go`](otel.instrumentation.go): otelc already loads
   all the `otelc.yml` files of this module when an application imports the
   root package.
3. Update the vulnerability table in [`README.md`](README.md), including the
   package import path for implemented vulnerability types.
4. Add tests that prove the instrumentation is injected and reports the expected
   result when built with Orchestrion and with otelc: unit tests in the package
   (run with both tools, see [Testing](#testing)), and end-to-end checks in
   `_integration/otelc/internal/suite`.

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

The runner builds with Orchestrion by default. Use `-tool=otelc` to build with
otelc. CI runs the benchmarks with both tools. Check that a change has a
similar overhead with both tools.

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

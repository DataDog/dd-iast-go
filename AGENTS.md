# Agent Instructions

The @README.md file contains a high-level description of the module, and can be
consulted to obtain general information about the intent and purpose of this
code.

## Operating Constraints

This package is designed to be hooked into customer code-bases at compilation
time using [orchestrion]. This implies this code might run in hot loops or
within the critical path of the customer's application. In light of this, all
code in this module MUST abide by the following rules:

- NEVER break the host application (e.g, by causing a `panic`)
- NEVER slow down the host application more than strictly necessary
- NEVER leak memory or hold onto memory for longer than is necessary
- ALWAYS keep accurate provenance information through taint propagation

As a consequence of these principles:
- this codebase prefers dropping data when under excessive load over blocking;
  and all expensive operations are gated by a cheap check (e.g,
  `CanBeTainted(value)`);
- all data storage must guarantee a maximum memory footprint that will never be
  exceeded, and we can accept dropping data if the allowed storage is saturated.

## Project Structure

- `/iast/` contains sub-directories for each kind of IAST vulnerability
  supported by this package. These directories contain the `orchestrion.yml`
  files, and all packages containing one such `orchestrion.yml` file is imported
  from `orchestrion.tool.go` at the package root. This gives users an easy way
  to bring in all supported instrumentation while keeping the flexibility to
  only enable the things they want.
- `/internal/` contains all implementation details not intended for external
  consumption. Those details are those that are not necessary to implement new
  IAST detections externally to this package (but building on public features
  from it).
- `/taint/` contains all the taint tracking machinery; exposing a simple API
  that instrumentation will use to track untrusted values through the program
  flow.

## Plans

Before implementing any significant feature:
1. a detailed plan should be created and stored under `_docs/plans/<slug>.md`
2. the plan is to be reviewed by a critic sub-agent (if possible from another
   provider and with maximum effort budget), and refined until both agents agree
   the plan is solid
3. the plan is to be reviewed by the user, and refined until the user agrees the
   plan is solid
4. the plan is to be committed yo the repository with a commit message which
   title is of the form `wip(plan): <feature tag line>`

Then, once the feature is implemented, and the user is satisfied with the
delivered code; the plan should be deleted from `_docs/plans`. This way, the
plan exists in the history of the pull request, but does not stay permanently
in the codebase where it would be dead weight.

## Pre-Commit Validation

Before committing any change:

- run `gofmt` on every modified Go file;
- run all applicable linters and checkers and fix every reported issue; and
- do not commit until all applicable validation completes cleanly.

## Testing

### Orchestrion gating of instrumentation packages

Tests that require compile-time instrumentation must be run with [orchestrion],
so the correct way to execute them is to use the following command pattern:

```console
$ go tool orchestrion go test <go test args ...>
```

In order to be friendlier to users, such tests must begin with a conditional
skip instructing the user on how to properly run the suite if [orchestrion] was
not properly used:

```go
import "github.com/DataDog/orchestrion/runtime/built"

func TestName(t *testing.T) {
  if !built.WithOrchestrion {
    t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
  }

  // ...
}
```

This does not apply to mere unit tests which do not require any compile-time
instrumentation to be injected.

[orchestrion]: https://github.com/DataDog/orchestrion

### Testing of injectable packages

Many packages in this module will be injected by orchestrion as new dependencies
of instrumented packages. This can cause issues when testing those packages with
coverage instrumentation, as a coverage-instrumented for-test variant of the
package may be built in addition to a regular coverage-instrumented variant, and
the right one must be selected for linking.

In some situations, orchestrion cannot technically create the correct package
version to inject if the tests are in the same package as the tested code, and
the build fails with a message indicating tests should be moved to a dedicated
`*_test` package. When doing so, un-exported members that were being tested
should usually be moved to a new `internal/` package instead of being exported
in-place (as this would increase the locally available API surface purely for
testing purposes).

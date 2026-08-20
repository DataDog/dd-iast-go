# Improve Go test coverage

## Objective

Increase useful test coverage with deterministic unit tests that protect stable
behavior. Do not add tests that only execute lines without checking externally
observable results or package contracts.

## Evidence and baseline

Datadog MCP reports `47.41%` total coverage for `main` at head commit
`80a3f5dda33b8b381e28ad58f0ede32f9b17da24`. This differs from the `43.56%`
reported in the task, but both reports identify the same broad coverage deficit.
The Datadog per-file report identifies these low-coverage files as the clearest
unit-test candidates:

- `internal/instrumentation/telemetry/telemetry.go`: only the entry line of each
  iterator is covered. The early-stop branch after every yielded metric remains
  uncovered. Existing tests also leave randomized values in global counters,
  which is poor isolation under shuffled test execution.
- `internal/model/constants/origin.go`: the enum-to-wire-value conversion,
  parsing, and JSON behavior are mostly uncovered.
- `internal/model/constants/vulnerabilitytype.go`: the enum-to-wire-value
  conversion, parsing, and JSON behavior are mostly uncovered.
- `internal/config/config.go`: environment parsing defaults, malformed values,
  and numeric boundaries are only partly covered.

A local non-instrumented baseline (`go test ./... -coverprofile=...`) reports
`32.0%`. Package coverage is `0.0%` for `internal/config` and
`internal/model/constants`, and `50.0%` for
`internal/instrumentation/telemetry`. Instrumentation-dependent sink tests skip
without Orchestrion, so the authoritative final coverage run must use
`go tool orchestrion go test`.

## Selected test surface

### Test-package and Orchestrion compatibility

Start tests in the package that gives them the narrowest necessary access.
Configuration, model constants, and event admission tests initially use their
production package because they exercise unexported behavior; telemetry tests
remain in the existing external `telemetry_test` package.

Validate the package layout early with the exact Orchestrion coverage command.
If Orchestrion cannot link a coverage-instrumented package because an in-package
test creates a for-test package variant, move the affected tests to the
corresponding `*_test` package. If those tests still need unexported logic, move
that logic to a narrowly scoped new `internal/` package and test it there rather
than exporting production symbols only for tests. Keep any such extraction
behavior-preserving and include it in the specialist review.

### 1. Configuration parsing

Add package-internal table-driven tests in `internal/config` for:

- every accepted telemetry log level, its exact case-sensitive syntax, and a
  rejected value;
- valid and invalid regular expressions;
- boolean defaults, accepted values, empty values, and malformed values;
- unsigned integer defaults, accepted values, an explicit empty value,
  malformed lexical forms, overflow, and bounded lower/upper clamping;
- generic parser defaults, accepted values, and parse failures, including the
  security-visible current behavior that an explicitly empty redaction pattern
  is a valid regexp that matches every string.

Assertions will cover returned values and, where exposed by
`uintFromEnvNoTelemetry`, telemetry origin for unset, valid, empty, malformed,
and overflowing inputs. The origin attached by the higher-level bounded helper
is observable only through `dd-trace-go` instrumentation internals; tests will
not couple to those internals. A sentinel-guarded subprocess test
will start a fresh test binary with default, valid, and invalid/clamped
configuration environments. It will verify that package initialization wires
all documented environment variables to the public configuration globals.
This avoids pretending that direct helper tests cover init-time configuration.
The child process exists for behavioral isolation; its execution is not
expected to contribute to the parent coverage profile, while package init also
runs in the covered parent binary. The branch fixes the environment variable
typo: the supported spelling is now `DD_IAST_DB_ROWS_TO_TAINT`. The
initialization test will assert this literal
value and verify that the former `DD_IAST_DB_ROWS_TO_TAIN` spelling is not
accepted as an alias. Validation will also confirm that the repository-root
configuration documentation uses the corrected spelling. The unused
`stringFromEnv` helper will not receive a line-driving test.

Tests will use `t.Setenv` or an explicitly filtered subprocess environment,
restore process environment through test cleanup, and will not run in parallel
because environment state and instrumentation registration are process-global.

### 2. Model enum serialization contracts

Add exhaustive in-package (`package constants`) table-driven tests in
`internal/model/constants` for every `Origin` and `VulnerabilityType` value so
that package-private parsers and test helpers can be checked directly. Each
table will define the constant
name and its wire representation, then verify:

- the literal protocol cardinalities (18 origins and 36 vulnerability types),
  table length, and bidirectional contents of `AllOrigins` or
  `AllVulnerabilityTypes`;
- `String` output;
- JSON marshal/unmarshal round trips for every valid value;
- MessagePack marshal/unmarshal round trips for every valid value, including
  prefix/remainder handling and the `Msgsize` upper-bound contract;
- invalid enum fallback formatting and rejection of unknown, `null`, wrong-type,
  or malformed serialized values.

The exhaustive tables intentionally duplicate the protocol mapping. This makes
an accidental wire-format change fail visibly and makes additions require an
explicit test decision. A defensive test will exercise every `uint8` value
through the non-test-only formatting and marshaling methods and assert that no
value panics. Invalid values are not expected to round-trip: they format to a
fallback string that the parsers reject. Tests will assert the error without
pinning incidental receiver-mutation behavior after a failed unmarshal. The
private `name` methods are excluded from the never-panic assertion because they
are explicitly test helpers and are only called with values bounded by the
count constants.

### 3. Telemetry iterator cancellation

Extend `internal/instrumentation/telemetry/telemetry_test.go` to verify the
range-over-function cancellation contract for every possible stopping point in
both source and sink iterators. Capture each iterator's complete order once;
then each subtest will use actual `for ... range iterator` syntax, break at a
selected metric, and assert the visited values equal the corresponding captured
prefix. Also assert that the complete-order set equals the exhaustive model
constant set. This avoids declaring the current order a public contract while
still catching a missing `return` after any `yield` call, which would invoke a
stopped range iterator and panic. One direct callback test per iterator will
also verify that returning `false` stops further callbacks for callers that do
not use range syntax.

Existing reflection-based tests will continue to verify field completeness and
counter identity. They will register cleanup before mutating counters and reset
all touched global counters to prevent state leakage under `-shuffle=on`. New
tests will not mutate the build-time `InstrumentedSource` or `InstrumentedSink`
maps.

### 4. Event admission behavior

Add focused in-package (`package model`) tests in
`internal/model/event_test.go` for:

- `NewEvent` allocation using the configured request limit;
- vulnerability de-duplication when enabled;
- duplicate admission when de-duplication is disabled;
- rejection at the per-request limit without modifying the event, growing its
  capacity, or bypassing the limit to perform de-duplication.

The tests will assert that the first duplicate remains stored and that the
limit check takes precedence over de-duplication. These tests protect the
bounded-storage behavior required by the repository and restore
package-global configuration with test cleanup. They will not run in parallel.

## Explicitly excluded

- Do not add direct line-coverage tests for generated `*_gen.go` files. Datadog
  ignores generated files, and serialization is covered through public
  round-trip contracts instead.
- Do not test private logging implementation details or couple tests to
  `dd-trace-go` internals.
- Do not broaden this change into production refactoring, except for a minimal
  behavior-preserving move to a new `internal/` package if Orchestrion requires
  external `*_test` packages.
- Do not add timing-sensitive, randomized, or snapshot-only tests.

## Validation

1. Run `gofmt` on every modified Go file.
2. Run focused tests for each modified package, including shuffled execution.
3. Run `go test -race` for each modified package as an additional state-leak
   check, while recognizing that these tests do not claim broad concurrency
   coverage.
4. Run the exact main-module CI coverage command:
   `go tool orchestrion go test -shuffle=on -covermode=atomic -coverpkg=./...
   -coverprofile=<profile> ./...`. New tests are unit tests and must not skip
   when Orchestrion is absent.
5. Inspect `go tool cover -func=<profile>` and compare package and total
   coverage with the baseline, excluding generated `*_gen.go` entries when
   interpreting the Datadog-counted result. Check both configured 85% gates. If
   total coverage remains below 85%, first identify untested behavior within
   the selected files. Do not add line-driving tests merely to cross the gate;
   report the measured shortfall and obtain user approval before broadening the
   production scope.
6. Run the separate benchmark-module unit tests:
   `go -C benchmarks/overhead test -shuffle=on ./...`.
7. Run the unconditional CI static checks: `go tool checklocks ./...` and
   `go -C benchmarks/overhead vet ./...`.
8. Obtain a read-only review from a different-foundry tier-4/5 sub-agent
   explicitly acting as a Go testing and QA specialist. Verify every finding,
   correct material issues, and request one follow-up review.

## Acceptance criteria

- All new tests assert behavior or a compatibility/boundedness contract.
- Tests are deterministic, independent of execution order, and restore global
  state.
- The exhaustive enum tables fail when a new enum is added without an explicit
  protocol expectation.
- Both telemetry iterators honor cancellation at every yield point and tests
  do not leak counter state.
- Focused, shuffled, race, Orchestrion, benchmark-module, and static checks
  pass.
- Datadog-counted coverage materially increases without modifying production
  code. The configured `85%` patch and total coverage gates pass. If the total
  gate cannot be met with high-quality tests for the selected behavior, the
  measured shortfall is reported rather than hidden or filled with weak tests.

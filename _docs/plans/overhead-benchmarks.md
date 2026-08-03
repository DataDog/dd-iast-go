# Plan: IAST Overhead Benchmarks

## Goal

Add a reproducible, repository-local benchmark suite that measures the runtime
cost added when Orchestrion weaves `dd-iast-go` into representative Go request
processing. Run both the uninstrumented control and woven treatment on the same
CI worker, retain their raw Go benchmark output, and publish a statistically
useful comparison without turning normal CI into a flaky performance gate.

The suite answers two separate questions:

1. What does the application workload cost without compile-time weaving?
2. What incremental `ns/op`, `B/op`, and `allocs/op` cost appears when the same
   source and inputs are built with Orchestrion and IAST integrations enabled?

## Status and Delivery Gate

This document is the planning deliverable only. After critic review has been
incorporated, implementation stops for explicit user review. Only after the
user approves this plan will it be committed separately as
`wip(plan): add IAST overhead benchmarks`; implementation must not begin before
that approval and plan commit.

## Scope

### Included

- End-to-end, in-process HTTP workloads using `net/http` and `httptest`, since
  HTTP request parsing and handler execution are representative of the critical
  path where IAST sources, propagation, and sinks execute.
- Multiple workload shapes rather than one synthetic microbenchmark:
  - a minimal health endpoint to expose fixed request/weaving overhead;
  - form/query/header parsing plus string manipulation to exercise source and
    propagation machinery;
  - curated weak-hash and weak-cipher sink operations, which are the concrete
    IAST vulnerability aspects currently present in this repository;
  - parallel request processing to expose contention and shared-store costs.
- Identical benchmark source, fixtures, iteration structure, and process
  configuration for control and treatment builds.
- A script as the single local/CI entry point that builds two distinct test
  binaries, executes repeated samples, validates that the treatment really was
  woven and the control was not, and runs `benchstat` over the results.
- A dedicated CI job that uploads raw results and the comparison report.
- Documentation for local execution and interpretation.

### Excluded from the first iteration

- A hard pass/fail regression threshold. Shared GitHub runners are noisy, and a
  threshold without a stable baseline risks false failures. CI will fail for a
  broken suite or missing instrumentation, but not merely for a measured delta.
- External services, network calls, databases, or containers. Sink-shaped
  workloads use deterministic in-process fakes/drivers so results measure IAST,
  not I/O variance.
- Compile-time/build-time overhead. This issue targets runtime overhead; build
  timing can be added later as an independent suite.
- Long-lived historical storage or automated PR comments. Raw artifacts make
  this possible later without coupling the initial suite to another service.

## Layout

Create a separate top-level `benchmarks/overhead/` Go module so benchmark-only
dependencies and integrations are isolated from the product module:

```text
benchmarks/overhead/
  go.mod                    # benchmark-only module and pinned tools
  orchestrion.tool.go       # tracer, net/http, and IAST integrations
  README.md                 # usage, workload definitions, interpretation
  overhead_test.go          # benchmark matrix and httptest workload harness
  instrumentation_test.go   # control/treatment build assertion
  testdata/                 # fixed request bodies or templates, if needed
  runner/main.go            # paired build/run/compare command
```

Generated output goes to a caller-selected directory (defaulting to a temporary
directory), never into the source tree. The script emits at least:

```text
control.txt
iast.txt
comparison.txt
```

## Benchmark Design

### One source, two Orchestrion-compiled variants

The comparison must not use duplicate control and IAST benchmark functions;
they would drift. Instead, copy only the benchmark module into isolated
temporary trees, use `go mod edit` to replace `github.com/DataDog/dd-iast-go`
with the current source tree, and compile the same test package twice with
Orchestrion:

- **control:** `go tool orchestrion go test -c` with only the `dd-trace-go`
  tracer integration retained in `orchestrion.tool.go`;
- **IAST:** the same command with the repository's complete integration set.

Both variants use the same application source and build/test flags; the
`dd-iast-go` integrations are the only intended difference. Orchestrion's
tool identity keeps differently woven objects distinct in Go's build cache.
Run each binary directly with the exact same
`-test.bench`, `-test.benchmem`, `-test.benchtime`, and `-test.cpu` arguments.

### Prove the independent variable

An overhead comparison is invalid if both binaries are woven or neither is.
Add two script-only, expectation-flagged helpers based on
`github.com/DataDog/orchestrion/runtime/built.WithOrchestrion`, both skipped by
default:

- the tracer-only control binary reports `WithOrchestrion == true` but produces
  no IAST finding;
- the IAST binary reports `WithOrchestrion == true`.

The control helper runs only under an explicit runner flag and asserts that
Orchestrion is enabled without IAST sink behavior. The woven helper starts with the repository's exact prescribed
`if !built.WithOrchestrion { t.Skip(...) }` preamble and then asserts true. Fail
fast before collecting timings when either invariant is false. Because
`WithOrchestrion` proves only that Orchestrion ran, also run an untimed
functional probe that invokes a known weak-hash aspect and
asserts an IAST-specific observable effect (a vulnerability on a locally
captured span) exists only in the treatment. Also print
the Go version, OS/architecture, CPU count, repository revision, and benchmark
arguments beside the results for reproducibility.

### Stable workload mechanics

- Construct immutable request input templates outside the timed loop, but make
  a fresh request, body, recorder, and parsed form state per operation; request
  bodies and parsed form state are not reusable.
- Use `b.ReportAllocs`, `b.ResetTimer`, and `b.SetBytes` where meaningful.
- Keep response consumption inside the timed operation so both variants do the
  same observable work; discard output through deterministic in-memory sinks.
- Avoid randomness, wall-clock assertions, logging, tracing exporters, and
  external I/O.
- Prevent compiler elimination by consuming results through a package-level
  sink only where the HTTP harness does not already make work observable.
- Use `b.Run` names that encode workload and serial/parallel mode while keeping
  names identical across variants so `benchstat` pairs them automatically.
- Fix both `GOMAXPROCS` and `-test.cpu`. Treat parallel results as aggregate
  throughput under controlled contention, not per-request latency.
- Start with enough work per operation to make instrumentation overhead
  measurable without making CI excessive. Document how to run longer local
  samples for investigations.

### Workload matrix

Implement workloads against integrations that exist when the code is written.
Do not fabricate calls to internal IAST APIs merely to make a number look
interesting. At present, Health and Request Processing are explicitly weaving
controls: the empty taint aspect means they do not yet claim to measure taint
machinery. The curated weak-hash/cipher cases are the IAST overhead measurements.

1. **Health:** create a GET request, route it through a simple handler, and
   consume a small response. This provides a low-work baseline and catches
   fixed weaving/runtime overhead.
2. **Request processing:** parse fixed query parameters, headers, and a
   URL-encoded body; normalize/concatenate selected values; encode a structured
   response. Include both a direct handler control and an `httptest` client/server
   round trip that exercises the tracer's `net/http` integration. This exercises
   realistic standard-library application work and naturally picks up
   source/propagation aspects as they land.
3. **Weak-hash/cipher sink paths:** invoke a stable, named set of deterministic
   standard-library operations currently instrumented by this repository.
   Include separate no-active-span (fast no-op) and active sampled-span
   reporting cases. The latter starts and finishes a bounded local span per
   logical operation, with IAST enabled and request sampling fixed at 100%, and
   uses a non-exporting, bounded/discarding trace writer. Finished spans are
   drained or capped independently of `b.N`; per-span vulnerability/evidence
   state becomes unreachable at `Finish`, and no package-level capture retains
   it. A capturing mock tracer is permitted only for the single untimed
   functional probe. Reset or uniquely scope deduplication state so later
   iterations do not silently measure only a duplicate-vulnerability fast path.
4. **Parallel request processing:** run the request-processing workload through
   `b.RunParallel`, with per-worker request/recorder state to avoid benchmark
   harness races. This reveals contention without sharing mutable fixture data.

Future HTTP sources/propagation/sinks may extend the matrix deliberately, but
new integrations do not automatically join it: stable benchmark names and
semantics are required for historical comparison.

## Runner and Statistical Comparison

The Go benchmark runner will:

1. use strict shell settings and resolve paths relative to itself;
2. accept overrides for output directory, independent sample count, benchtime,
   fixed CPU count,
   and benchmark regex while providing bounded CI-friendly defaults;
3. record environment metadata;
4. create isolated integration sets, then compile and validate control and IAST
   variants with Orchestrion;
5. run each sample in a fresh process, in deterministic alternating AB/BA
   blocks, with `-test.run=^$`, `-test.benchmem`, and controlled
   `GOMAXPROCS`/`-test.cpu` values; do not use `-test.count` because global IAST
   state would survive repetitions in one process;
6. preserve raw output even if comparison generation fails;
7. reject mismatched benchmark-name or sample-count sets, then generate
   `comparison.txt` with `go tool benchstat` from a committed, pinned
   `golang.org/x/perf/cmd/benchstat` tool dependency in `go.mod`/`go.sum`.

Keep compile time outside benchmark timing. Set IAST/tracer configuration
explicitly in the runner rather than inheriting developer or CI environment
variables, and document every setting that changes sampling/reporting behavior.
Write metadata to a separate `metadata.txt` so `control.txt` and `iast.txt`
remain valid Go benchmark streams. Use a statistically useful local default
(for example 10 independent samples); permit an explicitly labeled two-sample
smoke mode for PR CI. Shared-runner CI output is diagnostic even with more
samples because host noise prevents trustworthy regression gating.

## CI Integration

Add a dedicated `benchmark` job to `.github/workflows/ci.yml`:

- use the same pinned checkout and Go setup conventions as existing jobs;
- invoke only `go -C benchmarks/overhead run ./runner` so local and CI behavior cannot
  diverge;
- upload the metadata, both raw result files, and `comparison.txt` with a short
  retention period and `if: always()` so partial diagnostics survive failures;
  create the artifact directory before any fallible step and pin
  `upload-artifact` to a full commit SHA, matching repository conventions;
- append the comparison to `$GITHUB_STEP_SUMMARY` only when it exists and quote
  it safely;
- fail when compilation, variant validation, benchmark execution, or result
  pairing fails, but do not gate on a performance percentage initially.

Run this bounded smoke configuration on every pull request and set an explicit
job `timeout-minutes`. Longer statistically useful runs remain local/manual or
may be added as a scheduled job after runner cost is understood.

The benchmark package remains covered by the existing unit-test job, but the
normal test command will not execute benchmarks because Go benchmarks only run
when `-bench` is supplied.

## Validation

Before delivery:

1. format and statically check all Go and shell changes;
2. run the existing full instrumented test suite;
3. run the overhead script with smoke settings to exercise both build variants,
   the instrumentation guard, all benchmark names, and report generation;
4. inspect raw results to confirm every benchmark appears in both files and
   includes `ns/op`, `B/op`, and `allocs/op`;
5. explicitly run short baseline and woven parallel benchmarks under the race
   detector so `b.RunParallel` is exercised (a test-only race command is not
   sufficient);
6. test paths containing spaces and invalid arguments where practical so runner
   failures are clear and do not silently produce misleading comparisons;
7. validate the workflow YAML and ensure generated benchmark artifacts remain
   untracked.

Expected commands (exact flags may be refined during implementation):

```console
go tool orchestrion go test ./...
go test -race -run='^$' -bench='Parallel' -benchtime=100ms ./benchmarks/overhead
go tool orchestrion go test -race -run='^$' -bench='Parallel' -benchtime=100ms ./benchmarks/overhead
go -C benchmarks/overhead run ./runner -count=2 -benchtime=100ms
jj diff
```

## Documentation and Interpretation

The benchmark README will explain:

- prerequisites and a one-command quick start;
- the exact distinction between baseline and IAST variants;
- workload semantics and which IAST paths each currently exercises;
- why `benchstat` confidence intervals matter more than a single percentage;
- that results from different machines are not directly comparable;
- how to increase repetition/benchtime for reliable local investigations;
- where CI artifacts and summaries are found;
- that results measure runtime overhead only, not Orchestrion build overhead.

## Acceptance Criteria

- A developer can run one repository-local command and receive paired raw Go
  benchmark results plus a `benchstat` comparison.
- The command demonstrably compares an ordinary binary with an
  Orchestrion-woven binary built from identical benchmark source.
- The suite contains serial and parallel realistic request-processing workloads
  and reports time and allocation metrics.
- No benchmark relies on external I/O or an unbounded data structure.
- CI executes the suite, surfaces the comparison, and retains raw artifacts.
- Functional failures make CI red; noisy performance deltas alone do not.
- Existing tests and race checks continue to pass.

## Follow-up Opportunities

- Establish a dedicated stable runner and historical store, then define
  statistically justified regression budgets per workload.
- Add scheduled longer runs, trend dashboards, or automated PR comments.
- Add build-time and binary-size comparisons as separate metrics.
- Expand the workload matrix alongside new HTTP sources, taint propagation
  aspects, sanitizers, and vulnerability sinks.
- Add representative third-party routers only when their added dependency and
  maintenance cost is justified by measurements that differ materially from
  `net/http`.

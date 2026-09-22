# Plan: comprehensive propagation scenario testing

## Start here

Read this file, `AGENTS.md`, and `CONTRIBUTING.md`, then inspect `jj status`.
The [operation matrix](propagation-coverage-matrix.md) and
[engine path classification](propagation-coverage-paths.md) are complete.
Independent critic review is complete. The user's subsequent annotations
exclude external System Tests and retain the focus on local coverage. Read the
[review decisions](propagation-coverage-review.md).
The user approved this revised plan and its local commit on 2026-09-22.
Implementation is complete. The user authorized publication on 2026-09-23.

Validation and independent implementation review passed. See the
[measured results](propagation-coverage-results.md).

This is a handoff plan written on 2026-09-22 from a completed read-only
assessment. The approved plan was committed before implementation. The user
asked for this file so a new session could take over.

User requirement:

> I want scenarios covering most, if not all code paths here, because this is
> central to our business here.

The goal is confidence in propagation behavior, not merely a higher aggregate
coverage percentage. Local unit, native-call, and source-to-sink tests must
provide that confidence without relying on external System Tests.

## Baseline and completed work

| Item | Assessed baseline |
| --- | --- |
| Repository | `DataDog/dd-iast-go` |
| PR | <https://github.com/DataDog/dd-iast-go/pull/39> |
| Published head | `3168522002ee7e5eee83338e6c991c659415b6a7` |
| PR bookmark | `romain.marcadier/taint-tracking` |
| Toolchain | Go 1.26.6; use the Orchestrion version pinned in `go.mod` |

The preceding coverage correction is complete and published. Do not repeat it:

- `ac248a1f`: collect coverage from all test runs.
- `31685220`: add tests for bounded runtime paths.
- CI merges six profiles across five modules: ordinary and instrumented root
  tests, plus the four nested-module test runs.
- Every one of the uploaded profile's 4,356 block counts was checked against
  the independent sum of those six profiles.
- All 25 checks passed. Datadog reported 85.2% patch and 86.3% overall coverage
  against unchanged 85% thresholds. The merged Go statement result was
  6,260 / 6,838, or 91.5%.

Go statement coverage, Datadog line coverage, and scenario/path coverage are
different measures. Do not present one as proof of another.

### Propagation coverage at the baseline

These are **Go statement percentages from the uploaded CI profile**:

| Component | Covered / total statements | Coverage |
| --- | ---: | ---: |
| `iast/propagation` wrappers | 413 / 415 | 99.5% |
| `internal/taint/propagation` engine | 1,052 / 1,194 | 88.1% |
| `internal/taint/ranges` primitives | 437 / 466 | 93.8% |

All 109 functions reported for the propagation engine were reached, but only
56 had complete statement coverage. There were 142 unexecuted statements.
The weaker engine files included `conversion.go` at 76.0% and `writer.go` at
84.0%.

Some uncovered statements are defensive guards or concurrency-dependent
cleanup. Classify their reachability before proposing tests. Do not construct
impossible native results just to execute a guard.

### Useful tests already present

Retain and extend this coverage instead of duplicating it:

| Area | Existing evidence |
| --- | --- |
| Exact copies, windows, joins, replacement, repeat, source limits | `internal/taint/propagation/propagation_test.go` |
| Byte mapping, Unicode, invalid UTF-8, exact/coarse boundaries, owner-local sources | `internal/taint/propagation/bytes_exact_test.go` |
| Partial ranges, marks, conversion, bounded windows and coarse fallbacks | `internal/taint/propagation/range_behavior_test.go` |
| Native writer copies, mutation invalidation, reset/truncate, result identity, errors and panics | `iast/propagation/writer_test.go` and `internal/taint/propagation/writer_behavior_test.go` |
| Independent byte-level reference model and fuzz targets | `internal/taint/ranges/property_test.go` and `fuzz_test.go` |

The range property tests use fixed random seeds: 10,000 canonicalization cases,
5,000 cases covering composite operations, and 1,000 operation-identity cases.
Native string/byte tests cover many supported operation families. UTF-8
contributor tests and writer tests already make stronger assertions than a
simple tainted/not-tainted check.

## Verified gaps

### Local end-to-end tests do not yet exercise transformation chains

`iast/integration/testapp/e2e_test.go:51` and `:73` send an HTTP query value
directly to SQL or command execution. JSON cases decode and inspect taint but
stop before a sink. The finding assertions check counts and source-index
bounds, not the complete expected evidence and source identity.

### Some native-call assertions are too weak

`iast/propagation/strings_test.go:116` and
`iast/propagation/bytes_test.go:108` mostly check that allocating operations
produce a tainted result. A wrong offset, wrong contributing source, or lost
secure mark can still pass.

Strengthening those local assertions is a required part of this work. Allocating
operations must assert native values and the promised ranges, source identity,
and marks; taint presence alone is not sufficient.

`iast/propagation/operators_test.go:23` exercises concatenation arities 2-16
through direct wrapper calls. Native operator injection is tested on
representative expressions, not the full advertised matrix.

### Lifecycle and failure coverage is incomplete

The engine's publication loops contain unexecuted stale-owner, rejected-range,
and related failure paths. Existing finish-race tests start competing workers,
but do not force a particular lookup/finish/publication order. They are useful
stress tests, not proof that each critical interleaving occurred.

### Continuous property, fuzz, and race coverage needs strengthening

Range primitives have property tests and fuzz targets. The higher-level
propagation engine does not have equivalent coverage of generated operation
sequences. The current CI workflow has no fuzz campaign; normal test execution
runs the fuzz seeds only. Its explicit `-race` invocation covers `./.github`,
not the propagation runtime. Full runtime race checks passed locally during
the previous task but are not a dedicated CI requirement.

## Scope and constraints

This is primarily test and test-enforcement work:

- External System Tests are out of scope. The user has a separate PR for that
  work; requiring feature-specific cases before they are implemented is not a
  goal here. Do not change the system-tests repository, its manifests or weblogs,
  `.github/workflows/system-tests.yml`, or its execution gate. This plan has no
  dependency on that PR's publication or external job results.
- Cover supported operations and their real failure behavior. Preserve current
  native values, aliases, evaluation order, counts, errors, and panics.
- Keep exact provenance where promised. Where the contract uses coarse
  provenance or bounded drops, assert that specific result instead.
- Do not lower thresholds, add Datadog exclusions, weaken existing tests,
  change dependencies, or add public APIs for test access.
- Do not add unsupported propagation features or refactor production code to
  raise coverage. If a test exposes a real defect, first demonstrate it with
  a failing regression and make only the smallest necessary correction.
- Use deterministic synchronization and existing test seams. No fixed sleeps,
  polling-based test success, arbitrary corrupt snapshots, or prose assertions.
- Do not add `t.Parallel` to suites that mutate process configuration globals.
  Keep all seeded state and request owners bounded and release them per case.

Use current code and `README.md` as the contract. Historical plans contain
superseded statements, including older buffer-copy limitations. Exact current
buffer copies are supported; divergent/historical copies, builder copies,
indirect propagation calls, and unsupported JSON destinations remain separate
limitations. Do not turn a negative test into an unrequested feature.

## Execution plan

### Phase 1: establish the operation and path matrix

- [x] Verify the current baseline and preserve unrelated work.
- [x] Map every supported operation to unit and native-call tests.
- [x] Classify each remaining uncovered engine path.

Build the matrix from `README.md`, `iast/propagation/orchestrion.yml`, the
operator and JSON advice, and the implementation. Include reader propagation.
For each operation, record the applicable scenarios below, existing test
names, missing cases, and expected exact/coarse/drop behavior.

| Dimension | Scenarios to account for |
| --- | --- |
| Analysis state | Disabled/no active scope; active but clean; active and tainted; finished or reused owner |
| Contributors | Clean prefix/suffix; partial taint; different sources; tainted separator/replacement; unused tainted input |
| Ownership and marks | One owner; multiple owners with overlapping local source IDs; owner-fanout limit; mark preservation/intersection |
| Shape and bounds | Empty/one-byte result; alias versus fresh allocation; Unicode/invalid UTF-8; exact/coarse and range/capacity boundaries |
| Publication and lifecycle | Successful publication; contention; quota exhaustion; partial owner success; finish/reset/reuse |

Do not require the full Cartesian product for every function. Use representative
classes that exercise every distinct reachable decision. A justified
not-applicable cell must name the relevant invariant.

**Acceptance:** every supported operation has a named test location, and every
remaining uncovered engine block is assigned either a reachable scenario or
a concrete reason it cannot occur under the current contract. For reachable
race-dependent blocks, also name the available test seam and any ordering that
cannot be forced through that seam. A missing test seam does not make a block
unreachable. Record block coordinates and per-file statement counts in the
matrix so the result does not depend on temporary artifacts. An aggregate
percentage is not an acceptable substitute.

### Phase 2: protect complete local source-to-sink scenarios

- [x] Add multi-stage HTTP-to-SQL propagation scenarios.
- [x] Add multi-stage HTTP-to-command propagation scenarios.
- [x] Add reader/JSON/writer chains with negative controls.

Use the existing `iast/integration/testapp` infrastructure:

First add `iast/propagation`, `iast/io`, and `iast/bufio` to that module's
`orchestrion.tool.go`. Its current imports enable sources, JSON, and sinks but
not the transformation chains. Start with a chain test that fails because the
fresh transformed value loses provenance, then enable those existing aspects.
This changes fixture setup, not the supported production feature set.
Immediately run this nested module's woven coverage command with a fresh cache
and the existing CI bridge-package exclusion before adding the remaining chain
tests. This checks the new fixture imports against the known bridge archive
linking limitation early.

Implementation verified another fixture constraint: the pinned injector's
root-package filter excludes the module-root external test package
`testapps/integration_test`. Native transforms therefore live in small
application fixtures in `chains.go`, `command_chain.go`, and `json_chain.go`.
The tests call these fixtures through real HTTP requests and inspect every
promised stage. The initial SQL chain failed without propagation; the full
nested woven coverage run passed after the imports and fixture were added.

| Scenario | Required observations |
| --- | --- |
| Two named HTTP values -> trim/slice -> join/concatenate -> format -> SQL prepare/execute | Native query; expected ranges at exact stages; documented coarse transition; correct source identities and final evidence; separate prepare and execute findings |
| HTTP value -> supported transforms -> command attempt | Correct contributing command value and evidence; one finding at execution, not at construction |
| HTTP body -> reader composition -> JSON decode -> string/byte or writer transforms -> sink | Decoded provenance survives the chain; correct source document and literal association; no reader binding remains after decode/finish |
| Clean query plus a tainted bound SQL parameter | No SQL-injection finding from the bound parameter |
| Clean/rejected/unsupported contributor | No invented provenance or finding; native error/panic behavior remains unchanged |

Include repeated equal JSON literals with different source ranges, escaped
Unicode, typed destinations and `,string`. Keep custom unmarshalers and other
unsupported destinations as negative cases. Reuse existing regression tests
for decoder reuse, failure, panic and oversize; add the missing composition,
not duplicate setup-only tests.

Inspect exact evidence parts and source origin/name/value, not only finding
counts or valid source indexes. Where redaction changes the visible evidence,
assert the existing redaction contract. Seed secure marks through existing
test access only; do not add a new public sanitizer API.
Use the recipe in `iast/propagation/writer_test.go:318`: obtain the owner from
a store snapshot, mark its ranges with `ranges.MarkAll`, and adopt a complete
string clone. The nested testapp can import the internal store and ranges
packages. These cases prove preservation of seeded marks, not a production
sanitizer feature.

**Acceptance:** positive and negative chains pass through real injected
application calls to captured findings in the local integration fixture.
These tests verify complete expected evidence and source identity independently
of external System Tests.

### Phase 3: complete native-call provenance assertions

- [x] Strengthen native string and byte operation assertions.
- [x] Cover every advertised operator injection form.
- [x] Complete writer and reader boundary scenarios.

Primary locations:

- `iast/propagation/{strings,bytes,operators,writer}_test.go`
- `iast/internal/propagationtest/`
- `iast/io/io_test.go` and `iast/bufio/bufio_test.go`

Replace weak positive checks with exact expected values and provenance where
the contract is exact. Retain boolean-only assertions where absence of taint is
the actual property being tested.

Test native concatenations of arities 2-16, each supported slice form, named and
generic types, and supported byte-to-string conversions. Include side-effecting
operands to prove single evaluation and order. Direct calls to `ConcatN` remain
useful unit tests but are not proof that Orchestrion rewrites the native syntax.
Also exercise both pointer and value receiver forms for the writer advice;
identical wrapper callees do not prove both forms are injected.
Prefer native expressions in the external `iast/propagation` test package;
existing tests prove that those expressions are injected. Add non-test
`iast/internal/propagationtest` helpers only when necessary, and exercise every
new helper in a test included in the woven root coverage run.

For allocating operations, combine clean data, partial taint, distinct sources,
tainted separators/replacements, and unused contributors. For writers, cover
tainted and clean writes, growth, truncation, copies, reset, overwrite, mutable
exposure, and subsequent reads. For composed readers, exercise the last
included and first excluded input at the implementation's inspection bound.

Assert source identity and secure marks in addition to offsets and lengths.
For coarse transforms, assert the documented contributor selection and mark
intersection rather than demanding unsupported exact mapping.

**Acceptance:** a regression that taints the entire result, swaps sources,
loses marks, or fails to inject a supported call cannot pass merely because
the output is still tainted.

### Phase 4: close engine failure paths and generated scenarios

- [x] Cover reachable admission and publication failures.
- [x] Force critical owner-lifecycle orders deterministically.
- [x] Extend the independent oracle to propagation sequences.
- [x] Add bounded fuzz coverage for mapping and state transitions.

Prioritize `internal/taint/propagation/{conversion,writer,propagation}.go`,
then exact/coarse string and byte mapping. Relevant existing tests include
`propagation_test.go:816`, `:850`, `bytes_exact_test.go:370`,
`range_behavior_test.go`, and the store admission/mutation/writer tests.

Exercise one owner's publication failing while another succeeds, owner finish
and slot reuse, contention, and root/value/range limits. Check the surviving
provenance, released charges and anchors, and unchanged native results.
Retain existing stress tests, but add deterministic tests at the narrowest
existing seam for the specific lifecycle orders they do not guarantee.

Put lock-contention and late-write ordering tests in the existing in-package
store tests, which can hold the actual lock without a production test hook.
Use propagation tests for stale handles, owner-slot reuse, partial admission,
and native-result preservation. Do not claim these tests force a pause between
an engine lookup and publication: no existing propagation seam provides that
pause. The path matrix must distinguish lower-level deterministic coverage,
engine stress coverage, and an engine block whose execution is not guaranteed.
Approval of this plan includes review of those explicit residual gaps; it does
not authorize production hooks merely to force coverage counters.

The path table accounts for all 128 zero-hit blocks (142 statements):
53 ordinary or documented internal-contract statements, eight stale-owner
statements testable through exported internal access, seven stale-snapshot
statements testable through existing private helpers, 17 inline race-dependent
statements, ten statements requiring native values above 4 GiB, five guards
requiring non-native arguments, and 42 native-impossible invariant guards.

Cover the seven private-helper statements with one in-package
`stale_owner_internal_test.go`. Use real snapshots captured before finish or
slot reuse, not corrupt snapshots. Validate its ordinary and woven coverage
linkage first. This does not provide a seam for the 17 inline race statements.
Do not add negative native counts or mismatched result lengths to force the
five argument guards. Leave the >4 GiB cases outside the bounded test budget.
Test the documented `RepeatBytes` count-one alias contract directly, clearly
labelled engine-only evidence rather than a native `bytes.Repeat` result.

Generate short sequences from supported exact operations. Compare values with
native Go behavior and provenance with an independent per-byte source/mark
model. Include Unicode, invalid UTF-8, partial ranges, repeated values, and
existing limit boundaries. Extend the current range oracle rather than creating
a parallel generic test framework.

Test coarse transitions separately with named fixtures. Assert the expected
first contributing source per owner, whole-result range, mark intersection,
and inspected-input/owner bounds, including bounded drops. A subset-of-input
source assertion alone is too weak: it can miss a swapped source. Do not demand
exact byte attribution after a coarse transition, or use an unconditional
"tainted iff an input is tainted" assertion when admission can fail.

**Acceptance:** each reachable failure path has a named scenario and expected
outcome. Generated tests can detect incorrect provenance, not merely invalid
range structure. Remaining unreachable guards have explicit explanations.
Race-dependent engine blocks without an existing deterministic seam remain
listed separately with their lower-level and stress evidence; do not mark them
as deterministically exercised. The >4 GiB cases and non-native argument guards
remain explicit exclusions, not scenarios claimed to have run.

### Phase 5: make the checks continuous and verify delivery

- [x] Add an appropriate propagation race check to CI.
- [x] Run bounded fuzz campaigns, not only seed replay.
- [x] Run ordinary, instrumented and nested-module validation.
- [x] Complete independent review and publish only when authorized.

Keep test execution in test jobs and static checks in lint jobs. Run each fuzz
target separately with a finite iteration or time budget; record the target,
budget and result. Do not introduce a new fuzzing dependency without need.

The root CI test job will run
`go test -race -count=1 -shuffle=on ./internal/taint/...` in addition to the
existing CI-tool race check. Keep the full local root race run in validation.

Use 10,000 fuzz executions per target in the root CI test job, with
`-run='^$'`, `-parallel=4`, `-fuzzminimizetime=1000x`, and `-timeout=5m`.
Run `FuzzCanonicalize` and `FuzzSliceAndCopy` separately in the ranges package,
plus `FuzzEngineSequence` and `FuzzOwnerLifecycle` separately in propagation.
Replay seeds during ordinary tests as well. Upload any failing input corpus.
This adds real mutation campaigns to PR checks without a new scheduled workflow.
Limit generated sequences to eight operations, two owners, 256 input bytes,
and 4 KiB of output; test larger capacity and fanout boundaries with named
fixtures. Use 2,000 fixed-seed sequences in the property test as well. Keep the
small per-byte oracle helper local to the external propagation test package;
no shared production helper is needed. Record the local campaign results.
The execution budget is `-fuzztime=10000x`; the timeout is a failure deadline,
not a successful campaign end. Record elapsed time per target and check that it
leaves sufficient headroom before pinning the CI timeout. Investigate any
timeout as a separate failure, not as a found fuzz input.

For example, one campaign is:

```sh
go test -run='^$' -fuzz='^FuzzCanonicalize$' -fuzztime=10000x \
  -fuzzminimizetime=1000x -parallel=4 -timeout=5m ./internal/taint/ranges
```

Invoke the same command separately for `FuzzSliceAndCopy` in ranges and for
`FuzzEngineSequence` and `FuzzOwnerLifecycle` in propagation. Never use a
pattern that selects two fuzz targets in one invocation.

If work is delegated, Phase 1 comes first. After it is complete, the in-repo
integration, native-call, and engine test tracks can proceed independently in
their listed directories. Give the coordinator ownership of the in-repository
CI workflow edits. Do not let multiple workers edit shared test helpers
concurrently.

## Validation instructions

Use Go 1.26.6 and the existing dependencies. Go 1.27.1 is not a substitute:
earlier probes failed on changed `encoding/json.Decoder` source shapes.

Representative root checks:

```sh
export GOTOOLCHAIN=go1.26.6
export GOFLAGS=-mod=readonly
evidence=$(mktemp -d)
woven_cache=$(mktemp -d)

go test -count=1 -shuffle=on \
  -covermode=atomic -coverpkg=./... \
  -coverprofile="$evidence/root.ordinary.cover" ./...

GOCACHE="$woven_cache" go tool orchestrion go test -count=1 -shuffle=on \
  -covermode=atomic -coverpkg=./... \
  -coverprofile="$evidence/root.woven.cover" ./...

go test -race -count=1 -shuffle=on ./...
go test -race -count=1 -shuffle=on ./.github
go vet ./...
go vet ./.github
go tool checklocks ./...
```

Also apply the repository's formatting checks to modified Go files and
`actionlint` to modified workflows.

For nested coverage, reproduce the collector in `.github/workflows/ci.yml`
exactly for:

- `iast/database/sql/testapp`
- `iast/os/exec/testapp`
- `iast/integration/testapp`
- `benchmarks/overhead`

The pinned injector cannot share synthetic bridge coverage archives reliably
in nested builds. Those builds omit bridge instrumentation; both root runs
still cover every bridge. Keep the bridges in the final denominator and do
not add Datadog ignores.

A fresh cache and the explicit root `-coverpkg=./...` are important when
diagnosing archive fingerprint mismatches. Prior comparisons that changed
both imports and workspace paths did not isolate a root cause. Do not repeat
the disproved claim that one particular test import caused those failures.

`built.WithOrchestrion` alone does not prove a call was rewritten:
implementation packages under `internal/` are excluded from call-site advice.
Use the existing instrumented application fixtures to prove native injection.

For nontrivial implementation, obtain the required read-only review from a
different model foundry at high reasoning. Verify findings independently.
Preserve an executable regression before changing behavior to fix a defect.

If publication is authorized, verify the resulting PR head, CI artifact and
Datadog results for that exact SHA. Signing during `jj git push` can change
the commit SHA without changing the tree; subscribe to the published SHA,
not an earlier local hash. The external System Tests job is not an acceptance
condition for this work.

## Completion criteria

### Scenario coverage

- [x] Every supported operation is represented in the scenario matrix.
- [x] Every in-budget reachable scenario with an existing deterministic seam is exercised; native-impossible and non-native argument guards have specific invariants, and race-only and >4 GiB gaps retain their explicit classifications and applicable evidence.
- [x] Native-call tests check values and the promised provenance, not just taint presence.
- [x] Multi-stage source-to-sink tests verify findings and negative controls.

### Validation and delivery

- [x] Deterministic lifecycle/pressure tests, property tests, fuzz campaigns and race checks pass.
- [x] Existing contracts, coverage thresholds and Datadog ignores remain intact.
- [x] Independent review is complete and the final report distinguishes statements, lines and scenario coverage.

No arbitrary new percentage is the sole completion condition. A higher number
does not compensate for a missing business-critical scenario.
The user approved the revised path criterion above. It explicitly
permits residual race-only engine blocks without adding production test hooks;
it also excludes >4 GiB test allocations and fabricated native results. It does
not claim that stress execution proves each internal ordering occurred.

## Handoff evidence and workspace notes

The assessment was read-only. No implementation changes or new tests were made
for this follow-up. At its start the primary working copy was empty above
`31685220`. Use `jj` for version control and `apply_patch` for file changes.
Do not modify immutable changes or overwrite work from another session.

The separate `system-tests` workspaces are outside this plan and must remain
unchanged.
Temporary workspaces and compiler caches from the preceding coverage task
were removed.

Local evidence is under `/tmp/dd-iast-pr39-coverage-20260922/`:

| Evidence | Relative path |
| --- | --- |
| Published merged profile and six inputs | `ci-published/` |
| Per-function Go coverage report | `propagation-audit-functions.txt` |
| Prior correction's QA and independent review | `qa.md`, `review-report.md`, `journal.md` |

The temporary files are useful but are not the only record. They may expire.
The published source revision, measured baseline and findings are recorded
above. CI evidence links:

- Coverage and Go tests:
  <https://github.com/DataDog/dd-iast-go/actions/runs/35721738286>

Earlier design context:

- [Named propagation](taint-tracking-net-http-sqli-cmdi-phase-5.md)
- [Operator propagation](taint-tracking-net-http-sqli-cmdi-phase-6.md)
- [JSON propagation](taint-tracking-net-http-sqli-cmdi-phase-8.md)

Treat their historical status and benchmark results as history, not evidence
that the new scenarios already exist.

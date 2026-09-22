# Local propagation coverage results

Implementation, validation, and independent implementation review are complete.
The user approved the plan and authorized publication on 2026-09-23.
External System Tests remain outside this work.

## Coverage measured

These numbers compare the exact published baseline profile with the merged
local profile. The denominator is unchanged.

| Metric | Published baseline | Local result |
| --- | ---: | ---: |
| Go statements, whole root module | 6,260 / 6,838 (91.55%) | 6,335 / 6,838 (92.64%) |
| Propagation engine statements | 1,052 / 1,194 (88.11%) | 1,120 / 1,194 (93.80%) |
| Strict line coverage, existing Datadog ignores | 7,629 / 8,842 (86.28%) | 7,814 / 8,842 (88.37%) |

The line calculation marks a line covered only when every block on that line
has a hit. It applies the existing `*_gen.go` and `benchmarks/` ignores.
The baseline calculation agrees with the published 86.3% total gate result.
The local line result is not a new Datadog result: nothing was uploaded.

Go statement coverage is not line coverage. Neither metric measures scenario
coverage. The [operation matrix](propagation-coverage-matrix.md) and the named
tests below provide the scenario evidence.

Baseline SHA-256:
`485b5a3b76ca8cd8295d7e2c3760a160dd34819e554c7556de22885e65b6dfe5`.

Local merged-profile SHA-256:
`d56587f4a536bf89a5166126dabd824d0c204841a973b32f7d5bda238bb8d991`.

Some existing stress-dependent hits outside the engine inventory vary between
runs. The final profile has no hit at `store/mutation.go:73.43,75.3`, where
publication can refuse a mutated root; the baseline had one hit. The final
metrics use this run as observed, not a best-of-run union. All 68 approved
engine statements remain hit. Lookup's shard, lifecycle, and root-lock refusal
branches now have deterministic coverage rather than relying on stress.

## Every approved uncovered engine target was hit

The exact 128-block, 142-statement baseline inventory reconciles with the
final profile. All 65 blocks containing the 68 testable statements now have
hits. No target coordinate is missing or has a changed statement count.

| Class | Baseline uncovered statements | Now covered | Remaining |
| --- | ---: | ---: | ---: |
| R: ordinary/native or documented internal contract | 53 | 53 | 0 |
| D: deterministic stale-owner state through existing APIs | 8 | 8 | 0 |
| DN: real stale snapshots passed to private helpers | 7 | 7 | 0 |
| X: inline race windows without a deterministic seam | 17 | 0 | 17 |
| I: native values above 4 GiB | 10 | 0 | 10 |
| DA: non-native count/result argument guards | 5 | 0 | 5 |
| U: native-impossible guards | 42 | 0 | 42 |

The 74 remaining statements retain their approved classifications and
invariants in the [engine path table](propagation-coverage-paths.md).
Race-only paths are not called unreachable. Stress or race-detector success
is not claimed to force those orders.

The DN tests compile and pass in ordinary and woven builds. They use actual
captured snapshots after owner finish and reuse, then call existing private
helpers. No production hook or exported test API was added. Surviving owners
must retain their exact ranges, source IDs, and marks.

## Scenario evidence

| Area | Tests and checks |
| --- | --- |
| Local HTTP to SQL | `TestHTTPTransformedQueryToSQL`: slice, trim, join, formatting, complete evidence and source identity, separate prepare and execution call sites |
| SQL controls | `TestHTTPTransformedSQLBoundArgumentDoesNotReport`, `TestSQLChainIntersectsSeededSecureMarks` |
| Local HTTP to command | `TestHTTPTransformedCommandReportsOnlyOnAttempt`: replacement and writer ranges, full evidence, construction versus failed native start |
| Reader, JSON, writer, sink | `TestHTTPBodyReaderJSONWriterToSQL`: composed readers, typed/quoted/escaped strings, SQL evidence, reader cleanup |
| JSON destination controls | `TestJSONDestinationClassesPreserveTheirContracts`, `TestRepeatedJSONLiteralsKeepSeparateSourcesAndMarks`, clean-reader and custom-unmarshaler controls |
| Decoder bounds | `TestDecoderSlotCapacityAndRelease`, `TestDecoderCollisionStopsAfterFourProbes` |
| Native strings and bytes | Allocating, window, sequence-bound, case, replacement, repair, and coarse tests in `iast/propagation/{strings,bytes}_*_test.go` |
| Native operators | All concat arities 2-16, operand positions and evaluation counts, slice forms, named/generic operands, conversions, and explicit unsupported-context controls |
| Native writers | Pointer receiver forms, forced growth after tainted writes, marks, copies, exposures, overwrite, native panics, admission and owner fanout |
| Native readers | Delegation, byte bounds, eighth/ninth MultiReader inputs, binding admission, and cleanup |
| Physical reader release | `TestFinishReleasesReaderBindingObjects`: actual stored reader references become nil after owner finish |
| Lookup contention | `TestLookupBusyLocksClearSnapshotAndRecover`: deterministic shard/lifecycle/root lock refusal, cleared snapshots, and exact recovery |
| Engine failures | `path_entry_test.go`, `path_lifecycle_test.go`, `path_native_test.go`, `path_fanout_test.go`, `stale_owner_internal_test.go` |
| Generated operations | `TestEngineSequenceAgainstOracle`: 2,000 fixed-seed sequences; exact values and per-owner source/mark cells after each step |
| Coarse generated checks | Named fixtures check the exact first source, whole-result spans, mark intersection, inspection limits, and allowed drops |

The first SQL-chain regression failed with zero propagated ranges and zero
findings. The fixture was missing propagation/io/bufio advice, and the pinned
injector excludes module-root external tests from call-site advice. Adding the
imports and placing native transforms in small application fixture files made
the same assertions pass.

## Validation

All commands used Go 1.26.6 and `GOFLAGS=-mod=readonly`.

- Full root ordinary and woven suites, with atomic coverage and
  `-count=1 -shuffle=on -coverpkg=./...`.
- Full root `go test -race -count=1 -shuffle=on ./...`.
- Root and `.github` `go vet`; root `go tool checklocks`.
- `.github` tests under the race detector.
- Full woven suites and vet in all four nested modules: SQL, command,
  integration, and overhead.
- Full integration fixture under woven race detection; the later JSON
  destination case also passed the final full woven suite.
- Complete native propagation/io/bufio suite, plus deterministic decoder
  bounds under the race detector.
- All modified Go files checked with `gofmt`; Go LSP reports no errors.
- `actionlint .github/workflows/ci.yml`.

The tools-tagged fixture file is outside the normal LSP package view; its
actual woven build passed. Markdown and YAML LSP servers were unavailable.
The workflow passed actionlint; documents were checked through their links,
scope, counts, and exact profile-coordinate reconciliation.

Each fuzz target ran separately with `-run='^$' -fuzztime=10000x
-fuzzminimizetime=1000x -parallel=4 -timeout=5m`.

| Target | Executions | Wall time, including compilation |
| --- | ---: | ---: |
| `FuzzCanonicalize` | 10,000 | 16.241 s |
| `FuzzSliceAndCopy` | 10,000 | 16.105 s |
| `FuzzEngineSequence` | 10,009 | 3.338 s |
| `FuzzOwnerLifecycle` | 10,000 | 3.361 s |

The sequence campaign finished its 10,000-execution budget with nine extra
executions from parallel work already in progress. All targets completed
successfully, well before the five-minute failure deadline.

## Reproducible artifacts

The independent Claude Opus 5 review passed quality, security, and context.
Its follow-up passed after verifying the fixture comment fixes and the new
physical reader-release and deterministic lookup tests. The proposed
`go:noinline` fix was rejected using actual Go 1.26.6 compiler diagnostics:
the existing directive already prevents inlining.

Reports:
`/tmp/iast-final-validation.dw42rl/gate-review.md` and
`/tmp/iast-final-validation.dw42rl/gate-review-followup.md`.
The follow-up left two non-blocking test-expansion suggestions: checking the
binding probe-index reset and asserting contention counters. These are not
current implementation defects. The added tests cover their stated contracts:
physical object release, refusal results, snapshot clearing, and exact recovery.

The existing `.github/merge-coverage.py` merged exactly these six profiles:

- `/tmp/iast-final-validation.dw42rl/root.ordinary.v3.cover`
- `/tmp/iast-final-validation.dw42rl/root.woven.v3.cover`
- `/tmp/iast-chain-green.Ai8Fti/coverage.final.txt`
- `/tmp/iast-nested-sql.oPLD1B/coverage.txt`
- `/tmp/iast-nested-exec.EID64X/coverage.txt`
- `/tmp/iast-nested-overhead.gOaxmS/coverage.txt`

The merged profile is
`/tmp/iast-final-validation.dw42rl/coverage.merged.txt`.
`go tool cover -func` reports 92.6% after rounding.

Nested builds use the existing CI package list, which omits the synthetic
`internal/taint/*bridge` archive variants only for nested coverage. The root
profiles include those bridges. No exclusion, threshold, dependency, or
library API changed.

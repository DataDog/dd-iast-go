# Propagation coverage plan review

## Status

Independent critic review is complete after two follow-up rounds.
Final verdict: **approve; no remaining substantive disagreement**.
The user approved the revised plan, its local commit, and implementation on
2026-09-22. Publication is not approved.

After that review, the user explicitly scoped external System Tests out. Their
separate PR owns that work. The plan now removes external endpoints, manifest
activation, JUnit gates, external SHA pinning, and cross-repository delivery.
Local unit, native-call, and integration-fixture assertions remain required.
The user also confirmed that taint-presence-only assertions are insufficient;
the plan keeps exact source/range/mark checks as a required improvement.

The driver used an OpenAI model. The critic used
`ai-gw-anthropic-1m/anthropic/claude-opus-5` with high reasoning. Its full initial
report is at `/tmp/propagation-coverage-plan-review.md`; the decisions below
preserve its material findings without depending on that temporary file.

The user requested a separate planning change. These documents are in
`lknrmnos`, above the original handoff change `qrzsppyv`.

## Verified evidence

The exact merged profile from PR head
`3168522002ee7e5eee83338e6c991c659415b6a7` is still available. Its SHA-256 is
`485b5a3b76ca8cd8295d7e2c3760a160dd34819e554c7556de22885e65b6dfe5`.
The propagation engine has 767 blocks and 1,194 statements. Of these, 128
blocks containing 142 statements have zero hits. The path table must account
for exactly those coordinates, not a new single-run profile.

The completed path table was checked against the profile: 128 rows, 142
statements, no missing coordinates, extra coordinates, or duplicate rows.
The driver corrected two classifications: valid count-one byte aliases are a
documented internal contract, while native string/byte writes above 4 GiB are
resource-budget exclusions, not impossible native counts. Final categories
are R 53, D 8, DN 7, DA 5, X 17, I 10, and U 42 statements.

The driver repeated the audit's standard-library alias probe on Go 1.26.6
(exit code 0). This confirmed unchanged-case and no-match string aliases,
the fresh `bytes.Repeat` result, and the shrinking one-byte case transform.

The published PR still has 25 successful checks. These checks validate the
existing code; they do not validate the proposed new scenarios.

The driver ran the existing `TestOperatorConcatAndSlices` through Orchestrion
on Go 1.26.6. The first targeted run failed at link time with the known
`internal/taint/iobridge` archive fingerprint mismatch. A fresh `GOCACHE` plus
explicit `-covermode=atomic -coverpkg=./...` passed with exit code 0. This
confirms native expressions in the external test package are injected; the
single-test coverage percentage is not used as a new coverage baseline.

The driver also corrected matrix draft errors before adoption: the 125 aspects
contain 30 writer call forms, not 32; native three-operand concatenation was
mislabelled as two operands; native Buffer tests already cover two owners;
and missing pointer-form advice is a test gap, not an N/A invariant. The pinned
injector resolves the type of the receiver expression for pointer/value matching.

## Critic findings and driver decisions

The first follow-up found S1-S12 resolved and independently confirmed the
operation counts and receiver-form gaps. Its two validation-order clarifications
are included: run nested woven coverage immediately after fixture import
changes, and distinguish the fuzz execution budget from its timeout deadline.
The final review checked the complete block table, independently reconciled
per-file and per-class totals, and verified the stale-owner, private-helper,
inline-race, and large-native-write distinctions against source. It accepted
the explicit residual set. Full final report:
`/tmp/propagation-coverage-plan-review-final.md`.

| Finding | Driver assessment and plan correction |
| --- | --- |
| S1: deterministic contention cannot be forced from current external propagation tests | Confirmed in `store/owner.go:131-176`. Put lock-order tests in existing in-package store tests. Keep engine stress evidence separate. List engine race blocks with no deterministic seam as residual gaps, not unreachable guards. User approval must include this limitation. An in-package propagation test alone does not expose the store's private lock. |
| S2: an exact per-byte oracle is wrong for coarse output | Confirmed in `propagation.go:325-331` and `string_coarse.go:162-187`. Generate exact-operation sequences. Use named coarse fixtures with the exact promised source selection and mark intersection. Reject the critic's weaker source-subset and unconditional taint-presence suggestions: they can miss source swaps or legitimate admission drops. |
| S3-S5: external gate delivery, fork behavior, and ref pinning | Superseded by the user's scope decision. External System Tests remain untouched and are not an acceptance condition for this work. |
| S6: mark checks use seeded state, not a production sanitizer | Name the existing store/ranges seeding recipe at `iast/propagation/writer_test.go:318`. Do not claim sanitizer coverage or add a public API. |
| S7: nested fixture access to internal packages must be clear | Existing integration tests already import internal packages. Use that existing access for inspection and seeded marks. No API expansion is required. |
| S8: native expressions can stay in external test files | Confirmed by existing operator tests. Prefer those files rather than adding ordinary helper code solely for the arity matrix. |
| S9: ordinary helpers enter coverage totals | Require any necessary new helper to execute in the woven root test run. Preserve thresholds and ignore rules. |
| S10: fuzz budgets were unspecified | Choose separate 10,000-execution campaigns per range/exact-sequence/lifecycle target in the root PR test job, four workers, bounded minimization and a five-minute command timeout. Seed replay remains additional evidence. No extra scheduled workflow is required. |
| S11: race scope and configuration mutation need bounds | Use `./internal/taint/...` for continuous runtime race checks; retain full local validation. Do not introduce parallel tests around mutable global configuration. |
| S12: temporary evidence can expire | Preserve the exact profile hash, coordinates, statement counts, and classifications in the planning documents. Do not replace the known merged baseline with a new ordinary-only run. |

## Review limitations and process note

The critic reported a passing race run for propagation, ranges, store, and
request. The driver has not used that report as proof of the future change's
validation. Ordinary, woven, nested-module, race, fuzz, and static checks still
need to run after implementation.

Markdown LSP diagnostics were unavailable because no Markdown server is
configured. The driver checked artifact scope, local document links, aspect
counts, and exact profile-coordinate reconciliation instead. No code build is
required for these planning-only edits.

The critic disclosed two read-only `git` commands before it re-read the explicit
jj-only rule. That violated the delegation instructions. No repository changes
resulted from those commands. The driver used jj, and any follow-up review must
avoid all version-control commands.

## Approval boundary

The operation/path artifacts and critic review are complete. The user approved
implementation of the revised local-coverage plan, including its explicit
coverage limits. That approval is not permission to publish this repository.

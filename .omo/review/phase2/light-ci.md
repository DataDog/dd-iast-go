# light-ci: CI and coverage tooling
Verdict: The CI matrix, nested-module coverage collection, coverage merger, and bounded fuzz targets are coherent; the race lane does not exercise Orchestrion-woven call sites.
Scope covered: `.github/workflows/ci.yml`, `.github/merge-coverage.py`, `.github/coverage_test.go`, and `code-coverage.datadog.yml`; root and nested module metadata; the named fuzz targets; CI-tool tests and the exact race commands. The coverage configuration file is unchanged from the merge base.
## Findings
### light-ci-F1: Race jobs do not test woven call sites
- Severity: Medium
- Category: test-gap
- Location: .github/workflows/ci.yml:150-151
- Claim: The race commands use plain `go test` against `./.github` and `./internal/taint/...`. Unlike the primary unit-test command immediately above, they do not invoke `go tool orchestrion`, and neither target exercises woven application call sites. Thus the race lane can pass without checking races introduced at instrumentation join points or in their woven integration.
- Evidence: `.omo/review/evidence/light-ci/race-coverage.txt`; command: `go test -race -shuffle=on ./.github && go test -race -count=1 -shuffle=on ./internal/taint/...`; captured output shows both commands pass, while the workflow source confirms they are ordinary `go test` commands.
- Fix: Add a race invocation through `go tool orchestrion go test -race` for the relevant woven integration tests, while retaining the plain internal-package race run.
## Checked and found correct
- Module discovery walks the repository, finds `go.mod` files (including the four nested modules), and prunes hidden directories and `vendor`; it also fails if no bootstrap symbol fixture is present.
- The nested test matrix chooses Orchestrion for modules with `orchestrion.tool.go`, gets the root package list for nested coverage, and excludes bridge packages as documented in the workflow. The database/sql nested-module coverage command completed successfully and emitted coverage for root packages linked into its test binaries.
- The four configured fuzz target names exist in the test suite. The campaigns are limited to 10,000 executions each, parallelism four, and a five-minute Go test timeout.
- Coverage profiles are required to use `atomic` mode; duplicate blocks are summed by location and statement count, then sorted in source order. The CI-tool tests pass, covering aggregation, ordering, preservation of blocks, and invalid profiles.
- Action references inspected in the workflow use full 40-character commit SHA references. Workflow-level permissions are read-only; only the coverage-upload job adds `id-token: write`, and checkout steps that do not need persisted credentials disable them.
- `code-coverage.datadog.yml` retains its existing 85% patch and total thresholds and is unchanged from the merge base.
## Not covered / open questions
- The four fuzz campaigns were not run; only their configured target names and bounds were inspected.
- Action SHA immutability was checked syntactically from the workflow; upstream release-tag correspondence was not independently verified.
- Nested coverage execution was exercised for `iast/database/sql/testapp`, not all four nested modules.

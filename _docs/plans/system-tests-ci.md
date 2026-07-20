# System-tests CI

## Objective

Add GitHub Actions CI that validates the current `dd-iast-go` revision against
`DataDog/system-tests`, following the established `dd-trace-go` system-tests
workflow while limiting execution to the Go Orchestrion weblog and the IAST
behavior implemented by this module.

## Scope

The workflow will:

- build the `golang` `net-http-orchestrion` weblog with the checked-out
  `dd-iast-go` working revision;
- run the `DEFAULT` and `IAST_DEDUPLICATION` scenarios;
- run on pull requests from the main repository, selected pushes, a nightly
  schedule, manual dispatch, and reusable-workflow calls;
- pin one exact `system-tests` revision per workflow run;
- retain test logs and report JUnit results through the system-tests action;
- expose one stable aggregate job for branch protection.

The workflow will not:

- run non-Orchestrion Go weblog variants, because they cannot load this module;
- run general tracing, AppSec, RASP, GraphQL, proxy, or APM end-to-end scenarios;
- publish container images;
- modify `system-tests`, `dd-trace-go`, or the product implementation.

## Scenario selection

### Included

1. `DEFAULT`
   - The default weblog container configuration enables IAST with 100% request
     sampling and deduplication disabled.
   - For `golang/net-http-orchestrion`, the manifest enables the implemented
     weak-hash and weak-cipher tests, including their extended-location checks.
   - This is the primary end-to-end validation that the local module is loaded,
     instruments the weblog, and emits valid IAST events.

2. `IAST_DEDUPLICATION`
   - Enables IAST deduplication with 100% request sampling.
   - Selects the dedicated weak-hash deduplication tests, which the Go manifest
     enables for `net-http-orchestrion`.
   - This directly exercises module behavior that `DEFAULT` intentionally turns
     off.

### Excluded for now

- `IAST_STANDALONE`: its system-tests coverage is the standalone distributed
  propagation contract (`Test_IastStandalone_UpstreamPropagation_V2`), which
  the Go manifest currently marks `missing_feature`. It does not add coverage
  for the implemented weak-hash or weak-cipher sinks.
- `APPSEC_META_STRUCT_DISABLED`: the Go manifest currently marks both IAST
  metastruct tests irrelevant due to absent IAST support in that compatibility
  declaration. It should be reconsidered when those declarations and fallback
  behavior are implemented.
- Other AppSec/IAST scenarios: no other scenario provides enabled
  `dd-iast-go`-specific tests for the current feature set.

## Implementation

Create `.github/workflows/system-tests.yml`, adapted from
`../dd-trace-go/.github/workflows/system-tests.yml`.

### Events and permissions

- Support `workflow_call` with a required `branch_ref` input.
- Support `workflow_dispatch` with a `system-tests` ref input defaulting to
  `main`.
- Run for `pull_request`, `merge_group`, nightly `schedule`, pushes to `main`,
  and manual/reusable invocations. `main` is the only integration branch
  present in this repository. Use GitHub's native `merge_group` event rather
  than copying `dd-trace-go`'s repository-specific `mq-working-branch-**` push
  convention, and do not copy its unrelated tag filters.
- Grant only `contents: read` and `id-token: write`. The latter is required by
  the system-tests Test Optimization upload action. Do not request package
  write access because this workflow publishes no images.
- Add workflow-level concurrency keyed by workflow and ref. Cancel superseded
  pull-request runs only; do not cancel `main` or `merge_group` runs that may be
  serving as required integration checks.
- Guard build and test jobs against pull requests from forks, as in
  `dd-trace-go`; the aggregate job must still report a successful skipped state
  rather than waiting for unavailable OIDC credentials.

### Pin the system-tests checkout

Add a `warm-repo-cache` job that:

1. checks out `DataDog/system-tests` at the dispatched ref (or `main` when no
   dispatch ref is supplied), without persisted credentials;
2. resolves and exports the exact checked-out commit SHA;
3. caches the checkout's `.git` directory using that SHA.

All downstream jobs restore and check out that exact SHA, with an
`actions/checkout` fallback on cache miss. This prevents the image build and
scenario executions from observing different `system-tests` revisions.

### Build the weblog once

Add a `build-weblog-image` job that:

1. restores the pinned system-tests checkout;
2. checks out this repository revision to `binaries/dd-iast-go` using
   `branch_ref` for reusable calls and the triggering commit otherwise;
3. reads the exact `github.com/DataDog/dd-trace-go/v2` version required by that
   checkout's `go.mod` and writes
   `binaries/golang-load-from-go-get` in the form
   `github.com/DataDog/dd-trace-go/v2@<exact-version>`;
4. runs
   `./build.sh golang -i weblog -w net-http-orchestrion --save-to-binaries`;
5. uploads
   `binaries/golang-net-http-orchestrion-weblog.tar.zst` as a one-day artifact.

The system-tests Go image build detects `/binaries/dd-iast-go` and adds a Go
module replacement for the local checkout. The explicit
`golang-load-from-go-get` file prevents `install_ddtrace.sh` from replacing the
module with non-hermetic `dd-trace-go@latest`; instead, it resolves and replaces
`dd-trace-go` and its used contrib modules at the exact version against which
the checked-out `dd-iast-go` was developed. Orchestrion remains supplied by the
normal system-tests weblog configuration.

### Run the limited scenario matrix

Add a `system-tests` job, dependent on the cache and image jobs, with a
fail-slow matrix containing exactly:

- `DEFAULT`
- `IAST_DEDUPLICATION`

Each matrix entry will:

1. restore the exact pinned system-tests checkout;
2. check out this repository revision to `binaries/dd-iast-go` (the scenario
   job does not rebuild the image, so it does not need to regenerate the
   `golang-load-from-go-get` file);
3. download the prebuilt weblog artifact;
4. run `./build.sh golang -i weblog -w net-http-orchestrion` to load the saved
   image metadata;
5. install the system-tests runner;
6. execute `./run.sh <scenario>` with
   `SYSTEM_TESTS_WEBLOG=net-http-orchestrion`;
7. parse `logs*/reportJunit.xml` and fail unless the scenario's expected IAST
   tests were actually executed (not absent or skipped): weak hash and weak
   cipher for `DEFAULT`, and `TestDeduplication` for
   `IAST_DEDUPLICATION`;
8. always invoke the system-tests `push_to_test_optim` action at the same
   immutable action revision used by the current `dd-trace-go` precedent;
9. always archive any `logs*/` directories and upload a scenario-specific log
   artifact, while handling absent logs without failing the archive step.

No Datadog application key is needed by these scenarios. The result-upload
composite action attempts to obtain its own short-lived API key via the
`system-tests` OIDC policy and tolerates credential acquisition failure. Test
execution must not depend on upload authorization; confirm separately whether
the policy is authorized for `DataDog/dd-iast-go`, because an unauthorized
repository will skip uploads without failing the workflow. The action's literal
SHA is maintained independently from the dynamically pinned system-tests
checkout SHA, as required by GitHub Actions syntax.

### Stable aggregate result

Add `system-tests-done`, named `System Tests`, depending on both the build and
scenario jobs. It runs when dependencies finish unless the workflow is
cancelled and succeeds only when both dependencies succeeded, except that both
may be skipped specifically when the event is a pull request whose head
repository is not `DataDog/dd-iast-go`. Do not accept a skipped dependency for
other events. This intentionally differs from the current `dd-trace-go`
aggregate, which treats fork skips as failures, and provides a single
branch-protection check independent of matrix expansion.

## Validation

Before committing the implementation:

1. Parse the workflow as YAML and run `actionlint` if available.
2. Compare every external action reference and SHA with the current
   `dd-trace-go` precedent; keep actions pinned to immutable revisions.
3. Verify the matrix contains only `DEFAULT` and `IAST_DEDUPLICATION`, and that
   every build/run command names `golang` and `net-http-orchestrion`.
4. Test the JUnit assertion against representative report files or a local run;
   verify it rejects missing and skipped expected tests without rejecting a
   report containing successful expected tests.
5. Verify the local checkout path is exactly `binaries/dd-iast-go`, matching
   `system-tests/utils/build/docker/golang/install_orchestrion.sh`.
6. Verify fork pull requests cannot enter build/test jobs and that the
   aggregate check treats those skipped dependencies as successful.
7. Verify the workflow has explicit coverage for pushes to `main` and native
   merge-queue validation through `merge_group`.
8. Verify the generated `golang-load-from-go-get` entry exactly matches the
   `dd-trace-go/v2` version in the checked-out `dd-iast-go/go.mod`, and verify
   build logs show that `install_ddtrace.sh` took its load-from-go-get path
   rather than the `@latest` production path.
9. Confirm whether the `system-tests` OIDC policy accepts this repository, while
   keeping result upload best-effort either way.
10. If feasible in the local environment, build the weblog once against the
   local checkout and run both scenarios. Otherwise, document that end-to-end
   execution requires Docker and defer that evidence to the first workflow run.
11. Review the final diff for least-privilege permissions, bounded artifact
   retention, and absence of unrelated CI or product changes.

## Follow-up criteria

Revisit the scenario matrix when `system-tests/manifests/golang.yml` enables a
new IAST test for `net-http-orchestrion`. Add a scenario only if it selects an
enabled behavior not already covered by `DEFAULT`; in particular,
`IAST_STANDALONE` becomes worthwhile when Go implements its standalone
propagation contract.

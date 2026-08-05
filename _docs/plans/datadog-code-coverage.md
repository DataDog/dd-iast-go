# Plan: Report Test Coverage to Datadog

## Goal

Have the main CI workflow produce Go coverage for the root module and upload it
to Datadog Code Coverage using the same OIDC-based credential exchange and
coverage upload action used by `DataDog/dd-trace-go`.

## Delivery Gate

This plan is the current deliverable. Implementation will not begin until the
user approves it; the approved plan will then be committed separately as
`wip(plan): report test coverage to Datadog`. After the implementation has been
delivered and accepted, this plan will be removed so it remains in change
history without becoming permanent repository documentation.

## Reference Setup

The implementation follows the relevant, simpler subset of the current
`DataDog/dd-trace-go` setup:

- publish the Go cover profile from the unprivileged test job with
  `actions/upload-artifact`;
- isolate `id-token: write` in a separate coverage-submission job that does not
  build or execute repository code;
- download the profile there with `actions/download-artifact`;
- exchange that job's OIDC token for a short-lived Datadog API key with
  `DataDog/dd-sts-action`;
- upload the downloaded Go cover profile with
  `DataDog/coverage-upload-github-action`, explicitly selecting the
  `go-coverprofile` format;
- run the submission job under `if: always()` so it can handle profiles from
  failed test runs, while making credential acquisition and upload non-blocking
  and conditional on their prerequisite steps;
- add `code-coverage.datadog.yml` with `schema-version: v1` and
  `carryforward: false`, matching `dd-trace-go` and preventing an old report
  from being presented as current coverage when a commit has no successful
  upload.

All four actions involved in artifact transfer and Datadog submission will be
pinned to immutable commit SHAs rather than mutable tags.

## Prerequisite: Orchestrion Coverage Support

The implementation is blocked until Orchestrion can successfully build and run
this repository's test binaries with Go coverage instrumentation. With the
currently selected Orchestrion version, adding `-coverprofile` causes package
fingerprint mismatches at link time, including with a fresh Go build cache and
an explicit `-coverpkg` covering the root module. That defect must be fixed in
Orchestrion and this repository must consume a release containing the fix
before implementation of this plan begins. This plan does not introduce an
uninstrumented fallback or knowingly publish incomplete coverage.

Verify the prerequisite with the exact intended CI command and a fresh Go build
cache before changing the workflow:

```console
go tool orchestrion go test \
  -shuffle=on \
  -covermode=atomic \
  -coverpkg=./... \
  -coverprofile=coverage.txt \
  ./...
```

The command must complete successfully, all tests that require Orchestrion must
run rather than skip, and `go tool cover -func=coverage.txt` must parse the
result. If satisfying the prerequisite requires updating the Orchestrion tool
dependency, that update and its own validation should be delivered separately
before this CI integration so the coverage change rests on a known-good tool
version.

Once the prerequisite is met, replace the existing test invocation with the
command above. This produces one profile from the same woven test binaries that
provide the CI test signal, avoiding duplicate test execution and preserving
coverage from instrumentation-dependent tests.

The nested `benchmarks/overhead` module is excluded. Its tests validate the
benchmark harness rather than the shipped root module, it is already tested by
a separate CI command, and a root-module Go cover profile cannot include it in
the same invocation.

## Workflow Changes

### `.github/workflows/ci.yml`: `test` job

Keep the existing global `contents: read` permission; do not grant the test job
`id-token: write`.

1. Update `Unit Tests` to run the Orchestrion-wrapped command with
   `-covermode=atomic` and `-coverprofile=coverage.txt`. This single invocation
   remains the test gate and collects coverage from the woven test binaries.
2. Add an `Upload coverage artifact` step after the test commands, using a
   SHA-pinned `actions/upload-artifact`. Run it under `if: always()` so a profile
   produced before a test failure remains available. Upload only
   `coverage.txt`, use a stable artifact name such as `coverage-profile`, set a
   short retention period, and configure a missing profile not to introduce a
   second failure when the test command failed before producing one.

### `.github/workflows/ci.yml`: `upload-coverage` job

Add a dedicated job that depends on `test` and runs under `if: always()`, so it
can submit any profile produced by a failed test run. Grant only this job:

```yaml
permissions:
  contents: read
  id-token: write
```

The job must not compile, test, or execute repository code. Its steps are:

1. Check out the exact workflow commit with credentials disabled, solely to
   provide repository metadata and the checked-in Datadog coverage
   configuration to the uploader.
2. Download `coverage-profile` with a SHA-pinned
   `actions/download-artifact`. Treat a missing artifact as non-fatal and use
   its outcome to skip the remaining submission steps.
3. Get Datadog credentials using the same immutable
   `DataDog/dd-sts-action` revision as `dd-trace-go`, with the
   repository-specific policy name `dd-iast-go`. Run only after a successful
   artifact download and use `continue-on-error: true`.
4. Upload the downloaded `coverage.txt` using the same immutable
   `DataDog/coverage-upload-github-action` revision as `dd-trace-go`, passing
   the STS API key and `format: go-coverprofile`. Run only after both artifact
   download and credential acquisition succeed, and use
   `continue-on-error: true`.

This boundary keeps OIDC token minting out of the job that builds and runs
repository-controlled code. The privileged job handles the profile as data and
runs only narrowly selected, SHA-pinned actions.

The repository's Datadog STS configuration must contain a trust policy named
`dd-iast-go` authorizing this GitHub repository and the Code Coverage upload.
That policy is infrastructure outside this repository. If it does not already
exist, it must be provisioned before uploads can succeed; CI tests will remain
unaffected because both Datadog integration steps are non-blocking.

### `code-coverage.datadog.yml`

Add:

```yaml
schema-version: v1
carryforward: false
```

### `.gitignore`

Create the repository-level ignore file with:

```gitignore
/coverage.txt
```

The root-anchored rule covers the workflow's generated profile while avoiding
an unnecessarily broad rule for intentionally checked-in fixtures in nested
directories. This makes accidental tracking of the generated report impossible
without an explicit force operation.

## Validation

Before committing the implementation:

1. Validate the workflow YAML syntax and inspect the action expressions,
   dependency conditions, and permissions. Confirm that `id-token: write`
   appears only on `upload-coverage`, and that this job runs no repository
   commands.
2. Generate the profile with the instrumented suite, using a fresh Go build
   cache to ensure success does not depend on stale artifacts, then inspect it:

   ```console
   cache_dir="$(mktemp -d)"
   GOCACHE="$cache_dir" go tool orchestrion go test \
     -shuffle=on \
     -covermode=atomic \
     -coverpkg=./... \
     -coverprofile=coverage.txt \
     ./...
   go tool cover -func=coverage.txt
   rm -rf "$cache_dir"
   ```

   Confirm that instrumentation-dependent tests ran rather than skipped and
   that the profile contains their woven packages.

3. Run the nested-module unit tests still present in the CI job:

   ```console
   go -C benchmarks/overhead test -shuffle=on ./...
   ```

4. Confirm `coverage.txt` is ignored and absent from `jj status`, remove it and
   the temporary build cache after validation, then inspect `jj diff` for
   generated or unrelated files.
5. Confirm in a GitHub Actions run that `test` publishes only
   `coverage.txt`, `upload-coverage` downloads that artifact, OIDC credential
   acquisition succeeds only in the latter job, the uploader identifies the
   file as a Go cover profile, and Datadog associates the report with the
   expected repository and commit.
6. Exercise or inspect the failed-test/no-profile path and confirm the test
   failure remains the meaningful failure while artifact and Datadog steps do
   not obscure it.

## Acceptance Criteria

- An Orchestrion release that fixes coverage-instrumented builds is consumed
  and validated before this workflow implementation begins.
- The existing Orchestrion test suite and nested benchmark-module tests
  continue to run and retain their current failure behavior.
- The test job produces a valid Go cover profile for the root module from the
  Orchestrion-built test binaries; no uninstrumented fallback or duplicate test
  run is used.
- The generated root `coverage.txt` is ignored by version control and cannot be
  tracked accidentally.
- The test job publishes `coverage.txt` as a short-lived workflow artifact but
  cannot mint an OIDC token.
- Only the dedicated coverage-submission job receives `id-token: write`; it
  does not build, test, or execute repository code.
- CI exchanges GitHub OIDC identity for short-lived Datadog credentials; no
  long-lived API key is added to repository secrets or workflow text.
- Coverage is uploaded to Datadog using SHA-pinned actions and an explicit Go
  coverage format.
- Datadog credential or upload failures do not turn an otherwise successful CI
  run red.
- Datadog does not carry forward stale coverage when a commit has no successful
  report.

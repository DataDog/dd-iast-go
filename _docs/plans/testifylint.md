## Decisions

### Assertion: `InDelta` with delta `0`; keep `assert` or `require` as it is

Replace `Equal(t, 1.0, <span>.Tag(spans.SpanTagEnabled))` with `InDelta(t, 1.0, <span>.Tag(spans.SpanTagEnabled), 0)` at the 6 sites. Line numbers are from `main` at `7ad1c4b`.

| File:line | Before | After |
|---|---|---|
| `iast/crypto/cipher/cipher_test.go:307` | `assert.Equal(t, 1.0, span.Tag(spans.SpanTagEnabled))` | `assert.InDelta(t, 1.0, span.Tag(spans.SpanTagEnabled), 0)` |
| `iast/crypto/hash/hash_test.go:53` | `assert.Equal(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled))` | `assert.InDelta(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled), 0)` |
| `iast/crypto/hash/hash_test.go:136` | `assert.Equal(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled))` | `assert.InDelta(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled), 0)` |
| `iast/crypto/hash/hash_test.go:237` | `assert.Equal(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled))` | `assert.InDelta(t, 1.0, spanList[0].Tag(spans.SpanTagEnabled), 0)` |
| `_integration/otelc/internal/suite/span.go:60` | `assert.Equal(t, 1.0, request.Tag(spans.SpanTagEnabled))` | `assert.InDelta(t, 1.0, request.Tag(spans.SpanTagEnabled), 0)` |
| `_integration/otelc/internal/suite/suite.go:333` | `require.Equal(t, 1.0, span.Tag(spans.SpanTagEnabled))` | `require.InDelta(t, 1.0, span.Tag(spans.SpanTagEnabled), 0)` |

Reasons:
- **The tag is a flag (`1` or `0`), not a computed value.** Delta `0` keeps the check exact. A tolerance has no meaning for a flag.
- **The linter accepts it.** In `testifylint` v1.6.4, `float-compare` reports only `Equal`, `EqualValues` and `Exactly` with a float argument, and `True`/`False` with a float `==`/`!=` ([`float-compare`](https://github.com/Antonboom/testifylint/blob/v1.6.4/README.md#float-compare), source `internal/checkers/float_compare.go`). No checker reports the new lines, also with `enable-all: true`.
- **Behavior of testify v1.12.1 on `interface{}`.** `InDelta` converts both values with `toFloat` (`assert/assertions.go:1413`). It fails for non-numeric values and for `nil`. Measured with a temporary test:

  | Value of the tag | `Equal(t, 1.0, v)` | `InDelta(t, 1.0, v, 0)` |
  |---|---|---|
  | `float64(1)` | pass | pass |
  | `int(1)` | fail | **pass** |
  | `float64(0)` | fail | fail |
  | `float64(1 + 1e-15)` | fail | fail |
  | `"1"`, `true`, `nil` | fail | fail |

- **The only difference (`int(1)` passes) has no effect here.** The tracer keeps each numeric tag as `float64`: `metrics map[string]float64` (dd-trace-go v2.12.0, `ddtrace/tracer/span.go:153`). `mocktracer.Span.Tag` reads `AsMap()` first (`ddtrace/mocktracer/mockspan.go:66`). The production code sets the int `1` (`internal/spans/annotation.go:72`, `internal/spans/vulnerability.go:16`), and the tests read `float64(1)`.
- **The new assertion still finds a regression.** With `annotation.go:72` and `vulnerability.go:16` changed to `0`, `TestMD5` fails: `Max difference between 1 and 0 allowed is 0, but difference was 1`.
- **`assert`/`require` stay the same.** `require` in `vulnerabilityEvent` stops the test before it reads the JSON tag. If you change the package, you change when the test stops.
- **The expected value stays `1.0`.** It shows that the tag is a numeric metric.

Options not selected:

| Option | Why not |
|---|---|
| `InEpsilon(t, 1.0, v, 0)` | Relative error is not correct for a flag. It always fails when the expected value is `0` ("expected value must have a value other than zero"), so a later test of the `0` case cannot use the same pattern. |
| `InDelta` with a tolerance (for example `1e-9`) | It tells the reader that the value is computed. It is a flag. |
| `EqualValues(t, 1, v)` | The int literal hides the float from the linter. The check passes because of a type trick, and the reader cannot see why. |
| Type assertion or `IsType` + `InDelta` | 2 or 3 lines at each of the 6 sites, to check a type that the tracer always gives (see above). |
| `//nolint:testifylint // <reason>` at 6 sites | 6 directives for a pattern that the linter reports correctly. The scope is to fix the findings. |
| `linters.settings.testifylint.disable: [float-compare]` | Not the default settings. It also stops the check for real computed floats in new tests. |
| One shared test helper for the tag | The 6 sites are in 3 packages and 2 modules. A shared helper needs a new test package for 6 one-line changes. |

### `iast/crypto/hash/hash_test.go:237`: fix it, because it is a real finding

This is not only a change for consistency. `testifylint` reports the line. golangci-lint hides it with the default `issues.max-same-issues: 3`, because the root module has 4 identical messages. The configuration of [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) sets `max-same-issues: 0`. Then CI reports the line and fails if it is not fixed.

Measured on `main` at `7ad1c4b` (only `testifylint` enabled):

| `issues` settings | Root module | `_integration/otelc` | Other 3 modules | Total |
|---|---|---|---|---|
| golangci-lint defaults | 3 | 2 | 0 | 5 |
| Limits at 0 (as in [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104)) | 4 | 2 | 0 | **6** |
| Limits at 0 and `enable-all: true` | 4 | 2 | 0 | 6 |

### `.golangci.yml`: add 1 line, with no settings block

Change to the `.golangci.yml` from [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104):

```diff
 linters:
   default: standard # errcheck, govet, ineffassign, staticcheck, unused
   enable:
     - errorlint
     - gosec
     - misspell
     - nolintlint
+    - testifylint
   settings:
```

Reasons:
- **Default checks.** testifylint v1.6.4 enables 24 of its 25 checkers by default (`suite-thelper` is off). This is the same as `DataDog/orchestrion`: `testifylint` is in `linters.enable`, with no `linters.settings.testifylint` ([pinned `.golangci.yml`](https://github.com/DataDog/orchestrion/blob/7aa5a8c4134a61447b0b6b128608f0434ea7730b/.golangci.yml#L1-L138)).
- **No CI change.** The `golangci-lint` job from [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) reads the root `.golangci.yml` in all 5 modules.
- **No new dependency.** golangci-lint v2.15.0 contains testifylint v1.6.4 ([`go.mod`](https://github.com/golangci/golangci-lint/blob/v2.15.0/go.mod#L27)).
- **If the `enable` list on `main` is different** when [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) merges, add `testifylint` in alphabetical order. The change stays 1 line.
- **Measured:** `golangci-lint config verify` passes with this file. With the 6 assertion changes, `testifylint` reports 0 findings in the 5 modules. The other linters give the same 44 findings as the [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) baseline (same set before and after the test changes), so the test changes add no new finding.

Options not selected:

| Option | Why not |
|---|---|
| `enable-all: true` | 0 more findings today. But each golangci-lint update can then enable new optional checkers, with no review of the change. It is also different from `DataDog/orchestrion`. |
| A `linters.settings.testifylint` block with the default values | It has no effect, and it must be kept up to date. |

### Delivery: 1 PR from `main`; the `.golangci.yml` commit comes after [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) merges

Commits, in this order:
1. This design document: `wip(plan): enable testifylint and fix float-compare test findings`.
2. The 6 assertion changes: `test: compare the IAST enabled span tag with InDelta`. This commit does not need [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104): the tests pass on `main` today.
3. A merge of `main`, after [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) is merged.
4. The `.golangci.yml` line: `ci(lint): enable testifylint`.
5. Deletion of this design document, before merge.

The PR stays a draft until [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) is merged.

Options not selected:

| Option | Why not |
|---|---|
| Stack the PR on the branch of [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) | That branch still gets commits, and its design document will be deleted. The stacked PR shows the full diff of [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) until it merges. This adds work for a 1-line configuration change. |
| Add `testifylint` to [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) | Its approved design puts `testifylint` out of scope ("a test-code change, not a lint setup"). |
| 2 PRs (test changes now, configuration later) | The test changes have no reason without the linter. 1 small PR keeps the reason with the change. |

### Docs: no change

- [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) adds the `golangci-lint` command and version to `AGENTS.md` and `CONTRIBUTING.md`. It does not add a list of linters. So this PR changes no documentation.
- If the merged `AGENTS.md` or `CONTRIBUTING.md` has a list of linters, add `testifylint` to it.

### Findings in other open pull requests: the PR that merges second fixes them

Measured on the head of each open PR, with only `testifylint` enabled (limits at 0):

| PR | New findings | Where |
|---|---|---|
| [DataDog/dd-iast-go#106](https://github.com/DataDog/dd-iast-go/pull/106) (replaces [DataDog/dd-iast-go#95](https://github.com/DataDog/dd-iast-go/pull/95); head `8f734fd`) | 7 | 5 `require-error` in `_integration/otelc/internal/sentinel/main_test.go:37,85-88`; `float-compare` in `internal/instrumentation/heartbeat/heartbeat_test.go:168` and in `_integration/otelc/internal/suite/span.go:58` |
| [DataDog/dd-iast-go#100](https://github.com/DataDog/dd-iast-go/pull/100) | 6 | the same 5 `require-error`; the same `heartbeat_test.go:168` |
| [DataDog/dd-iast-go#93](https://github.com/DataDog/dd-iast-go/pull/93) | 5 | the same 5 `require-error` |
| [DataDog/dd-iast-go#92](https://github.com/DataDog/dd-iast-go/pull/92), [DataDog/dd-iast-go#101](https://github.com/DataDog/dd-iast-go/pull/101), [DataDog/dd-iast-go#102](https://github.com/DataDog/dd-iast-go/pull/102), [DataDog/dd-iast-go#103](https://github.com/DataDog/dd-iast-go/pull/103) | 0 | none |

[DataDog/dd-iast-go#39](https://github.com/DataDog/dd-iast-go/pull/39) and [DataDog/dd-iast-go#58](https://github.com/DataDog/dd-iast-go/pull/58) are based on an older `main` and have many findings. They fix them when they update against `main`.

Rule:
- If one of these PRs merges before this PR: merge `main` into this PR and fix the new findings here. Use `InDelta(..., 0)` for an exact float flag or count. Use `require.<same function>` for `require-error` (for example `require.ErrorContains`).
- If this PR merges first: the other PR fixes its own findings when it updates against `main`. Its `golangci-lint` CI leg fails until it does.

Reason: this is the same non-blocking rule that [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) uses for its in-flight PRs. This PR does not wait for code that is not on `main`.

## Constraints

1. Merge order: [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) merges before this PR. This PR cannot change `.golangci.yml` before that, because the file is not on `main`.
2. No production code change. Only the 4 test files and `.golangci.yml` change.
3. No version change: testify v1.12.1, golangci-lint v2.15.0 (testifylint v1.6.4).
4. The line numbers are from `main` at `7ad1c4b`. [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) adds only same-line `//nolint` comments in these files, so the lines do not move. The lint output is the final list.
5. Feature parity between Orchestrion and otelc: not affected. No change to `orchestrion.yml` or `otelc.yml`. Both tools run the changed tests.
6. Repository files, commit messages and the PR body contain no internal tracker keys, IDs or URLs, and no opaque plan labels.

## Acceptance criteria

All commands run from the repository root with golangci-lint v2.15.0 and Go `oldstable`, after the merge of `main` that contains [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104).

- [ ] `lint`: `golangci-lint config verify` passes.
- [ ] `lint`: this command prints `0 issues.` for each of the 5 modules:
  ```console
  for module in . benchmarks/overhead _integration/otelc \
      _integration/otelc/setups/hashonly _integration/otelc/setups/rootandhash; do
    (cd "${module}" && golangci-lint run ./...)
  done
  ```
- [ ] `lint`: `golangci-lint linters` shows `testifylint` under `Enabled by your configuration linters`.
- [ ] `lint`: local negative check: change `iast/crypto/cipher/cipher_test.go:307` back to `assert.Equal(t, 1.0, ...)`; `golangci-lint run --enable-only testifylint ./...` reports 1 `float-compare` finding. Revert the change.
- [ ] `lint`: `git diff origin/main -- .golangci.yml` shows exactly 1 added line (`    - testifylint`) and no `testifylint:` key under `linters.settings`.
- [ ] `lint`: `rg -n 'Equal\(t, 1\.0' --type go` gives no result, and `rg -n 'InDelta\(t, 1\.0, .*Tag\(spans\.SpanTagEnabled\), 0\)' --type go | wc -l` gives `6`.
- [ ] `unit`: `DD_IAST_EXPECTED_BUILD_TOOL=orchestrion go tool orchestrion go test -shuffle=on ./iast/crypto/cipher/ ./iast/crypto/hash/` passes.
- [ ] `unit`: `scripts/otelc-test.sh -shuffle=on` passes.
- [ ] `integration`: in `_integration/otelc`, `go tool orchestrion go test -shuffle=on . ./internal/...` and `go tool otelc go test -shuffle=on . ./internal/...` pass.
- [ ] `integration`: in `_integration/otelc/setups/hashonly` and `_integration/otelc/setups/rootandhash`, `go tool otelc go test -shuffle=on ./...` passes (these modules import `internal/suite`).
- [ ] `ci`: the 5 `golangci-lint` legs, the `test` and `integration` jobs, and `green-ci` are green.
- [ ] `docs`: `_docs/plans/testifylint.md` is deleted before merge.
- [ ] `hygiene`: no internal tracker key, ID or URL, and no opaque plan label, in the diff, the commits or the PR body.

## Review requirements

1. Romain approves this design in the draft PR before implementation.
2. The Reviewer checks:
   - the 6 sites use `InDelta` with delta exactly `0`;
   - each site keeps its `assert` or `require` package;
   - the `.golangci.yml` diff is 1 line, with no settings block;
   - no production file changes;
   - the merged `main` contains [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104).
3. Adversarial review is not necessary: the change is low risk (test files and 1 configuration line, no public API, no security boundary, no performance effect).

## Risks

| Risk | What reduces it |
|---|---|
| [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) changes its `enable` list or its limits before it merges | The PR is a draft until [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) merges. The rule "add `testifylint` in alphabetical order" works for each list. The acceptance check runs with the merged file. |
| An open PR merges first and adds findings ([DataDog/dd-iast-go#93](https://github.com/DataDog/dd-iast-go/pull/93), [DataDog/dd-iast-go#106](https://github.com/DataDog/dd-iast-go/pull/106), [DataDog/dd-iast-go#100](https://github.com/DataDog/dd-iast-go/pull/100)) | The merge-order rule above. The 5-module lint check after the merge of `main` shows each new finding. |
| Text conflict with [DataDog/dd-iast-go#106](https://github.com/DataDog/dd-iast-go/pull/106) in `_integration/otelc/internal/suite/span.go` (it changes the lines near 60) | The change is 1 line. The PR that merges second keeps the `InDelta` form. |
| `InDelta` accepts `int(1)` | The tracer stores all numeric tags as `float64` (see the assertion decision). The value check stays exact. |
| A later golangci-lint update adds new default testifylint checks | The binary version is pinned (`v2.15.0`). The PR that changes the version fixes the new findings. |

## Out of scope

- Optional testifylint checkers (`enable-all`).
- Changes to the `golangci-lint` CI job or its version.
- Fixes for findings that exist only on unmerged branches (see the merge-order rule).
- A shared test helper for the IAST enabled tag.

## Path of the temporary design document

`_docs/plans/testifylint.md`, committed with the title `wip(plan): enable testifylint and fix float-compare test findings` (`AGENTS.md`, section `## Plans`). It is deleted in the last commit before merge.

## How the facts were checked

Read-only, on copies of `main` at `7ad1c4b` and of the open PR heads (the checkout did not change):
- golangci-lint v2.15.0, only `testifylint` enabled, in each of the 5 modules: with default limits, with limits at 0, and with `enable-all: true` (table above).
- The configuration of [DataDog/dd-iast-go#104](https://github.com/DataDog/dd-iast-go/pull/104) plus `testifylint`, with the 6 changes: 0 `testifylint` findings; the other 44 findings are the same set as without the changes.
- Tests with the 6 changes (all pass; times on a laptop): Orchestrion unit tests of `iast/crypto/cipher` and `iast/crypto/hash` (1 min 6 s); `scripts/otelc-test.sh -shuffle=on` (2 min 25 s); `_integration/otelc` with Orchestrion (1 min 37 s) and otelc (52 s); both setups with otelc (about 1 min each).
- Regression check: production tag set to `0` makes `TestMD5` fail (see above).
- Sources read: testifylint v1.6.4 `internal/checkers/float_compare.go` and `checkers_registry.go`; testify v1.12.1 `assert/assertions.go` (`InDelta`, `InEpsilon`, `toFloat`); dd-trace-go v2.12.0 `ddtrace/tracer/span.go` and `ddtrace/mocktracer/mockspan.go`.

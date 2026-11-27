## Decisions

### Linter set: `standard` + `gosec` + `nolintlint` + `errorlint` + `misspell`

Exact `.golangci.yml` (repository root):

```yaml
version: "2"

linters:
  default: standard # errcheck, govet, ineffassign, staticcheck, unused
  enable:
    - errorlint
    - gosec
    - misspell
    - nolintlint
  settings:
    gosec:
      excludes:
        - G104 # Same check as errcheck. errcheck already ignores hash.Hash.Write.
    nolintlint:
      require-explanation: true
      require-specific: true
  exclusions:
    generated: lax
    rules:
      # Developer CLI. It is not shipped. It copies source trees, writes files
      # and runs "go" by design, with paths from its own flags.
      - path: ^benchmarks/overhead/runner/
        linters:
          - gosec

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
  uniq-by-line: false
```

Reasons:
- **`gosec`: yes.** This library runs inside customer applications, and it is a security product. The 7 existing `//nolint:gosec` directives show that the authors expect `gosec`. Without `gosec`, these 7 directives have no effect.
- **`G104` off:** it reports the same thing as `errcheck`, but without the `errcheck` default exclusions. All 3 `G104` findings are `hasher.Write` on an FNV hash (`internal/model/vulnerability.go:27,31,38`), which never returns an error.
- **`benchmarks/overhead/runner/` path rule:** all 17 `gosec` findings there (`G122`, `G204`, `G301`, `G304`, `G306`, `G703`) are file and process operations that the tool must do. 17 `//nolint` lines in a dev tool are noise. Weak-crypto rules do not apply there (the runner has no crypto code).
- **`nolintlint` with explanation + specific:** this design adds 29 directives. `nolintlint` makes sure that each one names its linter, has a reason, and is still used.
- **`errorlint`, `misspell`:** 0 findings today. They are in the configs of `DataDog/go-libddwaf` and `DataDog/orchestrion`. They cost nothing.
- **Limits set to 0 and `uniq-by-line: false`:** with the defaults, a fix shows hidden findings on the next run. I saw this: after the permission fixes, `G703` and more `G304` findings came out. CI must show all findings in 1 run.
- **No `run.build-tags`:** see the build-tagged files section.

Options not selected:

| Option | Why not |
|---|---|
| `standard` only (13 findings) | The 7 `//nolint:gosec` directives do nothing, and weak crypto in production code is not detected. |
| `+ testifylint` | 5 `float-compare` findings in tests. That is a test-code change, not a lint setup. See Follow-up. |
| `+ revive`, `perfsprint`, `gocritic` | Style rules. A new style policy needs its own decision. |
| Path rule for weak crypto in all test code | It hides weak crypto that is not intentional (for example a checksum in a test helper). It also goes against the rule in [DataDog/dd-iast-go#101](https://github.com/DataDog/dd-iast-go/pull/101): "suppress it on the same line". |

### CI: a new job `golangci-lint`, with a matrix of the 5 modules, in `green-ci`

Add this job to `.github/workflows/ci.yml` after the `lint` job:

```yaml
  golangci-lint:
    runs-on: ubuntu-latest
    name: golangci-lint (${{ matrix.module }})
    strategy:
      fail-fast: false
      matrix:
        module:
          - .
          - benchmarks/overhead
          - _integration/otelc
          - _integration/otelc/setups/hashonly
          - _integration/otelc/setups/rootandhash
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Setup Go
        uses: actions/setup-go@d8cbb8045d7f43706b9177cceb36c1f91a6644d5 # v7.1.0
        with:
          go-version: oldstable
          cache-dependency-path: ${{ matrix.module }}/go.sum
      - name: golangci-lint
        uses: golangci/golangci-lint-action@ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0
        with:
          version: v2.15.0
          working-directory: ${{ matrix.module }}
```

In `green-ci` (`.github/workflows/ci.yml:284`): add `golangci-lint` to `needs`, add `&& needs.golangci-lint.result == 'success'` to the `Success` step, and `|| needs.golangci-lint.result != 'success'` to the `Failure` step.

Reasons:
- **Separate job with a matrix:** the 5 modules run in parallel, each has its own annotations and its own cache, and a failure shows which module failed. One `needs` entry covers all 5 legs.
- **`working-directory` per module:** `golangci-lint` finds the root `.golangci.yml` from a sub-directory, and it writes paths relative to the repository root. I checked this in the 4 nested modules. So annotations point to the correct files. The root `./...` does not include `_integration/` (`_` prefix) or `benchmarks/overhead` (other module), so no module is linted 2 times.
- **Action `v9.3.0` = commit `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a`.** The tag is annotated. Its tag object is `d583c34f…`, not the commit. I got the commit with `gh api repos/golangci/golangci-lint-action/git/tags/d583c34f0599d37dbac4a198b9c83201be380893` and checked it with `gh api repos/golangci/golangci-lint-action/commits/v9.3.0 --jq .sha`. `v9.3.0` is the latest release (`gh release list -R golangci/golangci-lint-action`).
- **Binary `v2.15.0`:** latest release (2026-10-16). Its release binary is built with Go 1.27.0 (`.github/workflows/release.yml` at tag `v2.15.0`, `GO_VERSION: '1.27.0'`). So it can load modules with `go 1.26.6` from the Go `oldstable` toolchain.
- **Go `oldstable`:** same as all other jobs. I ran the full check 2 times, with Go 1.27.4 and with `GOTOOLCHAIN=go1.26.6`. The results are the same.

Options not selected:

| Option | Why not |
|---|---|
| 5 steps in the existing `lint` job | The modules run one after the other, all share one cache, and a module failure is less visible. |
| Action option `experimental: automatic-module-directories` | It is experimental, so its behavior can change in a minor release. |
| `golangci-lint` as a `tool` in `go.mod` (like `checklocks`) | Adds many dependencies to the root `go.mod` and to `LICENSE-3rdparty.csv`. The golangci-lint documentation does not recommend `go install` / `go tool`. |
| `version: latest` | A new linter release can break CI with no change in the repository. |

### Each baseline finding (44): 12 code fixes, 32 findings with `//nolint` on 29 lines

All new reasons use the words that the repository already uses.

**Code fixes (12 findings). No change in behavior.**

| File:line | Finding | Fix |
|---|---|---|
| `internal/model/vulnerability.go:37` | errcheck `binary.Write` | `_ = binary.Write(...)`. Writing into an FNV hash cannot fail. The hash value stays the same. |
| `internal/spans/orchestrion.go:33` | staticcheck QF1008 | `ann.Event.Vulnerabilities` → `ann.Vulnerabilities`. I ran `go tool checklocks ./...` after this change: it passes. |
| `benchmarks/overhead/overhead_test.go:100` | errcheck | `_ = response.Body.Close()` (error path before `b.Fatal`). |
| `benchmarks/overhead/runner/main.go:349,354,358,462,467` | errcheck `Close` | `_ = x.Close()`. These are error paths that already return the main error. |
| `benchmarks/overhead/runner/main.go:107` | errcheck `os.RemoveAll` | `defer func() { _ = os.RemoveAll(buildRoot) }()` |
| `benchmarks/overhead/runner/main.go:273` | errcheck `fmt.Fprintln` | `_, _ = fmt.Fprintln(...)` (usage text). |
| `benchmarks/overhead/runner/main.go:686` | errcheck `Close` | `defer func() { _ = file.Close() }()` (file is opened read-only). |
| `benchmarks/overhead/runner/main_test.go:126` | errcheck `Close` | `defer func() { _ = output.Close() }()` (this finding was hidden by the default limits). |

I did not select an `errcheck` `exclude-functions` list: it applies to all code, so it also hides `Close` errors on files that production code writes.

**Intentional weak crypto, `//nolint` on the same line (24 lines, 27 findings).** Reason text: `// Deliberately exercise weak <hash|cipher> detection.`. In `benchmarks/overhead`, use the existing text: `// Intentionally weak: this benchmarks the IAST sink.`.
- `iast/crypto/cipher/cipher_test.go:12,13`
- `iast/crypto/hash/hash_test.go:11,12,30` (line 30: see the coordination section)
- `benchmarks/overhead/instrumentation_test.go:9,34,50`
- `benchmarks/overhead/overhead_test.go:10,11,12`
- `_integration/otelc/cmd/app/main.go:14,15,27,28,29,41`
- `_integration/otelc/internal/suite/cipher.go:310,314`
- `_integration/otelc/internal/suite/hash.go:10,11,85`, and `hash.go:21`: change the existing `//nolint:staticcheck` to `//nolint:gosec,staticcheck`.
- `_integration/otelc/internal/suite/span.go:10`

**Correct code, `//nolint:gosec` with a reason (5 lines).**

| File:line | Rule | Reason text |
|---|---|---|
| `internal/config/config.go:82,83` | G115 | `// The value is bounded to math.MaxInt.` |
| `internal/model/vulnerability.go:47` | G115 | `// Intentional bit reinterpretation of the 32-bit hash.` |
| `internal/spans/annotation.go:120` | G404 | `// Request sampling does not need a cryptographic random source.` |
| `_integration/otelc/internal/suite/cipher.go:157` | G304 | `// The path comes from the go command (source file of a dependency).` |

**Path rule (17 `gosec` findings in `benchmarks/overhead/runner/`):** see the linter set section. No code change for them.

**The 7 existing `//nolint:gosec` and 4 `//nolint:staticcheck` directives stay.** `nolintlint` reports 0 unused directives.

The line numbers are from `main` at `7ad1c4b`. The implementer must use the CI output as the final list, because the line numbers can move after a rebase.

### Coordination with related changes

- Preferred order: [DataDog/dd-iast-go#101](https://github.com/DataDog/dd-iast-go/pull/101) merges first. It is smaller, and it adds the rule "suppress on the same line" that the baseline fixes use. Then this PR merges `main` and changes `iast/crypto/hash/hash_test.go:30` to:
  ```go
  _ "golang.org/x/crypto/md4" //nolint:gosec,staticcheck // Deliberately exercise weak hash detection; registers MD4.
  ```
- If [DataDog/dd-iast-go#101](https://github.com/DataDog/dd-iast-go/pull/101) is not merged when this PR is ready, this PR does not wait. It contains the same line, because the lint check must pass on its own. The PR that merges second resolves a 1-line conflict to the `gosec,staticcheck` version, and an `AGENTS.md` conflict (see the docs section).
- Reason: neither PR blocks the other, and both end with the same final line.
- For `internal/model/vulnerability.go:37` and `internal/spans/orchestrion.go:33`, the related changes are [DataDog/dd-iast-go#103](https://github.com/DataDog/dd-iast-go/pull/103) and [DataDog/dd-iast-go#102](https://github.com/DataDog/dd-iast-go/pull/102). Prefer those changes to merge first. If either is not merged when this PR is ready, include the corresponding fix here so lint passes without waiting. The PR that merges second resolves any conflict to the applicable fix.

### Build-tagged files: lint without build tags

Checked with `rg -n '^//go:build' --type go`:
- 6 files with `//go:build tools` (`orchestrion.tool.go`, `otel.instrumentation.go` in the root, `benchmarks/overhead` and `_integration/otelc`, and `otel.instrumentation.go` in the 2 setups). They have only blank imports of tool programs. With `--build-tags tools`, type checking fails: `import "github.com/DataDog/orchestrion" is a program, not an importable package` (in `setups/rootandhash`).
- 9 files with `//go:build ignore` (`iast/crypto/*/otelc_decl_*.go`, `instrumentation/spans/otelc_decl_finish.go`). otelc copies them into other packages (for example `package md4`), so they cannot be type-checked where they are.
- Reason: no tag adds code that can be linted. `tools` breaks the run.

### Docs

- `AGENTS.md`, section `## Pre-Commit Validation` (`AGENTS.md:94-95`): add 1 bullet before "run all applicable linters": "run `golangci-lint run ./...` (version `v2.15.0`, the version in `.github/workflows/ci.yml`) in each Go module, and fix every finding; see `CONTRIBUTING.md`". If [DataDog/dd-iast-go#101](https://github.com/DataDog/dd-iast-go/pull/101) merged first, keep its pointer line to the intentional-insecure-API section.
- `CONTRIBUTING.md:157-163`: add the command for all modules to the static checks block, and say that the version must be the CI version, with a link to the [install page](https://golangci-lint.run/docs/welcome/install/):
  ```console
  for module in . benchmarks/overhead _integration/otelc \
      _integration/otelc/setups/hashonly _integration/otelc/setups/rootandhash; do
    (cd "${module}" && golangci-lint run ./...)
  done
  ```
- Reason: `AGENTS.md:94-95` tells contributors to run all linters, but it names none. The local command must be the same as CI, or local runs pass and CI fails.
- `iast/AGENTS.md`: no change. The root file is the only source for the lint rules.

## Constraints

1. Each new `uses:` has a full commit SHA and a version comment (`# v9.3.0`), the same as `.github/workflows/ci.yml:22`.
2. The binary version is exact (`v2.15.0`), never `latest` or `v2.15`.
3. Go is `oldstable` from `actions/setup-go`, the same as the other jobs.
4. All 5 `go.mod` modules are linted in CI and in the documented local command.
5. Intentional weak crypto in tests, end-to-end suites, and benchmarks is never "fixed" or removed. It gets a `//nolint:<linter> // <reason>` on the same line.
6. Each `//nolint` names its linter and has a reason (`nolintlint` checks this).
7. No production behavior change: fixes only discard errors that cannot happen or are on error paths, or remove a redundant selector.
8. The job must not need more than `contents: read`.

## Acceptance criteria

- [ ] `lint`: `golangci-lint config verify` passes on `.golangci.yml`.
- [ ] `lint`: `golangci-lint run ./...` (v2.15.0) reports 0 findings in each of the 5 modules, with Go `oldstable`.
- [ ] `lint`: `nolintlint` reports 0 findings (all directives are specific, have a reason, and are used).
- [ ] `lint`: `rg -c '//nolint' --type go` total = 11 existing + 28 new lines (`hash.go:21` is an existing line that is changed) = 39. A different count is explained in the PR.
- [ ] `lint`: `go tool checklocks ./...` and `go -C benchmarks/overhead vet ./...` still pass.
- [ ] `ci`: the job `golangci-lint` has 5 matrix legs, all green.
- [ ] `ci`: `green-ci` has `golangci-lint` in `needs` and in both `if` conditions.
- [ ] `ci`: the action is pinned to `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a # v9.3.0` and `version: v2.15.0`. `setup-go` uses `oldstable`.
- [ ] `ci`: a test commit that adds an unchecked error (for example `os.Remove("x")`) makes the job fail. Revert the commit before review.
- [ ] `unit`: unit tests with Orchestrion and with otelc (`scripts/otelc-test.sh`), the `benchmarks/overhead` tests, and the integration tests pass (CI jobs `test`, `integration`, `benchmark`).
- [ ] `docs`: `AGENTS.md` and `CONTRIBUTING.md` name `golangci-lint`, the version `v2.15.0`, and the command for all 5 modules.
- [ ] `docs`: `_docs/plans/golangci-lint.md` is deleted before merge.

## Review requirements

1. Romain approves this design in the draft PR before implementation.
2. Review each `//nolint` reason, confirm that baseline code fixes do not change behavior, verify that the action SHA is the `v9.3.0` commit (not the tag object `d583c34f…`), and check that all 5 modules are in the matrix.
3. Feature parity between Orchestrion and otelc is not affected (no change to `orchestrion.yml` or `otelc.yml`).

## Risks

| Risk | What reduces it |
|---|---|
| CI Go (`oldstable`) gives other results than the local Go | I ran the check with Go 1.26.6 and 1.27.4: same results. The 5 CI legs are the final check. |
| Hidden findings come out after the first fixes | Limits are 0 and `uniq-by-line: false`. All 44 findings are listed here. |
| Conflict with [DataDog/dd-iast-go#101](https://github.com/DataDog/dd-iast-go/pull/101) | The coordination section gives the final line. The conflict is 1 code line and 1 doc paragraph. |
| Dependabot updates the action SHA but not the `version: v2.15.0` input | A new action version still uses the pinned binary, so CI stays the same. See Follow-up. |
| The `runner/` path rule hides a real issue in the runner | The runner is not shipped and uses only repository inputs. `errcheck`, `staticcheck` and `govet` still run on it. |
| When Go `oldstable` becomes 1.27, a binary built with a too-old Go fails | Bump the binary version in the same PR as a Go version bump. |

## Out of scope

- New style linters (`revive`, `perfsprint`, `gocritic`, `testifylint`).
- `formatters` in `.golangci.yml` (`gofmt` stays in the `lint` job).
- Removal of the `go -C benchmarks/overhead vet ./...` step (now partly covered by `govet`).
- Changes to `iast/AGENTS.md`.

## Path of the temporary design doc

`_docs/plans/golangci-lint.md`, committed with the title `wip(plan): add golangci-lint configuration and CI check` (`AGENTS.md`, section `## Plans`). It is deleted in the last commit before merge.

## How I checked (read-only, on a copy of `7ad1c4b`; no change in the checkout)

- `golangci-lint` v2.15.0, run in each of the 5 modules with the config above (limits off): 44 findings before, 0 after a simulated application of the baseline fixes. `go tool checklocks ./...` and `go -C benchmarks/overhead vet ./...` pass after the simulated apply.
- Default set, limits off: 13 findings (`errcheck` 11, `staticcheck` 2). The issue says 12 because `benchmarks/overhead/runner/main_test.go:126` was hidden by `max-same-issues: 3`.
- `--build-tags tools`: typecheck error (see the build-tagged files section).

## Follow-up

- Enable `testifylint`. Why: 5 `float-compare` findings in tests. Evidence: `iast/crypto/cipher/cipher_test.go:307`, `iast/crypto/hash/hash_test.go:53,136`, `_integration/otelc/internal/suite/span.go:60`, `_integration/otelc/internal/suite/suite.go:333`.
- Keep the `golangci-lint` binary version up to date. Why: Dependabot does not update the `version:` input. Evidence: `.github/dependabot.yml` has only `github-actions` and `gomod` entries.
- Remove the `go -C benchmarks/overhead vet ./...` step if `govet` in `golangci-lint` covers it. Why: the same check runs 2 times. Evidence: `.github/workflows/ci.yml:61-62`.

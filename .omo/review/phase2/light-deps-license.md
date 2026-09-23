# light-deps-license: dependency and license metadata
Verdict: The dependency and attribution changes are internally consistent, but the Orchestrion pseudo-version points to a commit absent from origin/main and blocks release until a merged release is available.
Scope covered: Root and nested go.mod/go.sum files (overhead plus database/sql, integration, and os/exec test apps); .ddla-overrides; LICENSE-3rdparty.csv; production SQL redaction import; HTTP/2 test imports; project LICENSE and test-app license headers; scoped base-to-HEAD diff; Orchestrion sibling clone revision and remote refs; dd-trace-go sibling clone tags.

## Findings
### light-deps-license-F1: Orchestrion pin is from an unmerged topic branch
- Severity: High
- Category: config
- Location: go.mod:14
- Claim: The root module pins `github.com/DataDog/orchestrion v1.12.2-0.20260828141217-23afa71d6dcb`, whose revision `23afa71d6dcb13cc221c6461745229779e7674b4` is on `origin/romain.marcadier/iast-operator-join-points` but is not an ancestor of `origin/main`. As the brief identifies this unmerged Orchestrion dependency as a release blocker, publishing with this pin depends on a topic-branch commit rather than a merged/released version.
- Evidence: `.omo/review/evidence/light-deps-license/orchestrion-pin-provenance.txt`; exact `git show`, `git show-ref`, and `git merge-base --is-ancestor ... origin/main` commands with captured output (`ancestor_exit=1`).
- Fix: Keep the pin for branch validation, but replace it with a merged Orchestrion release containing the required join-point changes before release.

## Checked and found correct
- `go-sqllexer v0.2.4` is a direct dependency used by production `internal/taint/redaction/sql.go` to tokenize supported SQL dialects. Its MIT license and Datadog copyright attribution are represented in `LICENSE-3rdparty.csv`.
- `golang.org/x/net v0.58.0` is used by the root module's HTTP/2 and h2c tests (`iast/net/http/http_test.go`); its direct requirement and BSD-3-Clause attribution are consistent. `golang.org/x/text v0.42.0` is marked indirect, and its BSD-3-Clause attribution is listed.
- The three new nested test-app modules use local `replace` directives back to the repository and repeat the Orchestrion and dd-trace-go requirements. Their go.sum files contain matching checksums for the pinned versions.
- The three added test-app license overrides identify the corresponding module components and assign Apache-2.0/Datadog attribution, consistent with the repository LICENSE and the test-app source headers. The license inventory adds those components and the newly listed x/net and x/text entries.
- Root, benchmark, and test-app modules declare Orchestrion as a tool where used. The root go directive remains `1.26.6`.
- `dd-trace-go/v2 v2.11.0-rc.1` is consistently pinned in the root and test-app modules and the corresponding tag exists in the sibling repository. This is a prerelease dependency; no separate defect is established by its version string alone in this review.
- Other observed version churn in the overhead module is limited to `golang.org/x/mod` and `golang.org/x/sync`; no inconsistent checksum was found in the scoped diff.

## Not covered / open questions
- No dependency build or test suite was run; this review assessed dependency/module and license metadata, and the release-blocking revision provenance directly.
- The existing third-party inventory contains license-expression parsing artifacts for the root package and overhead module; those rows were unchanged by this branch diff and are outside the changed attribution entries.

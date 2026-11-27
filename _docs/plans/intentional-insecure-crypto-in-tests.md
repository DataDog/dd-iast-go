# Design: silence the MD4 deprecation lint and document intentional insecure APIs in tests

Size: Small

## Decisions

1. **Lint suppression: one inline `//nolint:staticcheck` comment on the import line.**
   Line `iast/crypto/hash/hash_test.go:30` becomes:
   ```go
   _ "golang.org/x/crypto/md4" //nolint:staticcheck // Deliberately exercise weak hash detection; registers MD4.
   ```
   Reasons:
   - The repository already uses this exact style for the same finding: `_integration/otelc/internal/suite/hash.go:21` (md4) and `iast/crypto/cipher/cipher_test.go:32` (blowfish).
   - It names only the linter that fires (`staticcheck`, SA1019), so other linters still check this line.
   - The reason text keeps the old comment's information ("registers MD4") and tells why the import is intentional.
   - Verified: the finding goes from 1 to 0 (see above).

2. **`AGENTS.md`: update both files. The root `AGENTS.md` has the full rule. `iast/AGENTS.md` has a short bullet that points to it.**
   - Root `AGENTS.md`: add a new section `## Intentional Insecure APIs in Tests`, before `## Pre-Commit Validation`. Also add one line to `## Pre-Commit Validation` that points to this section as the only exception to "fix every reported issue".
   - `iast/AGENTS.md`: add one bullet to the list about unit tests (near lines 19-21) that points to the root section.
   - Rule text (root section), in substance:
     - Tests, end-to-end suites (`_integration/otelc/internal/suite`), and benchmarks (`benchmarks/overhead`) in this repository call known insecure or deprecated hash and crypto APIs (for example MD4, MD5, SHA-1, DES, RC4, Blowfish) **on purpose**. They verify that IAST detects these APIs.
     - This usage is correct. It is not a defect, a security finding, or a review comment.
     - Do NOT remove, replace, or "upgrade" these calls or imports. Do NOT flag them in reviews or reports.
     - When a linter reports this usage (for example `staticcheck` SA1019 or `gosec`), suppress it on the same line with `//nolint:<linter> // Deliberately exercise weak <hash|cipher> detection.` Do not change the code to remove the finding.
     - This exception applies only to code that exists to exercise IAST detection. Production code (non-test code that is not an IAST fixture) must not use insecure APIs.

   Reasons:
   - The root rule at `AGENTS.md:94-96` ("fix every reported issue") is the rule that causes agents to "fix" these calls. The exception must be next to it, in the same file.
   - Insecure APIs are used also outside `iast/` (`_integration/otelc`, `benchmarks/overhead`). Only the root file covers all of them.
   - Agents that work in `iast/` read `iast/AGENTS.md` first. A short pointer there makes the rule visible, and one source of the full text prevents 2 copies that drift apart.

3. **Scope: only the line `iast/crypto/hash/hash_test.go:30` and the 2 `AGENTS.md` files.**
   Reasons:
   - These 2 changes are the complete request from the issue owner.
   - Adding `golangci-lint` to CI changes the CI gate for all contributors, and it needs its own decision and config. It is out of scope.
   - The 2 other root findings (`errcheck` at `internal/model/vulnerability.go:37`, `staticcheck` QF1008 at `internal/spans/orchestrion.go:33`) are not related to insecure APIs. They are out of scope.
   - Other existing suppressions already follow the rule. Do not change them.

## Options compared

| Choice | Option | Result |
|---|---|---|
| Suppression | Inline `//nolint:staticcheck // <reason>` | **Selected.** Same as existing code; one line; verified. |
| | `.golangci.yml` exclusion rule | Not selected. No config file exists; adding one makes a new repo-wide policy for one line. |
| | Bare `//nolint` (all linters) | Not selected. It hides other linters' findings on the line. |
| | Replace the MD4 import | Not selected. It removes the MD4 detection test, which is the purpose of the test. |
| `AGENTS.md` | Root only | Not selected. Agents in `iast/` can miss it. |
| | `iast/AGENTS.md` only | Not selected. Does not cover `_integration/` and `benchmarks/`, and is far from the root lint rule. |
| | Both, full text in each | Not selected. 2 copies drift apart. |
| | Both, full text in root + pointer in `iast/` | **Selected.** |

## Constraints

- Do not change any test logic, any assertion, or any other import in `hash_test.go`. MD4 test coverage (`crypto.MD4` uses at lines 113 and 182) stays the same.
- Do not add a `.golangci.yml` file. Do not change CI workflows.
- Write the `AGENTS.md` text in clear, short sentences, in the same style as the current file (imperative, `MUST` / `Do not`).
- Run `gofmt` on `hash_test.go` before commit.
- Delete this design document from `_docs/plans/` before the PR is merged (root `AGENTS.md` "Plans" section).

## Acceptance criteria

- [ ] `[lint]` `golangci-lint run ./iast/crypto/hash/...` reports `0 issues.`
- [ ] `[lint]` `golangci-lint run ./...` at the repo root reports only the 2 unrelated findings (`internal/model/vulnerability.go:37`, `internal/spans/orchestrion.go:33`), and no finding in `iast/crypto/hash/hash_test.go`.
- [ ] `[lint]` The comment on `hash_test.go:30` is `//nolint:staticcheck // ...` (linter named, reason given). `gofmt -l iast/crypto/hash/` prints nothing.
- [ ] `[unit test]` `go tool orchestrion go test ./iast/crypto/hash/...` passes.
- [ ] `[unit test]` `scripts/otelc-test.sh` passes for `./iast/crypto/hash/...` (or the full script passes).
- [ ] `[unit test]` The diff of `hash_test.go` changes only line 30.
- [ ] `[docs]` Root `AGENTS.md` has the section `## Intentional Insecure APIs in Tests` with all 5 points of decision 2.
- [ ] `[docs]` Root `## Pre-Commit Validation` points to that section as the exception.
- [ ] `[docs]` `iast/AGENTS.md` has one bullet that points to the root section.
- [ ] `[docs]` This design file is removed from `_docs/plans/` before merge.

## Review requirements

- Standard Reviewer pass. No Adversarial Reviewer: the change is one comment and documentation, with no runtime effect.
- The Reviewer MUST NOT report the MD4 import, or any other intentional insecure API in tests, as a defect.

## Risks

- `//nolint` does not match the linter name in a later `golangci-lint` version. Low risk: `staticcheck` is the stable name in v2, and the same comment already works at `_integration/otelc/internal/suite/hash.go:21`.
- An agent reads the exception too widely and uses insecure APIs in production code. The last point of the rule limits the exception to code that exercises IAST detection.

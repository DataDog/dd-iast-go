# Line directive paths in crypto tests on Windows

Status: proposed. Size: Small. Risk: low (test files and one test-only helper).
Base branch: `romain.marcadier/heap-taint-ranges`.
Location in the PR: `_docs/plans/crypto-line-directive-paths.md` (remove before merge).

## Decisions

All choices are made. There are no open decisions.

### D1. Approach: suffix match at a separator, then use the raw reported path

Selected: keep the `/*line /path/to/file.go:N*/` directives. Add one test-only
helper that checks the reported path against the directive path. Then use the
**raw reported path** in the expected `model.NewVulnerability(...)` value, so the
exact `Hash` check stays.

Reasons:

- The cause is in the Go 1.27 compiler, not in IAST. Go 1.27 joins a directive
  path that is not absolute to the directory of the input file (golang/go#70478,
  `cmd/compile/internal/syntax/parser.go` `updateBase`). On Windows,
  `/path/to/file.go` has no volume, so it is not absolute. On Linux and macOS it
  is absolute, and nothing changes.
- The directory that Go 1.27 adds is not stable: it is the checkout directory,
  a temporary directory when otelc or Orchestrion rewrites the file, or a module
  path with `-trimpath`. A suffix match works for all of these.
- The helper is strict where the toolchain is stable: on Linux and macOS it
  requires exact equality. It accepts a prefix only on Windows.

Rejected:

| Option | Why not selected |
|---|---|
| Runtime-derived expected path (the `pkcs12Source` pattern, `_integration/otelc/internal/suite/cipher.go:137`) | The fixture file `/path/to/file.go` does not exist, so there is no runtime function to ask. A `runtime.Caller` oracle in each fixture adds more directive-bearing code that weaving can move, and it accepts any path as long as both sides agree. |
| Change the directives (relative path, Windows path with build tags, or no directive) | A relative path gives different results on Go 1.26 and Go 1.27 on all platforms. Per-OS fixture files duplicate code. No directive makes the expected lines change at each edit of the test file. |

### D2. Scope: include `_integration/otelc/internal/suite/suite.go`

Selected: fix 3 files with the same helper:

- `iast/crypto/cipher/cipher_test.go`
- `iast/crypto/hash/hash_test.go`
- `_integration/otelc/internal/suite/suite.go`

Reasons: `suite.go:382` has the same hardcoded `/path/to/file.go`, and its
fixtures (`suite/cipher.go:350-361`, `suite/hash.go:143-148`) use the same
directives. It also builds the expected value with `model.NewVulnerability`, so
the hash breaks in the same way. The fix is the same 3-line change. If it is not
fixed now, the first Windows run of the end-to-end tests fails for the same
reason.

### D3. Verification: 3 layers, then close-out on the Windows CI job

1. **Helper unit tests** (all platforms, no weaving). A table test calls the
   unexported `pathMatches(goos, got, want)` with synthetic Windows and Unix
   paths, so Linux and macOS CI also run the Windows cases.
2. **Woven tests on Linux and macOS, Go 1.26 and Go 1.27, both tools.** The
   existing CI jobs `Unit Tests` and `Integration Tests` (matrix `oldstable`,
   `stable`, `orchestrion`, `otelc`) run on the PR. The Implementer also runs
   the commands in "Tests" locally on macOS with both Go versions.
3. **Woven tests on Windows, Go 1.26.10 and Go 1.27.4, Orchestrion.** The base
   branch has no Windows job yet. The PR adds a temporary workflow
   `.github/workflows/windows-crypto-check.yml` in its own commit
   `wip(ci): check crypto tests on Windows`. It runs:
   - `go tool orchestrion go test -count=1 -shuffle=on ./iast/crypto/... ./internal/testutil/...`
   - in `_integration/otelc`: `go tool orchestrion go test -count=1 -shuffle=on . ./internal/...`

   The commit is removed before merge (like this file).

otelc on Windows is not in layer 3. Reason: `scripts/otelc-test.sh` already
fails on Windows before any test runs (`otelc-test: internal/build/otelc.yml not
found: the build is not marked as instrumented`, jobs `139424493482` and
`139424493784` of run `45676258990`). That is a different defect. See
"Follow-up".

Close-out: full Windows verification is done when the Windows CI job of the
base branch PR (it runs the full woven `./...` suite) passes on Go 1.26 and
Go 1.27 after this PR is merged into the base branch. The Delivery Lead records
the link to that green job.

### D4. Review bar: standard Reviewer only

Reason: only test code and a test-only helper change. No production code, no
public API, no new dependency. The Adversarial Reviewer is not necessary.

## Constraints

- C1. No change to production path handling. `internal/vulnerability/stacktrace/stacktrace.go`
  and `internal/vulnerability/report.go` do not change.
- C2. Keep the exact checks of line, method, evidence, span ID, stack ID and
  `Hash`. Only the path check changes from "equal" to "equal, or (Windows only)
  ends with the directive path".
- C3. The tests pass on Go 1.26 and Go 1.27.
- C4. The tests pass on Windows, Linux and macOS.
- C5. The tests pass with Orchestrion and with otelc (parity rule in `AGENTS.md`).
- C6. No new module dependency. `LICENSE-3rdparty.csv` does not change.
- C7. No change to the `/*line ...*/` directives or to the line numbers.

## Helper interface

New package `internal/testutil/linedirective` (non-test file, imported only by
tests):

```go
// PathMatches reports whether got is a path that the Go toolchain can give for
// the line directive path want. want is slash-separated and starts with "/",
// for example "/path/to/file.go".
func PathMatches(got, want string) bool { return pathMatches(runtime.GOOS, got, want) }

// pathMatches:
//   - want does not start with "/"         -> false
//   - got == want                          -> true (all platforms; Go 1.26)
//   - goos != "windows"                    -> false
//   - windows: replace `\` with "/" in got, then
//     strings.HasSuffix(got, want)         -> true
//     (want starts with "/", so the match is at a separator)
```

## Steps

1. Add `internal/testutil/linedirective/linedirective.go` and
   `linedirective_test.go` (interface above, table test below).
2. `iast/crypto/cipher/cipher_test.go:320`: replace
   `assert.Equal(t, "/path/to/file.go", vuln.Location.Path)` with
   `assert.Truef(t, linedirective.PathMatches(vuln.Location.Path, fixturePath), "path %q", vuln.Location.Path)`.
   Add `const fixturePath = "/path/to/file.go"`.
3. `iast/crypto/hash/hash_test.go:68` and `:153` (`TestMD5`, `TestSHA1`): after
   `require.Len(t, event.Vulnerabilities, 1)`, `require.NotNil` the location,
   `require.Truef(PathMatches(...))`, then use the reported path in the
   `Path:` field of the expected `model.NewVulnerability`.
4. `iast/crypto/hash/hash_test.go:190-243` (`TestHash`): in the loop, keep the
   evidence names in order instead of calling `model.NewVulnerability`. After
   decoding the event, `require.Len` (not `assert.Len`), check each reported
   path with `PathMatches`, then build `expectedVulns` with the reported path
   and the stack IDs. Reason: `NewVulnerability` computes `Hash` from the path
   at construction (`internal/model/vulnerability.go:24-40`), so the path must
   be known first.
5. `_integration/otelc/internal/suite/suite.go:368-386` (`assertSingleReport`):
   same as step 3 for `event.Vulnerabilities[0]`.
6. Add the temporary Windows workflow (D3, layer 3) in its own `wip(ci):`
   commit.

Commit order: `wip(plan): ...` (this file), then
`fix(test): accept Go 1.27 line directive paths on Windows` (steps 1-5), then
`wip(ci): ...` (step 6).

## Tests

Helper table (`linedirective_test.go`), `want = "/path/to/file.go"`:

| goos | got | result |
|---|---|---|
| linux | `/path/to/file.go` | true |
| darwin | `/path/to/file.go` | true |
| linux | `/home/u/repo/path/to/file.go` | false |
| windows | `/path/to/file.go` | true (Go 1.26) |
| windows | `D:/a/dd-iast-go/dd-iast-go/iast/crypto/cipher/path/to/file.go` | true |
| windows | `D:\a\repo\iast\crypto\hash\path\to\file.go` | true |
| windows | `github.com/DataDog/dd-iast-go/iast/crypto/hash/path/to/file.go` | true (`-trimpath`) |
| windows | `D:/a/repo/xpath/to/file.go` | false (no separator) |
| windows | `D:/a/repo/path/to/file.go.bak` | false |
| windows | `D:/a/repo/path/to/other.go` | false |
| windows | `path/to/file.go` | false |
| windows | `` (empty) | false |
| windows | `D:/a/path/to/file.go`, `want = "path/to/file.go"` | false (bad `want`) |

Commands (run each with Go 1.27.4 and with `GOTOOLCHAIN=go1.26.10`):

```sh
gofmt -l .
go vet ./internal/testutil/...
go tool checklocks ./...
go test -count=1 ./internal/testutil/...
DD_IAST_EXPECTED_BUILD_TOOL=orchestrion go tool orchestrion go test -count=1 -shuffle=on ./...
scripts/otelc-test.sh -count=1 -shuffle=on
(cd _integration/otelc && go tool orchestrion go test -count=1 -shuffle=on . ./internal/...)
(cd _integration/otelc && go tool otelc go test -count=1 -shuffle=on . ./internal/...)
(cd _integration/otelc/setups/hashonly && go tool otelc go test -count=1 -shuffle=on ./...)
(cd _integration/otelc/setups/rootandhash && go tool otelc go test -count=1 -shuffle=on ./...)
```

Use a separate `GOCACHE` for each tool (`_integration/otelc/doc.go`).

## Acceptance criteria

- [ ] `[unit]` The helper table test passes, with all rows above, on Linux and macOS.
- [ ] `[unit]` On Linux and macOS, `PathMatches` accepts only the exact path `/path/to/file.go`.
- [ ] `[unit]` Negative rows (`xpath`, `.bak`, `other.go`, relative, empty, bad `want`) return false.
- [ ] `[integration]` Woven Orchestrion unit tests (`./...`) pass on Linux, Go 1.26 and Go 1.27 (CI `Unit Tests (orchestrion, oldstable|stable)`).
- [ ] `[integration]` Woven otelc unit tests (`scripts/otelc-test.sh`) pass on Linux, Go 1.26 and Go 1.27 (CI `Unit Tests (otelc, oldstable|stable)`).
- [ ] `[integration]` `_integration/otelc` and both setups pass with both tools on Linux, Go 1.26 and Go 1.27 (CI `Integration Tests`).
- [ ] `[integration]` Local macOS run of all "Tests" commands passes on Go 1.26.10 and Go 1.27.4 (Implementer posts the output summary).
- [ ] `[windows]` Temporary Windows workflow passes on Go 1.26.10 and Go 1.27.4 with Orchestrion: `TestSaltedBlowfish`, `TestBlowfish`, `TestTripleDES`, `TestRC4`, `TestDES`, `TestMD5`, `TestSHA1`, `TestHash` pass, and `_integration/otelc` passes.
- [ ] `[review]` The diff has no change outside the 3 test files, the new `internal/testutil/linedirective` package, the temporary workflow and this file (C1, C6, C7).
- [ ] `[review]` Line, method, evidence, span ID, stack ID and `Hash` are still checked exactly; the hash tests compare a full `model.NewVulnerability` value (C2).
- [ ] `[review]` The same helper is used in all 3 files (C5 parity).
- [ ] `[close-out]` Before merge: the `wip(plan)` and `wip(ci)` commits are removed.
- [ ] `[close-out]` After merge into the base branch: the base branch Windows CI job (full woven `./...`) passes on Go 1.26 and Go 1.27.

## Risks

| Risk | Mitigation |
|---|---|
| The suffix match hides a wrong path on Windows. | Windows only; boundary at `/`; negative rows in the table test; Linux and macOS stay exact. |
| `TestHash` order: `cases` is a map, so the order is random. | Step 4 keeps the evidence names in iteration order and pairs them by index with the reported vulnerabilities, as the stack IDs already are. |
| The new package changes coverage or weaving. | It has no rules and no `internal/build` import; `-coverpkg=./...` adds a small, fully tested package. |
| The temporary workflow is merged by mistake. | Its own `wip(ci)` commit; a `[close-out]` criterion checks the removal. |

## Out of scope

- Changes to production path handling or to path normalization in reports.
- The permanent Windows CI job (it is part of the base branch work).
- otelc on Windows.

## Follow-up

- `scripts/otelc-test.sh` fails on Windows before tests run (`internal/build/otelc.yml not found`), jobs `139424493482` and `139424493784` of run `45676258990`. Without a fix, Windows has no otelc coverage.
- Application code with its own relative line directives gets different report paths on Go 1.27 (golang/go#70478). Check if IAST must document this behavior.

# prop-string-exact: exact string range offsets
Verdict: Join and Replace preserve the expected byte offsets within their exact-match bounds; supported string window operations lose provenance after 32 empty outputs.
Scope covered: `internal/taint/propagation/string_exact.go` (all functions), `propagation.go` (string windows, copy, repeat, coarse paths), `string_coarse.go`, `internal/taint/ranges/operations.go`, `iast/propagation/{strings,coarse}.go`, relevant propagation tests, phase-1 architecture/design/research notes. Executed isolated Go 1.26.6 reproducer tests for Split and Replace.

## Findings

### prop-string-exact-F1: Empty Split results consume the non-empty window budget
- Severity: High
- Category: false-negative
- Location: internal/taint/propagation/propagation.go:239-252
- Claim: `stringWindowsHit` stops at output index 32 rather than after 32 eligible non-empty windows. For `strings.Split(strings.Repeat(",", 32)+"secret", ",")`, the first 32 outputs are empty and the 33rd is `"secret"`. Even when the input's `"secret"` bytes are tainted, that first non-empty window is never derived; a subsequent sink sees it as clean. The same helper is used for array-returning Split/Fields wrappers. The advertised `maxWindows` budget counts *non-empty* windows, so this is a loss below that budget, not a deliberate capacity drop.
- Evidence: `.omo/review/evidence/prop-string-exact/zz_review_splitranges_test.go`, `.omo/review/evidence/prop-string-exact/zz_review_prop_string_exact_test.go`, `.omo/review/evidence/prop-string-exact/reproducer.out.txt`. In an isolated repo copy, place the first test in `iast/propagation/` and the second in `internal/taint/propagation/`; run `GOTOOLCHAIN=go1.26.6 go test -timeout 5m -count=1 -run '^TestReviewStringsSplitTaintedFirstNonEmptyAfterEmptyPrefix$' -v ./iast/propagation` and `GOTOOLCHAIN=go1.26.6 go test -timeout 5m -count=1 -run '^TestReview' -v ./internal/taint/propagation`. Both exit 1: wrapper says `first non-empty result loses taint`; internal lookup gets `[]ranges.Range(nil)` instead of `[{Start:0 Length:6 SourceID:7}]`. Four independent Replace boundary subtests pass in the same captured run.
- Fix: Traverse outputs until 32 non-empty alias windows have been considered, not until 32 slice entries have been visited. Keep the existing publication cap and record a drop only when eligible windows remain beyond it. Apply the same eligibility accounting to the analogous byte-window helper if its declared non-empty budget is intended to match.

## Checked and found correct

- `JoinString`: each element occupies its original byte length, each separator is inserted only between adjacent elements, and `ranges.Concat` shifts by the running byte offset. Empty elements still account for adjacent separators; an empty separator with a sole non-empty alias derives a window. Joins exceeding 16 inspected elements intentionally use the documented coarse fallback.
- `ReplaceString`: non-empty `old` advances past each non-overlapping match; empty `old` inserts at the start and after each decoded UTF-8 rune, including invalid bytes (one-byte decoding). Each copied segment keeps its input offset via `ranges.Compose`, and replacement segments have their own source IDs. The isolated four-case test passed for `n=0`, `n=-1`, one overlapping candidate, and `old=""` with multibyte input. More than 32 matches intentionally use the documented coarse fallback.
- `Cut`, `CutPrefix`, `CutSuffix`, `Split`, `SplitN`, `SplitAfter`, `Fields`, `FieldsFunc`, `Trim*`, and `Lines` yield windows of the input backing string; `StringWindow` derives each non-empty alias from its original byte pointer and root. Thus leading/trailing empties have no taint and UTF-8 byte widths are reflected in offsets. `SplitN(..., 0)` yields no windows and negative `n` uses all results. The array-output budget failure is the exception above; sequence APIs deliberately inspect only the first 32 yielded results.
- `RepeatString` derives `count=1` aliases; for count greater than one, `ranges.Repeat` shifts each source range by `i*len(input)` using checked `uint64` multiplication and publishes only a result fitting the root bound. Count zero yields empty, and an overflow panic occurs in the original `strings.Repeat` call before propagation, preserving native behavior.
- `CaseString` copies exact offsets for ASCII unchanged-length transforms; non-ASCII/length-changing cases and `Map` are intentionally coarse. `ToValidUTF8` includes replacement provenance only when the native function repairs input; `Clone` copies same-length ranges, subject to the documented minimum two-byte fresh-root size.

## Not covered / open questions

- No full instrumented `go tool orchestrion go test ./...` run; the wrapper was called directly with a real active taint scope, and the exact result was tested independently in the isolated package.
- The accepted coarse fallbacks beyond 32 replacement matches or 16 joined elements were checked statically for their bounded-input policy, not assessed for source precision after saturation.

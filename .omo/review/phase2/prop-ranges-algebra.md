# prop-ranges-algebra: bounded range and mark algebra
Verdict: The reviewed range transformations preserve canonical byte provenance and marks in the tested cases; configured range-limit truncation is not counted in drop telemetry.
Scope covered: `internal/taint/ranges/{ranges,canonical,marks,operations}.go`, its unit/property/fuzz test sources, `internal/taint/propagation/{string_exact,bytes_exact}.go` join/compose callers, and `internal/taint/store/root.go` range publication.

## Findings
### prop-ranges-algebra-F1: Configured-range truncation is invisible to drop counters
- Severity: Medium
- Category: quality
- Location: internal/taint/propagation/string_exact.go:82-94
- Claim: Each incremental `ranges.Concat` returns `Outcome.Truncated` when an output has more than the configured range limit, but the join caller checks only `Valid`. The excess tail range is discarded as designed; neither `telemetry.DroppedPropagation` nor the owner's `Counters().Ranges` records that loss. The byte-join and other transformation callers also ignore the flag. Consequently drop telemetry cannot distinguish successful complete propagation from a supported transform that silently lost taint at the range cap.
- Evidence: `.omo/review/evidence/prop-ranges-algebra/zz_review_range_drop_test.go` and `.omo/review/evidence/prop-ranges-algebra/range-drop.out.txt`. In a private copy, place the evidence test at `internal/taint/propagation/zz_review_range_drop_test.go`, then run `GOTOOLCHAIN=go1.26.6 go test -timeout 5m -count=1 -run ^TestReview_JoinRecordsRangeTruncationWhenEleventhRangeIsDropped$ -v ./internal/taint/propagation`. Output: `result ranges=10; owner range drops=0 -> 0; propagation drops=0 -> 0`, followed by `FAIL` at the counter assertion. The existing `TestPropagationTelemetry` passes because it covers a different drop path.
- Fix: Record a dropped-provenance event when an algebra outcome is truncated, at each publishing caller, without changing the documented earliest-prefix retention policy. Add a counter assertion for range-cap truncation in propagation tests.

## Checked and found correct
- `Canonicalize` validates all inputs before publishing, applies first-input overlap precedence, merges only adjacent equal source **and** mark tuples, and keeps the earliest output-order prefix when capped. The 10,000-case byte oracle and 80-range test passed under Go 1.26.6; the fixed scratch capacity accommodates the worst-case `2*n-1` fragments for at most 192 input ranges.
- `Copy`, `Concat`, `Slice`, `Clear`, `Overwrite`, `Repeat`, and `Join` passed the existing 5,000-case byte-oracle suite. `Compose`, overlapping copy snapshot semantics, shift, and empty-input handling are exercised by unit tests; all range-package tests passed in the private copy.
- `checkedEnd` rejects zero-length and wrapping ranges; result-length and shift overflow are rejected before output publication. The package tests include invalid-mark and `uint32` overflow cases. `MarkSource` handles source ID zero, `MarkAll` coalesces newly equal neighbors, and `UnsafeFor` preserves non-target marks in existing tests.
- Re-ran `GOTOOLCHAIN=go1.26.6 go test -timeout 5m -count=1 -run ^TestPropagationTelemetry$ -v ./internal/taint/propagation`; it passed. A separate reproducer deliberately fails only on the missing truncation counter.

## Not covered / open questions
- No instrumented SQL/command sink or cross-owner lifecycle run was needed to prove the range-counter finding; those integration paths are outside this algebra review.
- No long-running fuzz campaign or physical allocation near the `uint32` value-length ceiling was run. Existing boundary tests and arithmetic inspection covered the relevant overflow guards.

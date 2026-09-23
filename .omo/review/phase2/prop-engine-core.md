# prop-engine-core: propagation entry points and fast paths
Verdict: One reproducible High-severity provenance loss on supported string and byte splits; no crash found in the reviewed paths. A clean-window allocation and a drop-counter error also remain.
Scope covered: `internal/taint/propagation/propagation.go`, `telemetry.go`, `string_coarse.go`, `bytes_exact.go`; `internal/taint/store/{lookup,root}.go`, `internal/taint/request/lookup.go`; callers in `iast/propagation/{strings,bytes,coarse}.go`; selected package tests and private-copy reproductions on Go 1.26.6.

## Findings

### prop-engine-core-F1: Empty split fields exhaust the derived-window budget
- Severity: High
- Category: false-negative
- Location: internal/taint/propagation/propagation.go:232-254,515-537
- Claim: `StringWindows` and `ByteWindows` stop after **32 output indexes**, rather than 32 non-empty windows as their contract states. A tainted source containing 32 leading commas followed by `attack` yields 33 fields; the only non-empty field is never derived by the supported `strings.Split`/`bytes.Split` wrappers. A subsequent sink sees it as clean. The source is tracked and a separately allocated, byte-identical clean control is not tracked.
- Evidence: `.omo/review/evidence/prop-engine-core/zz_review_window_budget_test.go` and `.omo/review/evidence/prop-engine-core/window-budget.out.txt`. In the private copy run `GOTOOLCHAIN=go1.26.6 go test ./internal/taint/propagation -run '^(TestReview(String|Bytes)Split_retains_last_nonempty_field_after_empty_fields|TestReviewEmptyWindows_do_not_count_as_dropped_provenance)$' -count=1 -timeout=5m -v` (exit 1); the captured lines say `string last field="attack", tainted=false` and `bytes last field="attack", tainted=false`. The test uses the real direct-call wrappers and active request analysis.
- Fix: Cap *published non-empty* windows at 32. Continue inspecting empty outputs within a separate input-size-based bound (a supported split of a managed root has at most `len(input)+1` outputs), so skipping empties does not make work unbounded. Count an actual bounded-out contribution rather than assuming `len(outputs)>32` means one was dropped.

### prop-engine-core-F2: Clean derived input triggers an unnecessary clone
- Severity: Medium
- Category: perf
- Location: internal/taint/propagation/propagation.go:382-422
- Claim: A clean substring that was derived from a partially tainted managed root still has a store entry with zero ranges. `coarseStringHit` counts that owner, records a coarse propagation, and clones a native transform result before checking `o.found`; the returned string remains clean. This makes a clean transform in an active analysis allocate a redundant complete string and changes its backing identity.
- Evidence: `.omo/review/evidence/prop-engine-core/zz_review_window_budget_test.go` and `.omo/review/evidence/prop-engine-core/clean-window-clone.out.txt`. In the private copy run `GOTOOLCHAIN=go1.26.6 go test ./internal/taint/propagation -run '^TestWindowReviewCleanDerivedWindow_does_not_clone_result$' -count=1 -timeout=5m -v` (exit 1); output: `clean input: result cloned=true, tainted=false`.
- Fix: Require at least one accumulated range (`found`) before recording or cloning a coarse string result; a zero-range snapshot is not a contributing owner.

### prop-engine-core-F3: Empty bounded-out windows increment the drop counter
- Severity: Low
- Category: quality
- Location: internal/taint/propagation/propagation.go:234-236,517-519
- Claim: Both batch helpers call `recordDropped()` whenever there are more than 32 output entries, even if every entry is empty and no provenance could be published or lost. This overstates `DroppedPropagation`, whose declared meaning is bounded propagation contributions dropped.
- Evidence: `.omo/review/evidence/prop-engine-core/zz_review_window_budget_test.go` and `.omo/review/evidence/prop-engine-core/window-budget.out.txt`. The same bounded command above records `empty windows: dropped counter before=2 after=3` with 33 empty outputs.
- Fix: Increment only when the bounded scan actually leaves a non-empty taint-bearing output unprocessed; the corrected F1 window accounting provides the right place to do this.

## Checked and found correct
- No-active-store gate adds no allocation in the selected `TestNoActiveStoreIsNoOpAndAllocationFree`; owner-separated coarse source IDs and marks passed `TestCoarseStringPreservesEachOwnerSourceAndMarks` and `TestCoarseStringTwoOwnersKeepLocalSourceIDs`.
- A clean, untracked byte alias is not adopted by `CoarseBytes` in `TestCoarseBytesNeverAdoptsAnUntaintedInputWindow`. Finished/reused owners are rejected by `TestEntryHandleRejectsFinishedAndReusedOwner`.
- `TestPropagationTelemetry` passed for a genuine coarse transform and 33 non-empty windows. These six tests passed in one private-copy run with `GOTOOLCHAIN=go1.26.6 go test ./internal/taint/propagation -run '^(TestPropagationTelemetry|TestCoarseStringPreservesEachOwnerSourceAndMarks|TestCoarseStringTwoOwnersKeepLocalSourceIDs|TestCoarseBytesNeverAdoptsAnUntaintedInputWindow|TestEntryHandleRejectsFinishedAndReusedOwner|TestNoActiveStoreIsNoOpAndAllocationFree)$' -count=1 -timeout=5m -v`.
- Store snapshots revalidate the owner and root generation, and `Entry.Handle` revalidates owner identity before publication (`internal/taint/store/lookup.go:34-45,142-196`). The exercised wrappers call the native operation first; the reviewed propagation functions operate on its result without invoking that operation again. No panic occurred in the selected tests.

## Not covered / open questions
- No full woven integration suite, fuzz campaign, race stress, or all-module checks were run. Findings use focused private-copy tests; no production source was modified.
- Stateful writers, JSON, exact join/replace transformations, and sink reporting were outside this node's primary review.

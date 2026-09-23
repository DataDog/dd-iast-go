# store-tests: internal taint store test-quality audit
Verdict: Medium — the suite has broad, race-clean coverage, but three risky lifecycle/bound regressions are not deterministically protected.
Scope covered: all `internal/taint/store/*_test.go`; store implementation files; `go test -coverprofile` and selected `-race -count=20` runs in the required private copy.

## Findings
### store-tests-F1: Address-reuse regression check silently skips
- Severity: Medium
- Category: test-gap
- Location: internal/taint/store/identity_test.go:30-62
- Claim: `TestAddressReuseDoesNotReviveFinishedOwner` skips when the allocator does not recycle the old address within 512 allocations. In a 20-run race stress execution, it skipped 7 times, so a green suite frequently exercises no stale-address assertion. This leaves the store's highest-risk numeric-address/owner-generation invariant without a deterministic regression test.
- Evidence: .omo/review/evidence/store-tests/race-stress.txt + exact command recorded there; 7 skipped invocations emitted `allocator did not reuse the address within the bounded attempt`.
- Fix: retain the physical-reuse test as optional stress coverage, but add a deterministic package-internal test that installs a stale old-generation slot for a new live key, then proves lookup/reclamation exposes only the new owner and source.

### store-tests-F2: Finish blocking assertion can pass before Finish runs
- Severity: Medium
- Category: quality
- Location: internal/taint/store/lifecycle_test.go:14-35
- Claim: `TestFinishDrainsActiveWriterAndReleasesRoots` starts `Finish` in a goroutine and immediately uses a `select { default: }` to conclude that Finish is blocked by `lifecycleMu.RLock`. There is no synchronization proving the goroutine reached `Finish` or its lock acquisition; a regression that lets Finish return while the read lock is held can pass when the goroutine has simply not been scheduled.
- Evidence: static reasoning only (NEEDS-REPRO)
- Fix: expose or inject a test-only synchronization point after `Finish` transitions to `stateFinishing` and immediately before it waits on `lifecycleMu`, then wait for that signal before asserting that `done` remains unreadable.

### store-tests-F3: Binding-kind replacement and reader-budget transitions are untested
- Severity: Medium
- Category: test-gap
- Location: internal/taint/store/binding.go:166-202; internal/taint/store/binding_behavior_test.go:15-59
- Claim: The 91.5% package profile leaves all existing-pointer replacement branches in `bindingTable.bind` uncovered, including URL-to-reader rejection at `MaxReaderBindings`, reader-to-URL decrement, and same-pointer replacement. Those branches enforce the eight-reader strong-reference bound; the tests cover new-reader admission and fanout but not kind replacement or its accounting.
- Evidence: .omo/review/evidence/store-tests/coverage.txt + exact command recorded there; zero-hit blocks include `binding.go:186.31-202.14`.
- Fix: add table-driven tests that bind one object as URL, fill reader capacity, reject its URL-to-reader replacement while preserving its old binding, then convert a reader to URL and prove that a new reader can be admitted.

## Checked and found correct
- The complete store suite passed with a statement coverage profile: 91.5%.
- The selected concurrent lifecycle, lookup/mutation, and address-reuse tests passed under `-race` over 20 invocations with no race report.
- No `time.Sleep`-based store test was found. The only deadline-based concurrency test (`writer_test.go`) waits on explicit lock/release channels and uses its context only as a bounded failure guard.
- Tests exercise major hard limits: request/process bytes and values, root and writer capacity, range overflow, probe limits, reader limits, cleanup, mutation invalidation, and writer overlap handling.
- Positive provenance assertions generally inspect actual snapshots/ranges and owner/source IDs rather than only mock-call counts.

## Not covered / open questions
- The coverage profile also leaves stale-slot `reclaim` branches (`value.go:232-266`), mutation identity/generation rejects (`mutation.go:51-56,80-86`), and Acquire lock-contention paths (`owner.go:21-42`) unhit. These are worth adding after the three findings above, but this audit found no evidence that they are currently defective.
- This node audited unit-test quality only; it did not rerun the instrumented HTTP-to-sink end-to-end suite.

# light-test-determinism: Test nondeterminism audit
Verdict: One low-severity test gap found; no timing sleeps, parallel-global races, or map-order-dependent assertions found in the 139 repository Go test files.
Scope covered: All 139 `*_test.go` files outside `.omo/` in the private copy; searched for sleeps, timer waits, polling helpers, `t.Parallel`, random sources, `runtime.GC`, package-level test globals, global configuration writes, and map-range loops; inspected all timing/GC matches and map iteration candidates.
## Findings
### light-test-determinism-F1: Address-reuse assertion can be skipped
- Severity: Low
- Category: test-gap
- Location: internal/taint/store/identity_test.go:43-58
- Claim: The stale-entry check only runs if the allocator reuses the old address within `MaxRootsPerOwner` allocations. If not, the test calls `t.Skip`, so the GC/address-reuse lifecycle assertion is conditional on allocator behavior and can silently provide no coverage in that run.
- Evidence: `.omo/review/evidence/light-test-determinism/address-reuse-test.txt` (static source excerpt; no reproduction required for this test-coverage claim).
- Fix: Make address reuse deterministic in a test seam, or separate the always-run finished-owner invalidation assertion from the optional allocator-reuse scenario so the core lifecycle check cannot be skipped.
## Checked and found correct
- `time.After` occurs only in bounded channel-deadline cases in `iast/net/http/http_test.go:585` and `internal/vulnerability/tainted_dedup_test.go:93`; these wait for events with a failure timeout and do not poll or sleep.
- No `time.Sleep`, `time.Ticker`, or Eventually-style polling helper was found in the 139 Go test files.
- No `t.Parallel` call was found. Test configuration/global mutations inspected either restore prior values with cleanup or are initialized in isolated nested test applications.
- Map-range test loops inspected perform independent checks per entry; none relies on iteration order.
- `internal/taint/store/memory_test.go:20-39` calls `runtime.GC` around a heap measurement, but its heap-delta bound is guarded by `if after.HeapAlloc > before.HeapAlloc`; a lower post-GC measurement does not itself fail the test. Store charge/value assertions are explicit counters rather than GC-timing assertions.
- Randomized property tests use fixed `rand.NewPCG` seeds.
## Not covered / open questions
- No package test suite was run; this was a static nondeterminism scan. The finding follows directly from the test's bounded-reuse branch and skip behavior.
- `RTK.md` and `CLAUDE-omc.md`, referenced by the local project instruction file, were absent in the checkout.

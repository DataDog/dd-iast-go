# perf-algorithmic: adversarial taint propagation and reporting cost
Verdict: Two High severity, attacker-controlled super-linear reporting paths; bounded propagation and ordinary redaction showed no comparable reproducible defect.
Scope covered: `internal/taint/ranges/{canonical,operations,ranges}.go`, `internal/taint/propagation/{propagation,string_exact,bytes_exact,operator_concat,writer}.go`, `internal/taint/store/writer.go`, `internal/taint/evidence/evidence.go`, `internal/taint/redaction/{source,sql,analyzer,command}.go`; relevant request visitor, public source and `iast/propagation` wrappers. Benchmarks ran in a private copy with Go 1.26.6.

## Findings

### perf-algorithmic-F1: Rehashing a full source for each reported range
- Severity: High
- Category: perf
- Location: internal/taint/evidence/evidence.go:209-240,277-291
- Claim: `collector.addAt` calls `sourceIndex` for every unsafe range. Before testing whether the source is already indexed, `sourceIndex` hashes the *entire* source name and value. A single HTTP value of length S contributing R disjoint sink ranges therefore costs O(R*S) at every report, even though only one source is copied and the sink value can be O(R) bytes. Both S (up to the 64 KiB source root bound) and R (up to 64 per owner, four owners per snapshot) are attacker-influenced. This is repeated at every eligible sink invocation, not only when provenance is first stored.
- Evidence: `.omo/review/evidence/perf-algorithmic/review_scaling_test.go` (`BenchmarkReviewCollectRepeatedSource` and `BenchmarkReviewRepeatedSourceIndex`) and `.omo/review/evidence/perf-algorithmic/scaling-output.txt`. From a private copy, place the test in `internal/taint/evidence/review_scaling_test.go` and run `GOTOOLCHAIN=go1.26.6 go test -mod=readonly -run '^$' -bench '^BenchmarkReviewCollectRepeatedSource$' -benchmem -benchtime=100ms -count=1 -cpu=1 -timeout 5m ./internal/taint/evidence`. Actual `CollectString` with one source and 8, 16, 32, 64 separated taint ranges (source length 4, 8, 16, 32 KiB) took 462,871; 1,566,117; 10,259,389; 29,140,468 ns/op. Adjacent doubling ratios: 3.38, 6.55, 2.84. Its 64-range sink value is only 127 bytes; the benchmark asserts all 127 evidence parts and the original source identity. Timings on the shared machine are noisy, but the independent direct-collector reproducer isolates the repeated hashing and confirms the trend.
- Fix: Cache source resolution within one collection using a stable owner-local source identifier carried by `ResolvedRange`, so repeated ranges reuse the existing index without rehashing the full source. Keep exact identity comparison for distinct sources and the current fixed source/byte limits.

### perf-algorithmic-F2: Predictable source-index collisions cause quadratic probes
- Severity: High
- Category: perf
- Location: internal/taint/evidence/evidence.go:240-277
- Claim: The evidence index uses unsalted FNV and takes `hash % 512` as its starting slot, then linear-probes and compares source identities. An attacker can choose distinct HTTP source values with identical low nine hash bits, making insertion of N distinct sources take 1+2+...+N probes: O(N^2), within the 256-source/256-range caps. Unlike the request source table's seeded `maphash`, this index allows the collision set to be calculated offline. Reports on affected values pay the cost again at each sink.
- Evidence: `.omo/review/evidence/perf-algorithmic/review_scaling_test.go` (`BenchmarkReviewSourceIndexCollisions`) and `.omo/review/evidence/perf-algorithmic/scaling-output.txt`. From a private copy, place the test in `internal/taint/evidence/review_scaling_test.go` and run `GOTOOLCHAIN=go1.26.6 go test -mod=readonly -run '^$' -bench '^BenchmarkReviewSourceIndexCollisions$' -benchmem -benchtime=100ms -count=2 -cpu=1 -timeout 5m ./internal/taint/evidence`. Crafted same-slot sources took 362,814/379,680 ns/op at 64 sources and 1,500,446/2,597,548 at 128 (4.14x/6.84x doubling); the distinct-slot 128-source controls took 223,736/232,754 ns/op. The reproducer passes valid resolved ranges to the real collector. It does not measure a complete multi-owner sink call, so the absolute end-to-end amplification is not established.
- Fix: Use a process-seeded keyed hash for the evidence index (the request table already uses `hash/maphash`) while retaining the fixed 512 slots and bounded probe loop. Combine with F1's per-report source-index cache to avoid redundant work.

## Checked and found correct

- `ranges.Concat`, writer updates, and window derivation operate on fixed-capacity sets; `internal/taint/store/writer.go` tracks at most eight writer records per owner. Direct-wrapper benchmarks with 128-2,048 small tainted Builder writes and 128-2,048 Split parts did not reproduce a quadratic trend. Split propagation inspects at most 32 outputs; outputs past that bound are documented safe misses. Reproducer and captured output: `.omo/review/evidence/perf-algorithmic/writer_split_scaling_test.go`, `.omo/review/evidence/perf-algorithmic/scaling-output.txt`.
- Exact Replace mapping stops after 32 matches and falls back to coarse propagation; `StringWindows` stops after 32 outputs; joined propagation inspects at most 16 inputs before its coarse fallback. Selected boundary tests passed in the private copy (command and results in `scaling-output.txt`).
- SQL analysis rejects input above 32 KiB; source redaction limits comparison work to 1 MiB and performs bounded output truncation. Doubling 4-32 KiB query/source sizes with `BenchmarkReviewSQLAndRedaction` did not isolate super-linear growth apart from the evidence collector; results and reproducer are in `.omo/review/evidence/perf-algorithmic/`.
- `ranges.Canonicalize` explicitly uses O(n^2) overlap resolution, but a search of production `internal/taint` and `taint` callers found only test/benchmark use; production range construction uses fixed-capacity canonical sets. It is not a production hot-path finding.

## Not covered / open questions

- The absolute overhead of F1/F2 in a full SQL/command report including span commit and event serialization was not timed; collection itself is the measured reporting seam. Benchmarks are ratio-oriented because the machine is shared.
- The Builder benchmark covers direct call-site wrappers, not a separately woven executable. A dedicated end-to-end stress test of four concurrent owners each contributing 64 ranges could measure the maximum combined reporting cost.

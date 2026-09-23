# perf-bench-quality: Benchmark suite measurement validity and coverage

Verdict: The benchmark suite is well-engineered against classic Go
microbenchmarking pitfalls (package-level sink variables everywhere, `b.Loop()`,
`b.ReportAllocs()` on all but two functions, a sound differential-process
methodology in `benchmarks/overhead/runner`), but it has a systemic, repository-wide
blind spot: almost every benchmark that claims to measure the "active" IAST cost
only ever exercises the cheap `MayContain`-miss/gate-check path with clean or
literal data, never the actual tainted-hit path that fires when a real attacker
value reaches a sink. Reproducers added in a private copy show that gap is not
academic: the real hit path costs two to four orders of magnitude more than the
already-benchmarked miss path for SQL/exec sinks and string concatenation, and
that cost has zero CI-tracked signal today. Several of the riskiest components
named in the phase-1 architecture review (the core `internal/taint/propagation`
engine, `internal/spans`, HTTP eager source tainting) have no benchmark at all,
direct or indirect-but-attributable.

Scope covered: `benchmarks/overhead/{overhead_test.go,buffer_test.go,buffer.go,
instrumentation_test.go,runner/main.go,README.md}`; every `func Benchmark` in the
repository (`iast/database/sql/{sql_test.go,testapp/sql_test.go}`,
`iast/os/exec/{exec_test.go,testapp/exec_test.go}`,
`iast/propagation/operators_test.go`, `iast/encoding/json/json_test.go`,
`iast/integration/testapp/e2e_test.go`, `taint/taint_test.go`,
`internal/taint/ranges/benchmark_test.go`, `internal/taint/evidence/evidence_test.go`,
`internal/taint/{commandbridge,operatorbridge,sqlbridge,writerbridge}/bridge_test.go`,
`internal/taint/redaction/{analyzer_test.go,source_test.go}`,
`internal/taint/store/lifecycle_test.go`); the non-test source each benchmark
exercises (`iast/database/sql/sql.go`, `iast/os/exec/exec.go`,
`internal/taint/evidence/evidence.go`, `internal/taint/redaction/{analyzer.go,
source.go}`, `internal/taint/propagation/{propagation.go,string_exact.go,
operator_concat.go}`, `internal/vulnerability/tainted.go`,
`internal/taint/store/lookup.go`, `internal/taint/request/http.go`,
`iast/encoding/json/json.go`). Directory listings confirmed the absence of any
benchmark file in `internal/taint/propagation`, `internal/spans`,
`internal/taint/{httpbridge,jsonbridge}`, `iast/net/http`, and
`internal/taint/request`. All findings were reproduced by running Go benchmarks
in a private worktree copy (`/tmp/ddiast-review/wt/perf-bench-quality`, deleted
after this review) with `GOTOOLCHAIN=go1.26.6`; five reproducer files were added
there and copied into the evidence directory below.

## Findings

### perf-bench-quality-F1: Nearly every "Active" benchmark only exercises the MayContain-miss (clean) path, never a genuine tainted hit
- Severity: Medium
- Category: test-gap
- Location: `benchmarks/overhead/overhead_test.go:40` (`BenchmarkPropagationActiveUntainted`); `iast/database/sql/sql_test.go:38` (`BenchmarkReportActiveClean`); `iast/os/exec/exec_test.go:79` (`BenchmarkReportActiveClean`); `iast/propagation/operators_test.go:136-192`; `iast/encoding/json/json_test.go:154-186`; `iast/integration/testapp/e2e_test.go:224-263`
- Claim: `sql.Report`, `exec.Report`, `evidence.CollectString`/`CollectJoinedStrings`, and the `internal/taint/propagation` primitives all gate their expensive work behind a cheap `active.MayContain(key)` check (`internal/taint/evidence/evidence.go:106`, `iast/os/exec/exec.go:59-68`) that only returns true for a value that was actually derived from `taint.TaintString`/`TaintBytes`. Every "Active"-named benchmark in the repository except two passes a compile-time literal or untainted local variable through that gate: `sql_test.go:44 Report(ctx, "SELECT 1", ...)`, `exec_test.go:87 argv := []string{"echo", "clean"}`, `json_test.go:165-186 document := []byte(`{"value":"clean"}`)`, `overhead_test.go:40-97`'s six sub-benchmarks use plain literals like `"  attacker  "` that are never tainted despite the function's name (`BenchmarkPropagationActiveUntainted`), `operators_test.go:145 a, c := "alpha", "charlie"` (never tainted), and `e2e_test.go:240 document := []byte(`{"nested":{"value":"clean"}...`)`. This means every one of these benchmarks measures only the cost of the gate check itself, not the cost of the real detection path (evidence collection, `redaction.AnalyzeSQL`/`AnalyzeCommand`, `redaction.BuildWithSensitive`, `vulnerability.ReportTainted`, span attachment) that fires when a genuine SQL/command injection payload or a genuine tainted string reaches these call sites. Only `taint/taint_test.go:191 BenchmarkStringLookup/hit` (a bare boolean lookup) and `benchmarks/overhead/buffer_test.go:22 BenchmarkBytesBufferCopies` call `taint.TaintString`/`TaintBytes` and measure a genuine hit anywhere in the repository.
- Evidence: reproducers added to the private worktree and run there, output captured under `.omo/review/evidence/perf-bench-quality/`:
  - `sql-report-tainted-vs-clean.out.txt`: `BenchmarkReportActiveClean-16 15.13 ns/op 0 B/op 0 allocs/op` vs `BenchmarkReportActiveTainted-16 93713 ns/op 2759 B/op 38 allocs/op` (~6200x)
  - `exec-report-tainted-vs-clean.out.txt`: `BenchmarkReportActiveClean-16 21.18 ns/op 0 B/op 0 allocs/op` vs `BenchmarkReportActiveTainted-16 40523 ns/op 1162 B/op 19 allocs/op` (~1900x)
  - `concat4-tainted-vs-untainted.out.txt`: `internal/taint/propagation.Concat4` untainted `91.14 ns/op 0 allocs/op` vs tainted `39284 ns/op 1 allocs/op` (~430x; the machine is shared with other review agents per BRIEF.md, so treat the exact multiplier as noisy, but the qualitative gap reproduces across three independently written reproducers)
  - `json-literal-tainted-vs-clean.out.txt`: for a short JSON literal the gap is much smaller (`34.29 ns/op` clean vs `57.20 ns/op` tainted, 0 allocs either way) because a short literal is derived as a window rather than cloned — still, no such measurement exists in the shipped suite today.
  - repro source: `sql_repro_bench_test.go`, `exec_repro_bench_test.go`, `propagation_repro_bench_test.go`, `json_repro_bench_test.go`
- Fix: add one `*ActiveTainted` (or `.../hit`) sibling per sink/propagation benchmark that runs `taint.TaintString`/`TaintBytes` once during setup and feeds that value through the loop, mirroring what `BenchmarkStringLookup` and `BenchmarkBytesBufferCopies` already do correctly. Track both the miss and hit numbers in `benchstat` output so a hit-path regression is visible.

### perf-bench-quality-F2: Zero microbenchmarks for the core propagation engine, HTTP eager source tainting, span lifecycle, and several bridges named as the riskiest areas
- Severity: Medium
- Category: test-gap
- Location: `internal/taint/propagation/` (no `Benchmark*`); `internal/spans/` (no `Benchmark*`); `internal/taint/httpbridge/`, `internal/taint/jsonbridge/`, `internal/taint/writerbridge/` (no `Benchmark*`); `iast/net/http/` (no `Benchmark*`); `internal/taint/request/` (no `Benchmark*`, despite `fuzz_test.go`, `table_test.go`, `scope_test.go`, `owner_test.go`, `admission_behavior_test.go`, `lazy_behavior_test.go`, `internal_test.go` all existing there)
- Claim: `internal/taint/propagation` (`propagation.go`, `string_exact.go`, `bytes_exact.go`, `string_coarse.go`, `conversion.go`, `json.go`, `operator_concat.go`, `writer.go`) is the actual hot-path engine behind every one of the roughly 1,080 lines of call-site advice in `iast/propagation/orchestrion.yml`, and is called on every wrapped `strings`/`bytes`/`fmt`/`strconv`/`net/url`/operator/writer/JSON call in customer code once IAST is active -- yet it has no `Benchmark*` function anywhere. `internal/spans` (weak-key span annotation/owner lifecycle, source remap, 25,000-byte payload encoding -- risk area #10 in `.omo/review/phase1/00-architecture.md`), `internal/taint/httpbridge`, `internal/taint/jsonbridge` (decoder-slot collision risk -- risk area #5), and `internal/taint/writerbridge` are in the same position. `iast/net/http` and `internal/taint/request` -- `EagerHTTP` (`internal/taint/request/http.go:56-77`), which taints URI/path/query and rebuilds up to 32 header names/64 values on every sampled request, plus the 256-slot source `Table` and scope `Begin`/`Finish` sampling decision -- run on literally every inbound request when IAST is active, and also have no direct benchmark. These mechanisms are exercised only indirectly, in aggregate, through `benchmarks/overhead`'s `BenchmarkRequestProcessing`/`BenchmarkHTTPRoundTrip`, where a regression in one specific mechanism (say, header rebuilding, or span `Finish`) cannot be attributed and is diluted by `httptest` request-construction cost that both control and IAST binaries pay equally.
- Evidence: `grep -rln 'func Benchmark' internal/taint/propagation internal/spans internal/taint/httpbridge internal/taint/jsonbridge internal/taint/writerbridge iast/net/http internal/taint/request` returns nothing for any of these packages (directory listings confirmed no `*benchmark*_test.go` file exists). A reproducer added directly against `internal/taint/propagation.Concat4` (see F1's `concat4-tainted-vs-untainted.out.txt` and `propagation_repro_bench_test.go`) demonstrates the untested hit path in this exact package costs roughly two orders of magnitude more than the untainted path.
- Fix: add package-level benchmarks for `internal/taint/propagation` (miss/hit pairs for `Concat*`, `CopyString`, `StringWindow`, `JoinString`), `internal/taint/request` (`EagerHTTP` with a realistic header count, `Table` insertion/dedup under churn, `Begin`/`Finish`), and `internal/spans` (`Annotation` commit/`Finish` with the mock tracer). This closes the same class of gap the phase-1 architecture review already flagged as needing measurement (its "Open" check 24: "Measure `Stats().AverageProbe` and slow-path hit rate after many finished owners" -- there is no `Stats()`/`AverageProbe` accessor in the codebase at all yet, so this cannot currently be measured even if a benchmark were written).

### perf-bench-quality-F3: Operator concat/conversion/slice benchmarks give a false near-zero-overhead reading when run without Orchestrion weaving
- Severity: Medium
- Category: test-gap
- Location: `iast/propagation/operators_test.go:136-192`
- Claim: `BenchmarkOperatorConcat4Inactive`/`ActiveClean`, `BenchmarkOperatorConversionsInactive`, `BenchmarkOperatorOptimizedConversionExcluded`, and `BenchmarkOperatorSlicesInactive` measure plain Go operators (`+`, `string(data)`, slicing) whose IAST behavior only exists once Orchestrion has woven `iast/propagation/orchestrion.yml`'s operator advice into the call site. None of them check `built.WithOrchestrion`, unlike `TestOperatorEvaluationAndPanicSemantics` at line 195 in the very same file, which does `if !built.WithOrchestrion { t.Skip(...) }`. Run with plain `go test -bench=. ./...` -- the repository's own documented "Plain tests" invocation (`.omo/review/BRIEF.md` "Toolchain facts") and what a developer or a non-Orchestrion CI lane naturally runs -- `BenchmarkOperatorConcat4Inactive` and `BenchmarkOperatorConcat4ActiveClean` report statistically indistinguishable numbers, because `config.Enabled`/`request.Begin` have zero effect on an unwoven `+` operator: the advice that would call into `internal/taint/propagation` was never woven in. Reading these numbers without separately confirming the binary was woven, one would conclude IAST concat overhead is near zero; the benchmark neither skips nor reports whether weaving actually happened.
- Evidence: `.omo/review/evidence/perf-bench-quality/concat4-unwoven-no-signal.out.txt` -- plain (unwoven) `go test -bench=BenchmarkOperatorConcat4`: `Inactive-16 38.76 ns/op 24 B/op 1 allocs/op` vs `ActiveClean-16 38.17 ns/op 24 B/op 1 allocs/op` (identical within noise; both numbers are just the cost of a plain 4-operand Go string concatenation).
- Fix: add the same `built.WithOrchestrion` skip these benchmarks' sibling test already uses, or fail loudly (`b.Fatal`) when unwoven, so a plain `go test -bench=.` run cannot silently report a meaningless "0 ns overhead" result for these operator benchmarks.

### perf-bench-quality-F4: BenchmarkFinishWithActiveWriter times setup work and a goroutine spawn inside the loop, and has no b.ReportAllocs
- Severity: Low
- Category: quality
- Location: `internal/taint/store/lifecycle_test.go:37-49`
- Claim: The benchmark puts `store.Acquire()`, `owner.TaintString("retained-until-finish", 0)`, `owner.owner.lifecycleMu.RLock()`, a `go func(){ owner.Finish(); close(done) }()` spawn, and the `<-done` wait all inside `for b.Loop()`. This conflates the allocation/registration cost of `Acquire`+`TaintString` with the specific "Finish blocked behind a held read lock" behavior the name says it measures, and per-iteration goroutine creation adds scheduler noise on top of the signal being sought. There is also no `b.ReportAllocs()`, so none of the folded-in allocation cost is visible in `B/op`/`allocs/op`, unlike every other store benchmark.
- Evidence: static reasoning only (NEEDS-REPRO for a quantified before/after; the structural issue itself is visible directly at the cited lines)
- Fix: move `store.Acquire()`/`TaintString` construction to `b.ResetTimer()`-preceded setup that is redone per-iteration only where unavoidable (e.g., via `b.StopTimer()`/`b.StartTimer()` bracketing just the `Finish()`+lock-contention section), or accept the noise explicitly in a doc comment; add `b.ReportAllocs()`.

### perf-bench-quality-F5: BenchmarkCollectStringMiss is missing b.ReportAllocs()
- Severity: Low
- Category: quality
- Location: `internal/taint/evidence/evidence_test.go:182-187`
- Claim: `BenchmarkCollectStringMiss` calls `CollectString("clean-value", ...)` in a loop but never calls `b.ReportAllocs()`, unlike every other benchmark in the repository. `TestCollectStringMissDoesNotAllocate` a few lines below does assert zero allocations via `testing.AllocsPerRun`, so the guarantee is tested, but not by the benchmark itself -- a future regression that adds an allocation to the miss path would only show up as a latency delta with no `B/op`/`allocs/op` to diagnose it from benchmark output alone.
- Evidence: static reasoning only (NEEDS-REPRO; the gap is directly visible in the cited lines)
- Fix: add `b.ReportAllocs()`.

## Checked and found correct
- No dead-code-elimination artifacts were found in the benchmarks that were run: `internal/taint/ranges/benchmark_test.go`'s `dst`-writing pattern (`BenchmarkCanonicalizeTwo/ConcatTwo/SliceTwo`), `internal/taint/redaction/analyzer_test.go`'s `_ = AnalyzeSQL(...)`/`_ = AnalyzeCommand(...)` pattern, and `internal/taint/evidence/evidence_test.go`'s bare `CollectString(...)` call all produced plausible, non-near-zero `ns/op` when actually run (82ns-1.7ms depending on input size), consistent with the target functions being non-trivial and not inlined/eliminated. `AnalyzeSQL`'s three sub-benchmarks (typical/two-hundred-literal/quote-flood) correctly exercise algorithmic scaling independent of the taint gate, which is appropriate since the SQL analyzer's cost does not depend on whether its input is tainted.
- `benchmarks/overhead/buffer_test.go`'s `BenchmarkBytesBufferCopies` and `taint/taint_test.go`'s `BenchmarkStringLookup` correctly construct genuinely tainted input via `taint.TaintString`/`TaintBytes` before entering the timed loop, and their setup (buffer construction, bound method values `write, reset := unrelated.WriteString, unrelated.Reset`) is done outside `b.Loop()`.
- `benchmarks/overhead/overhead_test.go`'s `BenchmarkRequestProcessing`, `BenchmarkRequestProcessingParallel`, and `BenchmarkHTTPRoundTrip` do exercise a genuinely active-and-tainted code path: the handler's `req.FormValue`/`req.Header.Get` results flow through real `net/http` source hooks when the benchmark binary is woven and active, so `strings.TrimSpace`/`ToUpper`/`ToLower` on those values run the real propagation code, not just the gate check. Request/recorder construction inside the loop is intentional and correct for this suite's differential (control-vs-IAST, same-process-pair) design, since both binaries pay that cost identically; per-request allocation matches the documented `README.md` framing ("reveal fixed weaving overhead").
- `benchmarks/overhead/runner/main.go`'s methodology (isolated control/IAST source trees via `go mod edit -replace`, alternating sample order, fixed `GOMAXPROCS`, `benchstat` comparison, and `compareResultSets` verifying the two variants ran an identical benchmark set) is sound differential-benchmark design and was not found to have a validity defect.
- All Benchmark functions inspected use `for b.Loop()` (not the legacy `for i := 0; i < b.N; i++` pattern) and write results to package-level variables or `atomic.Int64`/typed fields rather than discarding them into an unused local, which is the standard Go idiom for avoiding accidental optimization of the measured work.

## Not covered / open questions
- I did not run the full differential `benchmarks/overhead/runner` tool end-to-end (it builds two full binaries with Orchestrion and requires `benchstat`); per BRIEF.md, wall-clock benchmarks are unreliable on this shared machine, and the runner's own methodology was reviewed by reading, not by executing a full comparison run.
- I did not attempt to build a fully woven comparison for F3 beyond the unwoven repro; an earlier attempt to run `go tool orchestrion go test -bench=BenchmarkOperatorConcat4 ./iast/propagation/...` in the private worktree was cancelled after several minutes because the shared machine was heavily loaded by other concurrent review agents' own Orchestrion builds (confirmed via `ps aux`), and the unwoven result alone already fully supports the claim (identical numbers with and without `config.Enabled`). Leftover child processes from that cancelled build were confirmed killed before finishing this review.
- I did not benchmark `internal/taint/store`'s `MayContain` slow-path/stale-slot-reclaim behavior under owner churn (phase-1 digest check 24); this would need a new benchmark and a `Stats()`/`AverageProbe` accessor that does not currently exist, so it is reported as part of F2 rather than independently reproduced.
- I did not review the nested `benchmarks/overhead/runner/main_test.go` (which tests the runner CLI itself, e.g. `splitRegexp`) since it contains no `Benchmark*` functions and is out of this node's focus.

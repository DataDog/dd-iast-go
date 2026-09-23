# light-bench-code: overhead benchmark runner and workload review
Verdict: No correctness findings in the reviewed benchmark runner and workloads.
Scope covered: `benchmarks/overhead/runner/main.go`, `runner/main_test.go`, `buffer.go`, `buffer_test.go`, `overhead_test.go`, `instrumentation_test.go`, `go.mod`, and `README.md`; runner unit tests, package tests, and the woven buffer benchmark smoke run.
## Findings
No findings.
## Checked and found correct
- The runner builds control and IAST test binaries in separate temporary source trees, then runs each sample as a separate process. It reverses control/IAST order on even-numbered samples.
- Benchmark samples inherit the requested sampling percentage, and metadata records it. Flag parsing rejects sampling outside 0–100 and preserves numeric parse errors.
- Result files are closed after each sample; benchmark-name sets are compared before benchstat runs. `benchstat` is declared as a Go tool in the nested module, and failures from both the tool invocation and output-file close are returned.
- Buffer workloads create taint through the ordinary wrapped `WriteString` path, distinguish copied-buffer reads/writes from unrelated untainted-buffer operations, and retain results in package-level sinks to prevent dead-code elimination.
- `go test -timeout 15m ./runner` passed, and `go test -timeout 15m ./...` passed in the overhead module.
- The one-iteration woven `BenchmarkBytesBufferCopies` smoke run passed.
## Not covered / open questions
- No wall-clock performance conclusions were drawn; the one-iteration woven run validates execution only.
- The full runner orchestration, including its dual builds and benchstat artifact generation, was reviewed statically but not run end to end.

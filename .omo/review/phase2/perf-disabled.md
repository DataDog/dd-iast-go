# perf-disabled: Disabled and sampled-out IAST overhead
Verdict: `DD_IAST_ENABLED=false` has zero measured allocations in the server/custom-handler hooks and representative propagation gates; `DD_IAST_REQUEST_SAMPLING=0` intentionally retains a per-request scope/context path (two or three allocations), an accepted design trade-off rather than a new High-severity defect.
Scope covered: `internal/config/config.go`, `internal/taint/request/{scope,lookup,owner}.go`, `internal/taint/{httpbridge,operatorbridge,writerbridge}`, `internal/taint/propagation/{propagation,writer}.go`, `internal/spans/{annotation,owner}.go`, `iast/net/http/orchestrion.yml`, `iast/propagation/{orchestrion.yml,strings.go,bytes.go,coarse.go,operators.go,writer.go}`, and the private `benchmarks/overhead` benchmark harness.

## Findings
### perf-disabled-F1: Sampled-out HTTP boundaries still allocate request state
- Severity: Info
- Category: perf
- Location: internal/taint/request/scope.go:73-103; iast/net/http/orchestrion.yml:17-45, 79-109
- Claim: A request with `DD_IAST_ENABLED=true` and `DD_IAST_REQUEST_SAMPLING=0` is not admitted to an analysis, but `begin` still constructs `Scope{DecisionSampledOut}` and calls `context.WithValue`. Both woven HTTP entry shapes observe `created=true`, so they execute the request-context clone and inactive eager path. The exact server-hook reproduction costs 432 B / 3 allocs per request; the custom application-handler reproduction costs 112 B / 2 allocs. This is not rated High because `phase1/01-design-intent.md` expressly records that the larger sampled-out HTTP bootstrap cost was accepted as a product decision.
- Evidence: `.omo/review/evidence/perf-disabled/disabled_path_bench_test.go` and `.omo/review/evidence/perf-disabled/direct-entry-hooks.txt`; `GOTOOLCHAIN=go1.26.6 go test -run '^$' -bench '^Benchmark(Disabled|SampledOut)(Server|Application)Hook$' -benchmem -benchtime=100000x -cpu=1`. The actual woven, sampling-zero runner output is retained in `.omo/review/evidence/perf-disabled/sampled-out-runner/`; it records unchanged allocation counts for `Health` (19) and `RequestProcessing` (47), while the real HTTP round trip rises from 414 to 423 allocs/op.
- Fix: If the accepted sampled-out cost is reopened, return the original context with `created=false` for `DecisionSampledOut`, then preserve only any required span-disabled telemetry without attaching a request `Scope`.

## Checked and found correct
- `DD_IAST_ENABLED=false` returns from `request.begin` before `Scope` construction or `context.WithValue`; `httpbridge.Begin` still performs its callback-load gate and the injected deferred `Finish` becomes a no-op. The direct server and application reproductions measured 0 B/op and 0 allocs/op.
- Direct propagation advice remains woven but is allocation-free while inactive: named windows go through `request.ActiveStore`, operators use `operatorbridge.HasValues`, and stateful writers use `WriterActive`. Disabled and sampled-out `named-window`, `operator-slice`, and `writer-state` gates all measured 0 B/op / 0 allocs/op in `.omo/review/evidence/perf-disabled/propagation-gates.txt`.
- The allocation-sensitive wrapper forms do not add allocations in the disabled or sampled-out state: `FmtSprintf` matches the standard formatter at 16 B/op and 1 alloc/op, and the `SplitSeq` adapter matches the standard sequence at 0 B/op and 0 allocs/op. Captured control/hook comparisons are in `.omo/review/evidence/perf-disabled/propagation-gates.txt`.
- Sampled-out requests do not call `defaultManager().Acquire`, so they take no analysis permit, create no store owner, and leave the operator/writer active counters zero. This follows from `sampleDecision(0)` and the `decision == DecisionActive` guard in `internal/taint/request/scope.go`.
- The private benchmark harness compiled cleanly with `GOTOOLCHAIN=go1.26.6 go test -run '^$' ./...`; its source and all output relied on by this report are retained under `.omo/review/evidence/perf-disabled/`.

## Not covered / open questions
- Wall-clock `ns/op` is recorded only as gate-cost context; shared-host timing is not used for a severity conclusion.
- The existing A/B runner hard-codes `DD_IAST_ENABLED=true`, so the disabled result uses an exact reproduction of the woven snippets with the same init-resolved config state rather than a whole-stack control/IAST runner comparison.
- This node did not benchmark JSON, reader, SQL, command, crypto, or URL-source bridge hooks outside the requested primary scope.

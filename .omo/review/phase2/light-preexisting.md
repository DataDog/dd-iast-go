# light-preexisting: Pre-existing crypto, stacktrace, and telemetry review
Verdict: No actionable defects found in the reviewed scope; focused plain and instrumented tests pass.
Scope covered: `iast/crypto/cipher/{cipher.go,cipher_test.go,orchestrion.yml,orchestrion.tool.go}`, `iast/crypto/hash/{hash.go,hash_test.go,orchestrion.yml,orchestrion.tool.go}`, `internal/vulnerability/stacktrace/{stacktrace.go,stacktrace_test.go}`, `internal/instrumentation/{instrumentation.go,telemetry/telemetry.go,telemetry/telemetry_test.go}`; related context in `internal/vulnerability/report.go`, `internal/vulnerability/tainted.go`, `internal/spans/orchestrion.go`, and `README.md`.
## Findings
None.
## Checked and found correct
- Weak-hash and weak-cipher reporting advice preserves standard-library crypto results in the focused instrumented tests; the tests also assert reported algorithm evidence and application call-site locations.
- `stacktrace.LocationFromFrame`, `Matches`, and generated-file detection cover nil frames, receiver layouts, namespace mismatches, and Unix/Windows generated paths in unit tests.
- Runtime telemetry counters use atomics, and the source/sink iterators are checked against all model enum values, including early-stop behavior.
- The nil context supplied by crypto advice follows `vulnerability.Report`'s explicit no-span path, which creates a separate orphan vulnerability span; README documents orphan events when no traced span is available. These constructors provide no context to propagate.
- Focused checks passed: `GOTOOLCHAIN=go1.26.6 go test -timeout 15m ./internal/vulnerability/stacktrace ./internal/instrumentation/telemetry` and `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 15m ./iast/crypto/hash ./iast/crypto/cipher`.
## Not covered / open questions
- No broad repository test suite, race run, or performance benchmark was run; this review was limited to the requested components and focused tests.

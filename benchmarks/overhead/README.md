# IAST Runtime Overhead Benchmarks

This package compares identical workloads compiled normally and with
`dd-iast-go` woven by Orchestrion. It measures runtime overhead only; compilation
time is deliberately excluded.

## Run

From the repository root:

```console
go -C benchmarks/overhead run ./runner
```

The benchmarks are a separate Go module with their own integration set,
including the `dd-trace-go` tracer and `net/http` integrations. The runner copies
only this module into two isolated source trees, uses `go mod edit` to replace
`github.com/DataDog/dd-iast-go` with the current repository, and builds both with
Orchestrion. The control tree retains the `dd-trace-go` integrations, while the
IAST tree also includes all relevant `dd-iast-go` integrations. It validates
both variants,
executes independent processes in alternating control/IAST order, and writes
`control.txt`, `iast.txt`,
`comparison.txt`, and `metadata.txt` to a temporary directory. Use `-outputdir`
to retain them at a known path.

Useful controls use the same names as `go test` where the concepts overlap:

| Flag | Default | Purpose |
|---|---:|---|
| `-count` | `10` | Independent process samples per variant |
| `-benchtime` | `500ms` | Go benchmark duration or iteration count per workload |
| `-cpu` | `1` | One fixed positive `GOMAXPROCS` and `-test.cpu` value |
| `-bench` | `.` | Benchmark selection expression |
| `-outputdir` | temporary | Artifact directory |
| `-sampling` | `100` | `DD_IAST_REQUEST_SAMPLING` value from 0 to 100 |

Unlike `go test -count`, every runner sample starts a fresh process so global
IAST state cannot survive between repetitions. The runner's `-cpu` flag accepts
one positive integer, not a comma-separated list.

For a quick smoke run:

```console
go -C benchmarks/overhead run ./runner -count=2 -benchtime=100ms

# Measure the sampled-out request path.
go -C benchmarks/overhead run ./runner -sampling=0 -bench=BenchmarkHTTPRoundTrip
```

## Workloads

- `Health` and `RequestProcessing` are realistic control workloads. Until HTTP
  taint aspects exist, they primarily reveal fixed weaving overhead.
- `HTTPRoundTrip` runs request processing through an `httptest` server and
  client so the `dd-trace-go` `net/http` integration is exercised in both
  variants.
- `WeakHashNoActiveSpan` measures a concrete IAST sink including creation and
  completion of the orphan vulnerability span used without an application span.
- `WeakHashActiveSpan` measures reporting into an active request span. Its mock
  tracer is reset after every operation, bounding retained spans independently
  of benchmark length.
- `WeakCipherNoActiveSpan` measures the corresponding orphan-reporting path for
  the instrumented DES constructor.
- `WeakCipherActiveSpan` measures DES reporting within an active request span.
- `RequestProcessingParallel` reports aggregate throughput under controlled
  contention. Its `ns/op` should not be interpreted as individual request
  latency.

Each workload reports `ns/op`, `B/op`, and `allocs/op`. The runner uses
`benchstat` to compare distributions. Prefer its confidence intervals over a
single percentage, and do not compare results collected on different machines.
Shared CI runners are useful for diagnostics but too noisy for hard regression
thresholds; use longer runs on a stable machine when investigating a change.

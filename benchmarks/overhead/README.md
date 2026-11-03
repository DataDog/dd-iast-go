# IAST Runtime Overhead Benchmarks

This package compares identical workloads compiled normally and with
`dd-iast-go` woven by Orchestrion or by otelc. It measures runtime overhead only;
compilation time is deliberately excluded.

## Run

From the repository root:

```console
go -C benchmarks/overhead run ./runner
```

The benchmarks are a separate Go module with their own integration set. The
runner does these steps:

1. It copies this module into two isolated source trees: control and IAST.
2. It removes the `dd-iast-go` integrations from the control tree. The control
   tree keeps the `dd-trace-go` integrations. The IAST tree keeps all the
   integrations.
3. It uses `go mod edit` to replace `github.com/DataDog/dd-iast-go` with the
   current repository.
4. It builds both trees with the selected tool (`-tool`). The integrations of
   each tool are in its tool file: `orchestrion.tool.go` for Orchestrion, and
   `otel.instrumentation.go` for otelc. With otelc, it also reads the otelc
   build report, to make sure that otelc built both variants and that only the
   IAST variant has the `dd-iast-go` rules.
5. It validates both variants.
6. It runs independent processes, in alternating control and IAST order.
7. It writes `control.txt`, `iast.txt`, `comparison.txt`, and `metadata.txt`
   to a temporary directory. Use `-outputdir` to keep them at a known path.

Useful controls use the same names as `go test` where the concepts overlap:

| Flag | Default | Purpose |
|---|---:|---|
| `-tool` | `orchestrion` | Build tool: `orchestrion` or `otelc` |
| `-count` | `10` | Independent process samples per variant |
| `-benchtime` | `500ms` | Go benchmark duration or iteration count per workload |
| `-cpu` | `1` | One fixed positive `GOMAXPROCS` and `-test.cpu` value |
| `-bench` | `.` | Benchmark selection expression |
| `-outputdir` | temporary | Artifact directory |

Unlike `go test -count`, every runner sample starts a fresh process so global
IAST state cannot survive between repetitions. The runner's `-cpu` flag accepts
one positive integer, not a comma-separated list.

For a quick smoke run:

```console
go -C benchmarks/overhead run ./runner -count=2 -benchtime=100ms
```

To build the variants with otelc:

```console
go -C benchmarks/overhead run ./runner -tool=otelc
```

Compare the results of the two tools only as two separate comparisons
(control versus IAST for each tool). Do not compare the absolute numbers of the
two tools:

- dd-trace-go does not have otelc rules for `net/http` yet. The otelc variants
  do not trace `net/http`, so `HTTPRoundTrip` does less work with otelc.
- otelc and Orchestrion must not share a Go build cache. The runner gives otelc
  a separate cache: the `OTELC_TEST_GOCACHE` directory (an absolute path) or,
  by default, the Go build cache directory with a `-otelc` suffix.

## Workloads

- `Health` and `RequestProcessing` are realistic control workloads. Until HTTP
  taint aspects exist, they primarily reveal fixed weaving overhead.
- `HTTPRoundTrip` runs request processing through an `httptest` server and
  client. With Orchestrion, the `dd-trace-go` `net/http` integration traces it
  in both variants. With otelc, nothing traces it: dd-trace-go does not have
  otelc rules for `net/http` yet.
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

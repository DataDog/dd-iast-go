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
IAST tree also includes all relevant `dd-iast-go` integrations. It runs three
variants:

| Variant | Binary | Results |
|---|---|---|
| control | control tree | `control.txt` |
| IAST | IAST tree | `iast.txt` |
| active | IAST tree, with `DD_IAST_BENCH_HEAPBITS=active` | `active.txt` |

The active variant differs only for the `HeapBits` workloads, which then
taint data with the allocator-backed taint bits. The runner validates the
variants, executes independent processes in a rotating order, and writes
`control.txt`, `iast.txt`, `active.txt`, `comparison.txt` (three columns),
`gate.txt`, and `metadata.txt` to a temporary directory. Use `-outputdir` to
retain them at a known path.

Useful controls use the same names as `go test` where the concepts overlap:

| Flag | Default | Purpose |
|---|---:|---|
| `-count` | `10` | Independent process samples per variant |
| `-benchtime` | `500ms` | Go benchmark duration or iteration count per workload |
| `-cpu` | `1` | One fixed positive `GOMAXPROCS` and `-test.cpu` value |
| `-bench` | `.` | Benchmark selection expression |
| `-outputdir` | temporary | Artifact directory |
| `-gate` | `false` | Fail when a `HeapBits` regression gate fails |

Unlike `go test -count`, every runner sample starts a fresh process so global
IAST state cannot survive between repetitions. The runner's `-cpu` flag accepts
one positive integer, not a comma-separated list.

For a quick smoke run:

```console
go -C benchmarks/overhead run ./runner -count=2 -benchtime=100ms
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
- `HeapBitsAllocChurn`, `HeapBitsGC` and `HeapBitsJSON` measure the
  allocator-backed taint bits (`internal/taint/heapbits`): allocation churn,
  a full GC of a heap with 1 Mi live objects, and JSON decoding and encoding.
  In the active variant, they taint 1 object in 4 (the JSON input for
  `HeapBitsJSON`).

## Regression gates

`gate.txt` reports two gates for the `HeapBits` workloads (plan
`_docs/plans/allocator-taint-bits.md`, section 7.2):

- IAST (the woven runtime hooks, with no taint) against control: no
  significant increase of `sec/op` greater than 2%;
- active against IAST for `HeapBitsGC`: no significant increase greater than
  10%, for `sec/op` and for `stw-p99-ns` (the 99th percentile of the wait to
  stop the world, at the resolution of the runtime histogram).

The gates use only the `HeapBits` workloads: the other workloads of the IAST
variant also run IAST detections (for example `WeakHash*`), which cost more
by design.

Without `-gate`, the report is informative. Use `-gate` with enough samples
(for example `-count=10`) on a stable machine. With `-gate`, a gate whose
workloads the `-bench` expression does not select (`SKIP`) also fails.

Each workload reports `ns/op`, `B/op`, and `allocs/op`. The runner uses
`benchstat` to compare distributions. Prefer its confidence intervals over a
single percentage, and do not compare results collected on different machines.
Shared CI runners are useful for diagnostics but too noisy for hard regression
thresholds; use longer runs on a stable machine when investigating a change.

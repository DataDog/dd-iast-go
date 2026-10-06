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
`gate.txt`, `gate.tsv`, and `metadata.txt` to a temporary directory. Use `-outputdir` to
retain them at a known path.

Useful controls use the same names as `go test` where the concepts overlap:

| Flag | Default | Purpose |
|---|---:|---|
| `-count` | `10` | Independent process samples per variant |
| `-benchtime` | `500ms` | Go benchmark duration or iteration count per workload |
| `-cpu` | `1` | One fixed positive `GOMAXPROCS` and `-test.cpu` value |
| `-bench` | `.` | Benchmark selection expression |
| `-outputdir` | temporary | Artifact directory |
| `-sampling` | `100` | `DD_IAST_REQUEST_SAMPLING` value from 0 to 100 |
| `-gate` | `false` | Fail when a regression gate fails |
| `-builddir` | temporary | Keep the build in a directory; a later run with the same directory reuses the binaries (same source only) |
| `-rotation` | `0` | Start the rotation of the variants `n` samples later (for a driver that runs one sample at a time) |
| `-evaluate` | `false` | Build and run nothing: compare the results of `-outputdir` and write `comparison.txt`, `gate.txt` and `gate.tsv` |

The variable `DD_IAST_BENCH_TAINT_LIVE=1` selects the "taint live elsewhere"
variant: a request that holds a tainted value stays active during the whole
process, while the workloads run (see `support_test.go`). The runner passes
the variable to the benchmark processes and records it in `metadata.txt`.

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
- `Strings*`, `Bytes*`, `Fmt*`, `URL*` and `Strconv*` (21 workloads) and
  `BytesBufferCopies/*` run the propagation hooks of the standard library with
  no request, or with no tainted value (gate G-A3).
- `PropagationActiveUntainted/*` run propagation hooks in an active request
  that has no tainted value (gate G-A4; needs `-sampling=100`).
- `ConcatChainHeap` and `ConcatChainStack` run a maximal `a+b+c+d` chain with
  no request (gate G-A5: same allocations).
- `SinkSQL/*` and `SinkCommand/*` send a tainted query parameter through
  propagation shapes (`tainted`, `taintedConcat`, `taintedBuilder`,
  `taintedSprintf`) to `database/sql` and `os/exec` sinks in a sampled
  request. `sinks_validation_test.go` checks that each tainted call gives
  exactly 1 vulnerability. There is no gate: the numbers are for the record.
  Note that one request keeps at most `DD_IAST_VULNERABILITIES_PER_REQUEST`
  findings: the timed loop measures the sink check and the dropped report.
- `HeapBitsAllocChurn`, `HeapBitsGC` and `HeapBitsJSON` measure the
  allocator-backed taint bits (`internal/taint/heapbits`): allocation churn,
  a full GC of a heap with 1 Mi live objects, and JSON decoding and encoding.
  In the active variant, they taint 1 object in 4 (the JSON input for
  `HeapBitsJSON`).

## Regression gates

`gate.txt` reports the following gates. They are informative, unless `-gate`
is set. `gate.tsv` has the numbers of the G-A gates, one line for each
workload (tab-separated).

| Gate | Workloads | Compare | Limit |
|---|---|---|---|
| G-A1 | `HTTPRoundTrip`, `-sampling=0` | control, IAST | +3.70 % (+6 % with `DD_IAST_BENCH_GATE_PROFILE=ci`) |
| G-A2 | `HTTPRoundTrip`, `-sampling=100` | control, IAST | none (record) |
| G-A3 | `Strings*`, `Bytes*`, `Fmt*`, `URL*`, `Strconv*` | control, IAST | under 80 ns: +4 ns; else +5 %; +0 allocations |
| G-A4 | `PropagationActiveUntainted/*`, `-sampling=100` | control, IAST | same as G-A3 |
| G-A5 | `ConcatChain*` | control, IAST | +0 allocations |
| G-C | `HeapBits*` | see below | see below |

The gates G-A1 to G-A5 are those of PR #39. The estimate is the difference of
the medians. For G-A3 and G-A4, the 95 % one-sided paired-bootstrap upper
bound of the difference must also pass. The samples of the two variants are
paired by position (the runner runs both variants in each round). G-A1 gates
the estimate only. A gate that does not apply to the sampling is `N/A`.

The gates G-C (plan `_docs/plans/allocator-taint-bits.md`, section 7.2) use
only the `HeapBits` workloads:

- IAST (the woven runtime hooks, with no taint) against control: no
  significant increase of `sec/op` greater than 2%;
- active against IAST for `HeapBitsGC`: no significant increase greater than
  10%, for `sec/op` and for `stw-p99-ns` (the 99th percentile of the wait to
  stop the world, at the resolution of the runtime histogram).

The other workloads of the IAST variant also run IAST detections (for example
`WeakHash*`), which cost more by design.

Use `-gate` with enough samples (for example `-count=10`; at least 4, because
with fewer samples `benchstat` never finds a significant difference) on a
stable machine. With `-gate`, a gate whose workloads the `-bench` expression
does not select (`SKIP`) also fails.

## Runtime hooks harness

`.github/runtime-bench.sh` and `.github/runtime-bench.py` measure the runtime
hooks (`iast/runtime/bench_test.go`) in woven builds with and without the
hooks (gate group G-B, profiles `local` and `ci`). See the header of
`.github/runtime-bench.sh`.

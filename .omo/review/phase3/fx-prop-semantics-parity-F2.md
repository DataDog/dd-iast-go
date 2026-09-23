# fx-prop-semantics-parity-F2: zero-precision fmt operand taints clean SQL

Verdict: **CONFIRMED.** An advertised direct `fmt.Sprintf` path propagates a tainted argument even when `fmt` emits none of that argument's bytes, and a real SQL sink reports the otherwise clean query.

## Verdict per finding

### prop-semantics-parity-F2: fmt.Sprintf taints an argument that emitted no bytes

- **Verdict:** CONFIRMED.
- **Claim checked:** `fmt.Sprintf("...%.0s...", tainted)` returns a byte-identical clean query but receives provenance and reaches SQL evidence collection.
- **Result:** Confirmed through a woven HTTP-query -> application `fmt.Sprintf` -> `database/sql.ExecContext` flow. The query was exactly `"SELECT 40 + 2 /*  */"`, `query_tainted=true`, the byte-identical literal control was clean, and the sink emitted one SQL finding.

## Reproduction

Independent source and output are under `.omo/review/evidence/fx-prop-semantics-parity-F2/`:

- `woven_http_sql_repro_app.go`
- `woven_http_sql_repro_test.go`
- `woven_http_sql_go1.26.6.out.txt`

Command:

```sh
cd /tmp/ddiast-review/wt/fx-prop-semantics-parity-F2/iast/integration/testapp
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l \
  go tool orchestrion go test -timeout 8m -count=1 \
  -run '^TestHTTPQuery_SprintfZeroPrecision_reportsCleanSQL$' -v .
```

Key output:

```text
query="SELECT 40 + 2 /*  */" query_tainted=true clean_control_tainted=false sql_findings=1
PASS
```

An independent propagation-fixture reproducer also observed `sink_status=1` for the same clean output; its source and output are saved beside the end-to-end evidence. Go 1.27.0 could not be evaluated because the pinned Orchestrion instrumentation fails to compile the Go 1.27 `encoding/json` internals (`dec.r`/`dec.d` missing); the captured failure is `woven_http_sql_go1.27.0.out.txt`.

## Reachability

Reachable for ordinary root-application code on the supported Go 1.26.6 toolchain:

1. `iast/propagation/orchestrion.yml` replaces direct root-package `fmt.Sprintf` calls with `iast/propagation.FmtSprintf`.
2. HTTP query values are supported sources, and the reproducer obtains `r.URL.Query().Get("omitted")` inside a woven request.
3. `database/sql.ExecContext` is a supported sink and emitted the false SQL-injection report.

The test sets 100% sampling to make observation deterministic. Defaults still enable IAST with 30% request sampling, so an otherwise normal sampled request can trigger the same false report. This is **not** a documented limitation: README lists `fmt.Sprint*` as supported formatting, and its direct-call limitation does not exclude zero-precision directives.

## Adjusted severity

**High** (unchanged): this is wrong provenance and a false-positive SQL-injection report on an advertised, direct propagation path. It violates the product accuracy rule, although it does not change the application's SQL bytes or execution.

## Root cause

`internal/taint/propagation/string_coarse.go:115-130` obtains taint keys from the format plus every inspected direct argument before considering formatting semantics. `string_coarse.go:175-197` then clones the full result and assigns a full-result coarse range for each accumulated owner. `FmtSprintf` in `iast/propagation/coarse.go:43-45` supplies all variadic arguments, so a `%.0s` operand is treated as contributing despite emitting zero bytes.

There are no duplicate findings in this assignment.

## Minimal fix

Replace unconditional argument accumulation for `FmtSprintf` with single-execution, directive-aware emission tracking: add provenance only for arguments that produced bytes in the native format result, while retaining format-literal provenance. The implementation must not call user `String`/`Format` methods a second time or alter `fmt` values, panics, or evaluation order. Lock it with the woven HTTP-to-SQL zero-precision regression: the returned query must remain byte-identical, untainted, and produce zero SQL findings.

# Evidence: crash-config-extremes (phase2)

All commands ran against a private copy at
`/tmp/ddiast-review/wt/crash-config-extremes` (rsync of the main checkout,
`.git`/`.omo` excluded), removed after this review node finished. Nothing in
the main checkout was modified.

## 1. `internal/config` matrix harness (`configdump_main.go`)

A standalone program (`cmd/configdump`) that imports `internal/config`,
observes the resolved values, and prints them as JSON. It exists because
`internal/config` resolves its values once from `init()` at process start, so
each environment combination needs its own process.

Build:
```
cd /tmp/ddiast-review/wt/crash-config-extremes
GOTOOLCHAIN=go1.26.6 go build -o /tmp/ddiast-review/configdump ./cmd/configdump
```

Then run with 57 environment combinations covering the full brief matrix
(`DD_IAST_MAX_RANGE_COUNT`, `DD_IAST_TRUNCATION_MAX_VALUE`,
`DD_IAST_VULNERABILITIES_PER_REQUEST`, `DD_IAST_MAX_CONCURRENT_REQUESTS`,
`DD_IAST_REQUEST_SAMPLING`, malformed/unterminated regexes for both redaction
patterns and their compatibility aliases, `DD_IAST_REDACTION_ENABLED`, and
`DD_IAST_ENABLED`, plus negative numbers, non-numeric strings, and
uint64-overflowing numbers not explicitly in the brief but implied by
"extreme"). Full per-combination input/output is in
`configdump_matrix_results.json`.

**Result: 57/57 exit code 0, zero panics.** Every numeric value clamps to its
documented bound with a warning; every malformed boolean/regex/integer falls
back to its default with a warning; nothing crashes.

## 2. Woven end-to-end reproducer (`config_extremes_test.go`)

Copied into `iast/integration/testapp/` (a nested woven test module) in the
private copy. It sets `internal/config` package variables directly to the
*post-clamp* values the matrix above proves each environment combination
resolves to (the package-level `config.*` variables are exactly what
`iast/integration/testapp`'s own tests mutate for setup, since that package's
`init()` unconditionally overrides env-derived config for its own baseline
tests), then drives real HTTP requests through the woven `net/http` -\>
`database/sql` sink path via `httptest`, and inspects the produced
`model.Event`/span tags.

Covered scenarios: `MaxConcurrentRequests=0` (disables analysis, confirmed via
`_dd.iast.enabled=0`), `MaxConcurrentRequests` saturated by 256 concurrent
requests against the clamped ceiling of 64, `VulnerabilitiesPerRequest=1`,
`VulnerabilitiesPerRequest` hard max of 64 under 100 sink hits in one request,
`TruncationMaxValue=0`, `TruncationMaxValue=MaxUint64`, `RedactionEnabled=false`
(documented bypass), an invalid-regex-pattern fallback, and `Enabled=false`.

Commands:
```
cd /tmp/ddiast-review/wt/crash-config-extremes/iast/integration/testapp
GOTOOLCHAIN=go1.26.6 go vet ./...
GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -run TestConfigExtremes -v -race -timeout 900s ./...
```

`woven_run1_test_harness_bug.log` is the first attempt: one subtest
(`...SaturatedDropsWithoutPanic`) failed with `"[]" should have 1 item(s), but
has 0`. That was a bug in the *test harness*, not the product: it called
`mocktracer.Start()`/`.Stop()` concurrently from 256 goroutines, and
`mocktracer` is a process-global recorder not safe for concurrent
(re)starting. The test was rewritten to use one shared mocktracer/httptest
server and fire concurrent HTTP client requests at it instead.
`woven_run2_race_pass.log` is the corrected run: **9/9 PASS under `-race`**,
including the 256-way concurrent saturation case.

## 3. Baseline test suites

`config_unit_tests.log`: `go test ./internal/config/... -v` (pre-existing
suite) - all pass.

`internal_baseline_test.log`: `go test ./internal/... -timeout 300s` (plain,
non-woven) - 26/26 packages pass, 0 failures.

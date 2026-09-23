# fx-hooks-yml-operators-F4: disabled operator allocation regression

Verdict: **CONFIRMED.** The woven paths add one heap allocation to each tested
nonescaping concat/conversion operation before the inactive bridge gate can
return. This contradicts the operator plan's disabled-path allocation-parity
requirement.

Scope covered: `iast/propagation/operators.go`,
`iast/propagation/orchestrion.yml`, `internal/taint/operatorbridge/bridge.go`,
README propagation coverage, and Phase 6 plan performance requirements.

## Verdict per finding

### hooks-yml-operators-F4: CONFIRMED

My independent fixture has separate uninstrumented controls in an excluded
`internal/reviewf4native` package. On Go 1.26.6, the native controls and the
unwoven expressions report zero allocations; the same expressions in the woven
root package report one allocation each while `operatorbridge.HasValues()` is
false:

* `len(a + b)`: `native=0 injected=1`
* `a + b == "abcdef"`: `native=0 injected=1`
* `converted := string(value); len(converted)`: `native=0 injected=1`

The check is deterministic (`testing.AllocsPerRun(200, ...)`) and uses global
sinks so the observed operations cannot be dead-code eliminated.

## Reproduction

Reproducer source and captured output:

* `.omo/review/evidence/fx-hooks-yml-operators-F4/reproducer_test.go`
* `.omo/review/evidence/fx-hooks-yml-operators-F4/native_control.go`
* `.omo/review/evidence/fx-hooks-yml-operators-F4/plain-go1266.txt`
* `.omo/review/evidence/fx-hooks-yml-operators-F4/woven-go1266.txt`
* `.omo/review/evidence/fx-hooks-yml-operators-F4/woven-default-go1266.txt`

Commands:

```sh
cd /tmp/ddiast-review/wt/fx-hooks-yml-operators-F4
GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 DD_IAST_ENABLED=false \
  go test -timeout 3m -count=1 -v ./reviewf4

GOFLAGS=-p=4 REVIEW_WOVEN=1 GOTOOLCHAIN=go1.26.6 DD_IAST_ENABLED=false \
  /usr/bin/time -l go tool orchestrion go test -timeout 3m -count=1 -v ./reviewf4
```

The former passes with `0/0` allocation parity. The latter fails exactly on
the three cases above; peak RSS was 327,499,776 bytes, below the brief's
4-GB reporting threshold. With `DD_IAST_ENABLED` unset, the woven Go 1.26.6
run reproduces the same `0/1` results, proving default-configuration
reachability when no active taint values exist. The Go 1.27.0 woven attempt
cannot reach these hooks because the separate `encoding/json` instrumentation
does not compile against Go 1.27.0; its captured compiler errors are in
`woven-go1270.txt`.

## Reachability

**Reachable by ordinary root-module customer code on the supported Go 1.26.6
toolchain and default configuration.** The aspects weave every eligible
two-operand string concat and byte-to-string conversion in root packages.
`HasValues` is an atomic counter check, but the host expression is already
computed and passed through a propagation-capable call before it is checked.
The default-enabled run proves the counter-zero path without relying solely on
`DD_IAST_ENABLED=false`.

This is **not a documented limitation**. README documents optimized conversion
contexts such as direct comparisons and map keys as intentionally unwrapped,
not direct string concatenation or an assignment/declaration conversion used
only by `len`. The README advertises both concat and allocation-preserving
byte-to-string declarations, while Phase 6 explicitly requires disabled and
active-clean local paths to add no allocations.

## Adjusted severity

**High (unchanged).** This is an avoidable one-allocation tax on common,
eligible hot-path expressions even while IAST has no active values, violating
the product rule that expensive work be gated cheaply and the documented plan
performance gate. It does not alter values or provenance, so it is not
Critical.

## Root cause

`iast/propagation/orchestrion.yml:23-31` rewrites all matched concat
expressions to `iastprop.Concat2(...)`; `operators.go:18-26` computes `a+b`
and passes it to `concat2Result` before its `HasValues` check. Likewise,
`orchestrion.yml:337-341` wraps eligible conversions and
`operators.go:198-204` materializes `string(value)` before checking the gate.
The potential active-path calls to `internal.Concat2` and
`internal.BytesToString` make these intermediate results escape despite the
eventual inactive return.

## Minimal fix

Generate a gate-at-call-site fast path that evaluates each original operand
once but tests activity **before** materializing the concat/conversion result:
return the original native `a+b` or `string(value)` expression when inactive;
only call propagation helpers on the active path. Keep the existing
single-evaluation/type-preservation constraints. Add this fixture as a woven
allocation-parity regression test for disabled and active-clean states.

# fx-base-test-127-F1: Go 1.27 JSON instrumentation

Verdict: All three findings are confirmed on their substantive failure modes. The two compile-break reports duplicate one defect; the job-server memory explosion is a separate amplification of that defect.

## Verdict per finding

- **base-test-127-F1 — CONFIRMED.** The Go 1.27 woven `encoding/json` compiler rejects the injected `dec.r` and `dec.d` references. A valid application cannot be woven.
- **hooks-compile-matrix-F2 — CONFIRMED.** Our own program imports `strings` but not `encoding/json` and still fails on Go 1.27 through dd-iast-go's woven dependency closure. The previous matrix's exact 7/7 count was not rerun; this independent program verifies the important "no JSON import" extension. "Only Go 1.27 blocker" means only one observed in that matrix, not an exhaustive guarantee.
- **hooks-compile-matrix-F6 — CONFIRMED.** The *same minimal program*, rather than x/exp, raised the orchestrion build's peak RSS to **24,120,426,496 bytes** and ended in `nats: maximum payload exceeded`. This confirms the high-memory failure mode, not the exact x/exp 17–22 GiB figures or the attribution of a separately observed 40 GB process. Error fanout is a plausible mechanism, not independently proved by tracing allocations.

## Reproduction

All commands ran in a private rsync copy of HEAD `2e23b46`, with `GOFLAGS=-p=4` unless noted. Reproducer: `.omo/review/evidence/fx-base-test-127-F1/minimal/main.go`.

| Command from private copy | Result / evidence |
| --- | --- |
| `GOTOOLCHAIN=local GOFLAGS=-p=1 /usr/bin/time -l timeout 120 go tool orchestrion go build encoding/json` | Exit 1: `<generated>:2: dec.r undefined`, `dec.d undefined`; `.omo/review/evidence/fx-base-test-127-F1/json127-compiler.txt`. |
| `GOTOOLCHAIN=local GOFLAGS=-p=4 /usr/bin/time -l timeout 180 go tool orchestrion go build -o /dev/null ./repro` | Exit 1: `resolving woven dependency on .../iast/database/sql: internal error: nats: maximum payload exceeded`; maximum RSS **24,120,426,496 B**; `.omo/review/evidence/fx-base-test-127-F1/build127-default.txt`. |
| `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l timeout 180 go tool orchestrion go build -o /dev/null ./repro` | Exit 0; maximum RSS **438,992,896 B**; `.omo/review/evidence/fx-base-test-127-F1/build126-control.txt`. |
| `GOTOOLCHAIN=local GOEXPERIMENT=nojsonv2 GOFLAGS=-p=4 /usr/bin/time -l timeout 180 go tool orchestrion go build -o /dev/null ./repro` | Exit 0; maximum RSS **426,426,368 B**; `.omo/review/evidence/fx-base-test-127-F1/build127-nojsonv2-control.txt`. |

The direct standard-library build gives the compiler diagnostic obscured by the application's NATS transport failure. `go list -f '{{join .GoFiles " "}}' encoding/json` selected `v2_stream.go` by default on Go 1.27, versus `stream.go` under `GOEXPERIMENT=nojsonv2` or Go 1.26.6.

## Reachability

The copied module's `go.mod:3` requires Go 1.26.6, not an upper bound; the local default Go 1.27.0 accepts it. No unusual runtime setting or direct JSON import is needed. `orchestrion.tool.go:19` enables the JSON aspect, while the ordinary customer build of a package with only `strings` still reaches the broken woven closure. `README.md` documents **Go 1.26 JSON propagation coverage**, but does not document a permissible build failure on Go 1.27. Safe loss of unsupported propagation would be a limitation; rejecting valid builds violates the explicit host-safety rule in `AGENTS.md` and `CONTRIBUTING.md`.

## Adjusted severity

| ID | Severity | Reason |
| --- | --- | --- |
| base-test-127-F1 | **Critical** (unchanged) | Compile failure on valid instrumented customer code. |
| hooks-compile-matrix-F2 | **Critical** (unchanged) | Same compile failure reaches customer code without a JSON import. |
| hooks-compile-matrix-F6 | **Critical** (unchanged) | Reproduced 24.1 GB build-process RSS and NATS failure on a one-file program; the specific 17–22 GiB x/exp measurement is not needed for the rating. |

## Root cause (file:line)

`iast/encoding/json/orchestrion.yml:28-47` unconditionally matches `(*encoding/json.Decoder).Decode` and emits `.r` and `.d`. Go 1.27's selected `encoding/json/v2_stream.go:19-24,71-96` instead defines `dec`, `opts`, and calls JSON v2. The remaining legacy `decodeState` aspects (`orchestrion.yml:49-117`) do not match JSON v2 and cannot supply JSON v2 provenance. F1 and F2 have the **same root cause**. F6 adds an Orchestrion failure-path amplifier: its `internal/jobserver/nbt/nbt.go:161-162,261` saves and fans out failed-build errors, `internal/toolexec/aspect/oncompile.go:174` wraps dependency errors, and `internal/jobserver/server.go:109` uses the maximum NATS payload. These lines suggest repeated error expansion; profiling would be needed to prove where the 24 GB was retained.

## Minimal fix

Constrain legacy JSON advice to a verified legacy standard-library layout or implementation and add JSON-v2-specific advice if Go 1.27 propagation is required. If the selected layout is unsupported, omit the advice without breaking the host build. Test a woven executable with and without direct JSON imports on both versions and under `GOEXPERIMENT=nojsonv2`. Independently cap/deduplicate Orchestrion's propagated compiler errors and fail promptly after the first dependency failure, rather than retaining and rewrapping unbounded error text.

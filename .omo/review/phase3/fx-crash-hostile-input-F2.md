# fx-crash-hostile-input-F2: quota admission happens after expensive SQL reporting work

Verdict: **CONFIRMED.** On the target Go 1.26.6 toolchain, a woven HTTP request with the default event quota ran all 40 tainted SQL reports but committed only two.

Scope covered: `iast/database/sql/sql.go`, `internal/vulnerability/tainted.go`, `internal/spans/tainted.go`, `internal/model/event.go`, SQL and HTTP Orchestrion aspects, configuration, README/design intent, and a private woven HTTP-to-`database/sql` reproduction.

## Verdict per finding

### crash-hostile-input-F2

- Verdict: **CONFIRMED**
- Duplicate status: no other candidate was supplied; no duplicate comparison applies.
- Mechanism: `sql.Report` executes `evidence.CollectString` and `redaction.AnalyzeSQL` before entering `vulnerability.ReportTainted` (`iast/database/sql/sql.go:35-46`). `ReportTainted` then runs `redaction.BuildWithSensitive`, resolves an annotation, and calls `CaptureLocationSkipWhile` before `commitTainted` (`internal/vulnerability/tainted.go:57-84`). Only `Annotation.TryCommitTainted` rejects an event at its vulnerability cap through `Event.CanAddVulnerability` (`internal/spans/tainted.go:61-70`; `internal/model/event.go:43-57`). This is the only event-quota check on that path.

## Reproduction

Evidence: `.omo/review/evidence/fx-crash-hostile-input-F2/quota-repro.go` and `.omo/review/evidence/fx-crash-hostile-input-F2/quota-repro.log`.

The independent program is a woven root executable. It starts a real `net/http` server, reads `Request.FormValue("q")`, creates/binds a request span, and passes that tainted value through 40 `database/sql.ExecContext` calls using a real `database/sql` driver.

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go build -o quota-woven ./cmd/quota-repro
DD_TRACE_STARTUP_LOGS=false DD_IAST_ENABLED=true DD_IAST_REQUEST_SAMPLING=100 \
  ./quota-woven -operations=40 -payload-bytes=30000
```

Key output with default quota and default deduplication:

```text
operations=40 payload_bytes=30000 executed_tainted=40 recorded_vulnerabilities=2 handler_elapsed=699.7515ms
```

The same program with two sinks recorded `2/2` in `12.121375ms`. A control with deduplication disabled and quota 64 recorded `40/40`, proving the source-to-sink path itself is valid. `ExecutedTainted` is incremented immediately before `BuildWithSensitive`; together with the static path above and valid control commits, this shows reports continue through analysis/evidence construction after the default event is full. The elapsed values are one shared-machine observation, not a benchmark.

Go 1.27.0 could not build this woven reproduction because the pinned Orchestrion integration generated invalid `encoding/json` field accesses; capture: `.omo/review/evidence/fx-crash-hostile-input-F2/go127-build.log`. That toolchain incompatibility does not refute the Go 1.26.6 runtime result.

## Reachability

**Reachable under default configuration:** yes, for every request selected by the default 30% sampler. IAST is enabled by default; event quota is two and deduplication is enabled by default (`internal/config/config.go:70-75`, README Runtime Configuration). Ordinary supported customer code needs only a woven root executable, an HTTP-derived value, and more than two tainted `database/sql` sink calls in one selected request. The reproduction set sampling to 100% solely to make that ordinary selected-request path deterministic.

This is **not** a documented limitation. README calls out Cost Control, and the design intent explicitly requires expensive work to be gated by cheap eligibility checks; neither documents post-quota sink analysis as an accepted trade-off.

## Adjusted severity

**High (unchanged).** The default quota bounds reports but not the repeated, bounded-yet-expensive hot-path work of selected requests. The independent 30 KiB reproduction shows 38 discarded reports still traverse the reporting pipeline; this is several times more work than necessary and conflicts with the stated host-overhead rule.

## Root cause

`iast/database/sql/sql.go:35-46` starts evidence collection and six-dialect SQL analysis before admission. `internal/vulnerability/tainted.go:57-84` builds evidence and captures a stack before `internal/spans/tainted.go:69` evaluates capacity.

## Minimal fix

For an already-bound request span, add an advisory non-mutating annotation-capacity probe (using `TryRLock`, checking open/sample state and current vulnerability count) before `CollectString`/`AnalyzeSQL`; return immediately when the event is full. Keep `TryCommitTainted` as the authoritative locked transaction to handle races and event-local deduplication. Preserve the current owner/orphan fallback when there is no bound annotation.

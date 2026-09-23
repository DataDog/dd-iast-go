# fx-perf-memory-F1: deduplicated SQLi findings still pay full evidence, redaction and stack capture

Verdict: CONFIRMED — the mechanism is real at HEAD 2e23b46, independently reproduced through a woven (Orchestrion) build; measured magnitude matches the finder.

## Verdict per finding

### perf-memory-F1 — CONFIRMED (severity High upheld)

1. **Code at HEAD 2e23b46.** Every cited line is accurate. `iast/database/sql.Report` runs `evidence.CollectString` (sql.go:37) and `redaction.AnalyzeSQL` (sql.go:45, argument evaluated at the call) with no dedup knowledge; the only cheap gate before it is `sqlbridge.Active()` (any active owner, bridge.go:56). `internal/vulnerability.ReportTainted` then runs `redaction.BuildWithSensitive` (tainted.go:57), span/annotation selection, and a full `CaptureLocationSkipWhile` depth-32 stack capture with a UUID (tainted.go:76; `StackTraceEnabled` defaults to **true**, config.go:84) before `commitTainted`, whose `dedup.Set.Check` (tainted.go:93) is the first and only process-level dedup test. The event-local hash check inside `TryCommitTainted`/`Event.CanAddVulnerability` (model/event.go:64-74) is per-span and also post-evidence. For SQLi the hash is `fnv32(type, location.Line, location.Path[, Method])` only (model/vulnerability.go:24-43) — no evidence, sources, or redaction output enters it, so all work before the hash computation is unnecessary for the dedup decision. This directly violates AGENTS.md ("all expensive operations are gated by a cheap check"); `Set.Check` is a non-blocking lock plus a fixed-array scan (dedup.go:57-72) — cheap. Not a documented limitation: README "Cost Control" claims overhead-minimization efforts, and dedup is documented as a feature, not as "deduplicated reports still pay full cost".

2. **Independent reproduction** (own minimal harness, woven): see below.

3. **Reachability.** Default config = sampling 30%, dedup ON, stack traces ON. Any woven customer app with a real SQLi at a fixed call site — the steady state of a production service — hits this on every sampled request for the whole 1-hour dedup window. Supported toolchain Go 1.26.6 + pinned Orchestrion (my builds used exactly that). `reachable_default: true`, `documented_limitation: false`.

4. **Severity: High (unchanged).** Steady-state hot-path allocation overhead several times larger than necessary: a deduplicated tainted request costs 22.5 KB vs a ~10 KB necessary floor (sampled-out + one committed finding), and the discarded report work alone (11.7–17.9 KB/req) exceeds 1.5–2.2x the entire plain request allocation. One minor nuance, not enough to demote: computing the dedup hash *does* require a location capture, so a small stack capture (~0.5–1 KB; the depth-1 pattern already exists in `selectLocationTrace`, report.go:196-208) is unavoidable before the check — the finder's "~18 KB is discarded" is right in substance; strictly ~95% of it is avoidable, since the depth-32 `NewEvent` capture (8.5 KB/req) is far more than the single application frame the hash needs.

Duplicates: the JSON under test contains a single item; no duplicates of this root cause were listed. The claim that it is distinct from crash-hostile-input-F2 (quota) holds: the quota (`VulnerabilitiesPerRequest`) is enforced even later, inside `TryCommitTainted` → `Event.CanAddVulnerability`, a different check on a different path; fixing the quota check alone would not remove this cost.

## Reproduction

Commands (full detail in `evidence/fx-perf-memory-F1/README.txt`):

```
# private copy, harness at iast/integration/testapp/cmd/dedupprobe/main.go (evidence/fx-perf-memory-F1/dedupprobe_main.go)
cd iast/integration/testapp && export GOTOOLCHAIN=go1.26.6 GOFLAGS="-p=4 -mod=mod"
go build -o out/dedup-plain ./cmd/dedupprobe
/usr/bin/time -l go tool orchestrion go build -o out/dedup-woven ./cmd/dedupprobe   # rc 0, 108 s, peak RSS 417 MB
env DD_TRACE_STARTUP_LOGS=false DD_INSTRUMENTATION_TELEMETRY_ENABLED=false DD_IAST_REQUEST_SAMPLING=100 \
  ./out/dedup-woven -n=300 -warm=20 -memprofile=prof/woven-s100.pprof
go tool pprof -top -cum -focus=iast/database/sql.Report -sample_index=alloc_space out/dedup-woven prof/woven-s100.pprof
```

Key output (`prof/my-results.json`, n=300+warm=20, per-request TotalAlloc around the handler):

| variant | B/req | obj/req | vulns committed (whole run) |
|---|---:|---:|---:|
| plain | 6,233 | 60 | 0 |
| woven, sampling 0 | 9,940 | 72 | 0 |
| woven, sampling 100, dedup ON (default) | 22,521 | 153 | **1** |
| woven, sampling 100, dedup OFF | 26,354 | 181 | 320 |

pprof (`prof/woven-s100-report-focus.txt`, 320 requests): `iast/database/sql.Report` cum 3.65 MB = **11.7 KB/request** although only 1 of 320 reports committed; `CaptureLocationSkipWhile` 2.71 MB = **8.47 KB/req** (matches the finder's 8.5 KB/req), `AnalyzeSQL` 0.51 MB, `BuildWithSensitive` 0.24 MB, `CollectString` 0.16 MB. An earlier partial run of this node (same evidence dir, `run.log`/`report-focus-p10.txt`, 10-param scenario) corroborates: `executed_tainted=500, measured_committed=0`, Report cum 8.33 MB over 551 requests = 15.1 KB/req. The finder's numbers (33,570 vs 8,209 B plain = 4.09x; Report cum 17.9 KB/req = 71% of the +25.4 KB sampled overhead) are consistent with both.

## Reachability

Ordinary customer code: an application woven with Orchestrion, default env (30% sampling, dedup on, stack traces on), containing one genuine SQLi concatenation at a fixed call site. Every sampled request after the first pays the full report pipeline and has its finding discarded. No special input, config, or toolchain beyond the supported one.

## Adjusted severity

**High** — steady-state hot-path overhead several times the necessary cost on a default-config path; violates the repo's own "expensive work gated behind cheap checks" operating constraint.

## Root cause

`internal/vulnerability/tainted.go:52-100` (`ReportTainted`): gate ordering — evidence collection (`iast/database/sql/sql.go:37,45`), redaction (`tainted.go:57`), and full stack capture (`tainted.go:76`) all execute before the first cheap eligibility test (`dedup.Set.Check`, tainted.go:93). Single root cause; the discarded work is the whole report pipeline.

## Minimal fix

In `ReportTainted` (tainted.go): first capture only a *shallow* location using the existing depth-1 recapture pattern (`selectLocationTrace`, report.go:196-208) plus the `SkipWhile` policy, compute the hash from type+location, and consult `taintedReportDedup.Check` (and, for the orphan path, the annotation's remaining capacity) **before** `CollectString`/`AnalyzeSQL`/`BuildWithSensitive`/full-stack capture. Capture the full depth-32 trace with UUID only for a finding that will actually commit, and reuse the already-captured shallow location. Alternative half-measure: hoist the dedup check into `iast/database/sql.Report` before `CollectString`, keyed on a cheap location.

## Checked and found correct

- Dedup itself is bounded and non-blocking: fixed 1,000-hash array, TryLock, hour-window clear (`dedup/dedup.go`); contention skips dedup rather than suppressing reports.
- `sqlbridge.Report` shields panics and gates on active owners before any report work; the fake-driver sink runs the real woven `database/sql.QueryContext` advice path.
- No retention: end-state gauges zero in the finder's matrix; my run's dedup variant holds no event bytes after the single committed finding.
- The location is genuinely required for the hash (type+Line+Path), so *some* capture must precede the dedup check — noted as a nuance, not a refutation.

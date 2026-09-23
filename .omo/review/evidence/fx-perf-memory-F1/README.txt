fx-perf-memory-F1 independent verification evidence (HEAD 2e23b46, GOTOOLCHAIN=go1.26.6,
orchestrion v1.12.2-0.20260828141217-23afa71d6dcb)

## Completed run (this deliverable) - reproducer: dedupprobe_main.go

dedupprobe_main.go was placed at <private copy>/iast/integration/testapp/cmd/dedupprobe/main.go
(a module with its own go.mod, replace directive back to the repo root), package main.
Handler has the exact func(http.ResponseWriter, *http.Request) shape so the woven build
installs the application.http.Handler fallback advice (Begin/EagerHTTP/Finish); one tainted
query param is concatenated into SQL text and executed with database/sql.QueryContext on a
fake driver (real sink). The mocktracer is NEVER reset, so vulns_total counts every
committed vulnerability across the whole process.

Build (one at a time, from iast/integration/testapp, GOTOOLCHAIN=go1.26.6 GOFLAGS="-p=4 -mod=mod"):
  plain:  go build -o out/dedup-plain ./cmd/dedupprobe
  woven:  /usr/bin/time -l go tool orchestrion go build -o out/dedup-woven ./cmd/dedupprobe
         -> exit 0, 108.3 s, peak RSS 436,862,976 B (~417 MB, below the 4 GB build-memory threshold)

Run matrix (env DD_TRACE_STARTUP_LOGS=false DD_INSTRUMENTATION_TELEMETRY_ENABLED=false),
n=300 measured + warm=20, per-request TotalAlloc/Mallocs deltas around the handler call:
  out/dedup-plain                    -> prof/my-results.json:"plain"
  DD_IAST_REQUEST_SAMPLING=0         -> "woven-s0"     (weaving + scope floor)
  DD_IAST_REQUEST_SAMPLING=100       -> "woven-s100"   (default dedup ON) + -memprofile=prof/woven-s100.pprof
  DD_IAST_REQUEST_SAMPLING=100
  DD_IAST_DEDUPLICATION_ENABLED=false -> "woven-s100-nodedup"

Results (prof/my-results.json):
  plain                6,233 B / 60 obj per req,  vulns_total=0
  woven-s0             9,940 B / 72 obj per req,  vulns_total=0
  woven-s100 (dedup) 22,521 B / 153 obj per req,  vulns_total=1   (3.61x plain; ONE finding in 320 requests)
  woven-s100-nodedup  26,354 B / 181 obj per req,  vulns_total=320 (every request commits)

Attribution (prof/woven-s100-report-focus.txt, pprof -top -cum -focus=iast/database/sql.Report
-sample_index=alloc_space out/dedup-woven prof/woven-s100.pprof; MemProfileRate=1, 320 requests):
  iast/database/sql.Report           cum 3.65 MB  = 11.7 KB per request  (all after the first discarded)
  CaptureLocationSkipWhile           cum 2.71 MB  = 8.47 KB per request (stack capture: NewEvent,
                                     SkipAndCaptureWithDepth, framesIterator.capture, newQueue, uuid)
  ReportTainted                      cum 2.98 MB
  redaction.AnalyzeSQL               cum 0.51 MB
  redaction.BuildWithSensitive       cum 0.24 MB
  evidence.CollectString              cum 0.16 MB
So 319 of 320 requests ran CollectString + AnalyzeSQL + BuildWithSensitive + a full depth-32
stack capture with UUID, and every one of those reports was then dropped by the only dedup
test, dedup.Set.Check at internal/vulnerability/tainted.go:93. The stack-capture cost matches
the finder's measurement (8.47 vs 8.5 KB/req) exactly.

## Earlier partial run of this node (16:09, kept for corroboration) - dedupcost_main.go

A first attempt of this node built a second woven harness (dedupcost_main.go, root module)
with a 10-param SQLi scenario and a bound-args control. Its woven build (build.log) exited 0
in 275.96 s with peak RSS 447,463,424 B. Its single completed measurement (run.log):
  DD_IAST_REQUEST_SAMPLING=100 -mode=vuln -params=10, 50 warmup (first reports) + 500 measured:
  bytes_per_req=30,743 objs=278 executed_tainted=500 warm_committed=1 measured_committed=0
i.e. telemetry confirms ReportTainted executed on ALL 500 measured requests while ZERO
committed. Its pprof (report-focus-p10.txt, 551 requests): sql.Report cum 8.33 MB =
15.1 KB/req (CaptureLocationSkipWhile 4.23 MB, BuildWithSensitive 2.17 MB, CollectString
1.08 MB, AnalyzeSQL 0.80 MB). report-focus-p1.txt / *-objs-*.txt / vuln-p*.pprof are the
same run's remaining artifacts. These independently reproduce the finding at the same
magnitude as the finder (17.9 KB/req for the 10-param typical scenario).

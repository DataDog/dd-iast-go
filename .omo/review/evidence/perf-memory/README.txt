perf-memory evidence (HEAD 2e23b46, GOTOOLCHAIN=go1.26.6, orchestrion v1.12.2-0.20260828141217-23afa71d6dcb)

Harness (placed in the private copy, now deleted):
  memprobe_main.go                -> iast/integration/testapp/cmd/memprobe/main.go (package main in the root module of the testapp)
  request_zz_perfmemory_probe.go  -> internal/taint/request/zz_perfmemory_probe.go (review-only read gauges, no behavior change)
  spans_zz_perfmemory_probe.go    -> internal/spans/zz_perfmemory_probe.go        (review-only read gauges)
Build (from iast/integration/testapp, GOFLAGS="-p=4 -mod=mod"):
  plain: go build -o out/memprobe-plain ./cmd/memprobe
  woven: /usr/bin/time -l go tool orchestrion go build -o out/memprobe-woven ./cmd/memprobe   (peak RSS 452 MB, build-woven-rusage.txt)
Run: run-matrix.sh (one fresh process per variant x scenario; writes results.jsonl, prof/results.jsonl, prof/*.pprof).
  summary.txt is the tabulated results.jsonl (delta/ratio are versus the plain build of the same scenario;
  typical49 is compared with plain typical, overcap with plain worst).

Method: handlers have the func(http.ResponseWriter,*http.Request) shape, so the woven build installs the
application.http.Handler fallback advice (Begin/EagerHTTP/Finish). Each handler starts a request span via
tracer.StartSpanFromContext (mocktracer; reset outside the window) and calls db.QueryContext on a fake driver.
Only the handler call sits between two runtime.ReadMemStats calls; TotalAlloc/Mallocs deltas are recorded per
request (n=2000, warm=200; worst/overcap n=300, warm=30). Retention: HeapAlloc after 2x runtime.GC() after warmup
vs after the n requests (retained_over_n), plus IAST gauges (store values/charged, permits, span annotations,
event-source bytes, owner-span bindings). live_in_request_over_end = post-GC HeapAlloc measured INSIDE a final
diagnostic request (after its sinks, before Finish) minus the post-run baseline. The diagnostic request also
records owner drop counters and the emitted event.

Scenarios: clean (constant SQL, no request data), safe (10 params as bound args), typical (10 params
concatenated into SQL text), typical49 (typical + 39 filler params = 49 names), worst (47 params, 31 headers,
46.6 KB JSON body, 64+-segment Builder query, 100 distinct tainted queries, 400 x 12 KB tainted Repeat,
16000 two-byte windows: saturates 4096 request values, 2 MiB request root bytes, 64 vulns/event),
overcap (256 params, 64 headers: above the source-map caps). idle = no-op woven handler (scope-only floor).
Variants: plain, woven-off (DD_IAST_ENABLED=false), woven-s0 (sampling 0), woven-s100 (sampling 100, other
defaults incl. dedup on), woven-s100-nodedup, woven-saturated (sampling 100, dedup off, ranges 64, vulns 64),
woven-defaults (all product defaults: 30% sampling).
Profiles: MemProfileRate=1 over the whole run (1+warm+n+1 requests: typical/clean 322, worst 27);
prof/*.top.txt are pprof -top -sample_index=alloc_space diffs, prof/*peek*.txt caller attributions.
Caveat: mocktracer rejects meta-struct so events use the _dd.iast.json fallback (encoding/json) instead of msgp.

life-soak evidence (HEAD 2e23b46, GOTOOLCHAIN=go1.26.6, orchestrion pinned v1.12.2-0.20260828141217-23afa71d6dcb)

Harness: soak_main.go was placed at iast/integration/testapp/cmd/soak/main.go in the private copy
(/tmp/ddiast-review/wt/life-soak, now deleted). request_soak_export.go -> internal/taint/request/soak_export.go and
spans_soak_export.go -> internal/spans/soak_export.go are review-only read gauges (no behavior change).

Build:
  cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-mod=mod go tool orchestrion go build -o soak ./cmd/soak
  ... same with -race -o soak-race
Runs (stdout = CSV, one row per 10k requests; each row taken after a 200-request serial probe, closing idle
connections, draining mocktracer spans, and runtime.GC() x2):
  ENV="DD_IAST_ENABLED=true DD_IAST_REQUEST_SAMPLING=50 DD_IAST_MAX_CONCURRENT_REQUESTS=8 DD_IAST_VULNERABILITIES_PER_REQUEST=4 DD_IAST_DEDUPLICATION_ENABLED=false DD_TRACE_STARTUP_LOGS=false DD_INSTRUMENTATION_TELEMETRY_ENABLED=false"
  soak-mock.csv     : env $ENV ./soak -n 300000 -warm 20000                (mocktracer, 320k requests)
  soak-real.csv     : env $ENV ./soak -real-tracer -n 200000 -warm 20000   (tracer.Start, agent unreachable, 220k)
  soak-defaults.csv : DD_IAST_ENABLED=true ./soak -real-tracer -n 200000 -warm 10000  (product defaults: 30%, 2 permits, dedup on)
  soak-disabled.csv : DD_IAST_ENABLED=false ./soak -n 100000 -warm 20000   (same woven binary, IAST off; baseline)
  soak-race.csv     : env $ENV GORACE=halt_on_error=0 ./soak-race -n 60000 -warm 10000   (race detector)
  *.stderr.txt      : stderr minus the expected "localhost:8126 connection refused" tracer line (all empty)
  soak-race.race-count.txt : count of "WARNING: DATA RACE" in race stderr (0)

Workload (16 client goroutines, keep-alive loopback client, request kind = i % 16):
  tainted SQL via slicing/TrimSpace/Join/Sprintf/concat -> Prepare/Exec/Query (3/16); os/exec with tainted path (1/64);
  clean SQL; panicking handler after sink (half http.ErrAbortHandler, half string panic; POST so the transport never replays);
  early return without reading POST body or starting a span; early http.Error; JSON Decoder body -> SQL;
  ParseForm/FormValue/PostFormValue/Cookie/Header -> strings.Builder/bytes.Buffer/ToUpper -> SQL; orphan (no span) SQL;
  late goroutine that runs a SQL sink 2ms AFTER the handler returned; io.ReadAll body -> ReplaceAll -> SQL;
  8 KiB tainted header -> Repeat -> SQL; no-span untainted; nested HandlerFunc with PathValue -> SQL.

Summary computed from the CSVs (slope = least squares of post-GC HeapAlloc over soak rows):
soak-mock: {"samples":30,"slope_bytes_per_req":"0.1983","projected_per_1M":"193.7KiB","first_half_avg":"16368401","second_half_avg":"16400619","heap_min":16303104,"heap_max":16486832,"objs_first":10110,"objs_last":9914,"gor":[6]} probe_min=90 probe_max=112 max_permits_used=0 max_live_slots=0 max_store_values=0 max_store_charged=0 max_annotations=0 max_event_source_bytes=0 max_owner_bindings=0 overflow_free_min=256 max_tombstones=2913 final_acquire_drops=1384 failures=0 elapsed_s=40.9 # panics=20000 late=20000 failures=0
soak-real: {"samples":20,"slope_bytes_per_req":"0.3509","projected_per_1M":"342.7KiB","first_half_avg":"26223267","second_half_avg":"26260475","heap_min":26124136,"heap_max":26352024,"objs_first":14503,"objs_last":14592,"gor":[15]} probe_min=90 probe_max=120 max_permits_used=0 max_live_slots=0 max_store_values=0 max_store_charged=0 max_annotations=0 max_event_source_bytes=0 max_owner_bindings=0 overflow_free_min=256 max_tombstones=3052 final_acquire_drops=623 failures=0 elapsed_s=21.7 # panics=13750 late=13750 failures=0
soak-defaults: {"samples":20,"slope_bytes_per_req":"-5.2227","projected_per_1M":"-5100.2KiB","first_half_avg":"26034525","second_half_avg":"25730058","heap_min":21309696,"heap_max":26833288,"objs_first":14619,"objs_last":14880,"gor":[15]} probe_min=49 probe_max=83 max_permits_used=0 max_live_slots=0 max_store_values=0 max_store_charged=0 max_annotations=0 max_event_source_bytes=0 max_owner_bindings=0 overflow_free_min=256 max_tombstones=4781 final_acquire_drops=33 failures=0 elapsed_s=16.8 # panics=13125 late=13125 failures=0
soak-disabled: {"samples":10,"slope_bytes_per_req":"0.2531","projected_per_1M":"247.1KiB","first_half_avg":"2000574","second_half_avg":"2022830","heap_min":1977896,"heap_max":2054264,"objs_first":9512,"objs_last":9593,"gor":[6]} probe_min=0 probe_max=0 max_permits_used=0 max_live_slots=0 max_store_values=0 max_store_charged=0 max_annotations=0 max_event_source_bytes=0 max_owner_bindings=0 overflow_free_min=0 max_tombstones=0 final_acquire_drops=0 failures=0 elapsed_s=7.2 # panics=7500 late=7500 failures=0
soak-race: {"samples":6,"slope_bytes_per_req":"2.0129","projected_per_1M":"1965.7KiB","first_half_avg":"16195080","second_half_avg":"16254099","heap_min":16158440,"heap_max":16309304,"objs_first":9845,"objs_last":10088,"gor":[6]} probe_min=90 probe_max=112 max_permits_used=0 max_live_slots=0 max_store_values=0 max_store_charged=0 max_annotations=0 max_event_source_bytes=0 max_owner_bindings=0 overflow_free_min=256 max_tombstones=3500 final_acquire_drops=599 failures=0 elapsed_s=42.2 # panics=4375 late=4375 failures=0

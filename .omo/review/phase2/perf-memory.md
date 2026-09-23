# perf-memory: per-request memory overhead of taint tracking
Verdict: Memory is bounded and fully released. After every request, retained heap returns to baseline and every IAST gauge returns to zero, in all 30 variant x scenario runs. Live in-request heap in the saturated worst case stays near the 2 MiB request root budget. Allocation volume is the weak point: a sampled typical request allocates 4.1x the plain build (5.5x when it reports), mostly on report work that deduplication then throws away (High). A sampled-out request still pays a 3.4 KB annotation, and tainted `strings.Repeat` doubles its allocation even after the byte budget is exhausted.
Scope covered: `internal/spans/annotation.go` (Annotation layout, `BindScope`, `trimStore`), `internal/spans/tainted.go` (event source bounds), `internal/taint/store/{limits,store,root,owner}.go` (fixed tables, root/byte/value reservation), `internal/taint/request/{scope,owner,http,lazy}.go` (admission, eager/lazy source caps), `internal/taint/propagation/propagation.go:262-320` (`RepeatString`), `internal/vulnerability/tainted.go:31-110`, `iast/database/sql/sql.go:34-49`, `internal/model/vulnerability.go:24-50` (hash inputs). Ran: a new woven vs plain `package main` harness (`evidence/perf-memory/memprobe_main.go`). It was built once plainly and once with Orchestrion. The woven build peaked at 452 MB RSS. I ran 30 fresh-process variant x scenario measurements plus 9 allocation profiles with `MemProfileRate=1`.

Measured per request (TotalAlloc/Mallocs delta around the handler call only; full table in `evidence/perf-memory/summary.txt`):

| Scenario | plain | IAST off | sampled out | sampled, dedup on | sampled, reporting |
|---|---|---|---|---|---|
| clean (constant SQL) | 5,481 B / 54 obj | 5,657 / 60 | 9,276 / 66 | 9,387 / 71 | n/a |
| safe (10 bound args) | 7,524 / 81 | 7,697 / 87 | 11,313 / 93 | 13,404 / 153 | n/a |
| typical (10 params -> SQL text) | 8,209 / 82 | 8,384 / 88 | 12,001 / 94 | 33,570 / 265 (4.09x) | 45,407 / 324 (5.53x) |
| worst (all request bounds saturated) | 5.31 MB / 1,149 | 5.31 MB | 5.31 MB | 12.07 MB (2.28x) | 13.09 MB / 11,804 (2.47x, 64 vulns) |

At product defaults (30% sampling), typical averages 18,767 B per request (2.29x plain): p50 is 12,000 B (sampled out) and p99 is 33,400 B. The first sampled request in a process allocates a one-time 14.25 MB fixed footprint (`store.New` 13.08 MB plus `NewManager` 0.84 MB).

## Findings
### perf-memory-F1: Deduplicated SQLi findings still pay full evidence, redaction and stack capture (~18 KB per sampled tainted request)
- Severity: High
- Category: perf
- Location: internal/vulnerability/tainted.go:57,76,90-100; iast/database/sql/sql.go:37-45
- Claim: With default deduplication on, a sampled request that reaches an already-reported SQLi location still runs all of the report work before the only dedup test at `commitTainted` (`set.Check`, tainted.go:93): `evidence.CollectString` (sql.go:37), `redaction.AnalyzeSQL` (sql.go:45), `redaction.BuildWithSensitive` (tainted.go:57), and a full `CaptureLocationSkipWhile` stack capture with a UUID (tainted.go:76). The SQLi hash covers only type, location line, and path (`model/vulnerability.go:24-43`), so no evidence or redaction output is needed to test dedup. This is the steady state for a production service: the same vulnerable call site is hit on every sampled request, and every result is discarded. The trigger differs from crash-hostile-input-F2, which covers the per-request quota: fixing the quota check alone does not remove this cost.
- Evidence: `evidence/perf-memory/results.jsonl` / `summary.txt`: `woven-s100 typical` allocates 33,570 B / 265 objects per request with `diag_vulns=0` (deduplicated), versus 12,001 B for sampled-out and 8,209 B for plain. `prof/s100-typical-report-focus.txt` (322 requests, only the first one emitted): `iast/database/sql.Report` cum 5.76 MB, which is 17.9 KB per request, or 71% of the +25.4 KB sampled overhead. Of that, `CaptureLocationSkipWhile` is 2.73 MB (8.5 KB per request), `BuildWithSensitive` 1.66 MB, `CollectString` 0.83 MB, and `AnalyzeSQL` 0.52 MB. Command: `env DD_IAST_REQUEST_SAMPLING=100 ./memprobe-woven -scenario=typical -n=300 -warm=20 -memprofile=prof/s100-typical.pprof`, then `go tool pprof -top -cum -focus='iast/database/sql.Report' -sample_index=alloc_space memprobe-woven prof/s100-typical.pprof`.
- Fix: Compute the location with a shallow capture (depth to the first application frame) and check `dedup.Set.Check` together with the quota before collecting evidence, lexing SQL, redacting, or capturing the full trace. Capture the full stack only for a finding that will actually be committed.

### perf-memory-F2: Every sampled-out request with a span allocates a 3,456-byte Annotation
- Severity: Medium
- Category: perf
- Location: internal/spans/annotation.go:37-55,199-205
- Claim: `BindScope` runs `LoadOrCompute` for a sampled-out scope, and the callback allocates `&Annotation{Sampled: active}` with `active == false` (line 204). `Annotation` embeds the fixed arrays `sourceIndex [512]uint16` and `eventSourceIndexes [256]int` (lines 47-49), so the object lands in the 3,456-byte size class. It exists only to record "not sampled", although the immutable `nonSampledAnnotation` sentinel (line 29) already exists for that purpose. At the default 30% sampling rate this hits about 70% of requests: a sampled-out request allocates +3.8 KB (+46% over plain for typical) against +0.18 KB for weaving alone. Sampled requests that never report also pay the full 3.4 KB. The size is bounded but more than 10x the necessary cost. perf-disabled-F1 recorded the allocation count but not the size.
- Evidence: `summary.txt`: `woven-off clean` 5,657 B against `woven-s0 clean` 9,276 B, with only +6 objects. In the no-span `idle` handler, sampled out costs just 128 B. `prof/s0-clean-bindscope-peek.txt`: `internal/spans.BindScope.func1` 1,112,832 B over 322 requests = 3,456 B per request. Command: `env DD_IAST_REQUEST_SAMPLING=0 ./memprobe-woven -scenario=clean -n=300 -warm=20 -memprofile=prof/s0-clean.pprof`, then `go tool pprof -peek 'spans.BindScope.func1' ...`.
- Fix: For sampled-out scopes, store a shared immutable sentinel, or a pointer-sized marker, instead of a fresh `Annotation`. Allocate the `sourceIndex` and `eventSourceIndexes` tables lazily on the first `TryCommitTainted`.

### perf-memory-F3: Tainted strings.Repeat always clones its result, even after the owner's byte budget is exhausted
- Severity: Medium
- Category: perf
- Location: internal/taint/propagation/propagation.go:262-297 (clone at 294, adopt at 316)
- Claim: `repeatStringHit` clones every tainted `strings.Repeat` result up to 64 KiB, and only afterwards attempts `AdoptString`. The clone exists to isolate the stdlib's static fast-path backing (`strings.Repeat` returns `repeatedSpaces[:n]` and similar only for short results, strings.go:640-649 in go1.26.6). For any longer result it simply doubles the allocation. Worse, once the owner's 2 MiB root budget is full, `reserveRootSlot` rejects the root, yet the clone is still made and returned. Each call then allocates twice for nothing, which conflicts with the AGENTS.md rule that expensive work be gated behind a cheap check. In the saturated worst case, this single path is 63% of the +7.8 MB per-request overhead.
- Evidence: `prof/sat-worst-clone-peek.txt`: `strings.Clone` <- `propagation.repeatStringHit` 132,710,400 B over 27 requests = 4.92 MB per request = 400 x 12,288 B. Every call cloned, although the diagnostic owner counters show `Bytes: 244` drops (`results.jsonl`, woven-saturated worst `diag_owner`), so 244 of the 400 clones per request were discarded immediately. Command: `env DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false DD_IAST_MAX_RANGE_COUNT=64 DD_IAST_VULNERABILITIES_PER_REQUEST=64 ./memprobe-woven -scenario=worst -n=20 -warm=5 -memprofile=prof/sat-worst.pprof`.
- Fix: Clone only when the result could alias static backing (for example `len(result) <= 128`, or when the fast-path prefix matches). Before cloning, check the owner's remaining root and byte budget cheaply, and skip the clone on saturation. The other clone-then-adopt paths (propagation.go:170,402; `joinStringHit`) deserve the same pre-check.

### perf-memory-F4: Requests with more than 48 query names or 32 header names get no query or header taint at all
- Severity: Medium
- Category: false-negative
- Location: internal/taint/request/lazy.go:163-173; internal/taint/request/http.go:97-106
- Claim: `manageMap` returns the original map untouched when it has more than 48 names or 96 values, and `taintHeaders` does the same above 32 names or 64 values. The caps are therefore all-or-nothing rather than "taint the first N". An attacker, or simply a wide search form, can add filler parameters and disable SQL injection detection for every parameter of the request. That is a false negative on the supported query-to-SQL path, and it is not documented in the README. This finding challenges the bounded-work trade-off under rule 4.
- Evidence: `results.jsonl`: `woven-s100 typical49` (the same handler and 10 injected params plus 39 `fN=1` fillers) gives `tainted_query=false`, `diag_vulns=0`, `owner_sources=3` (URI, path, and raw query only), whereas `typical` gives `tainted_query=true`. `overcap` (256 params, 64 headers) likewise shows `owner_sources=3`, `tainted_query=false`. Command: `env DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false ./memprobe-woven -scenario=typical49 -n=10 -warm=1`.
- Fix: Taint the first 48 names / 96 values (and 32/64 headers) in deterministic order and leave only the tail untainted, with a drop counter. Alternatively, document the cap and its evasion consequence.

### perf-memory-F5: Fixed and in-request footprint match the documented envelope
- Severity: Info
- Category: memory-bound
- Location: internal/taint/store/store.go:201-208; internal/taint/request/scope.go:47-59
- Claim: The first sampled request allocates 14.25 MB once (`store.New` 13.08 MB, `NewManager` 0.84 MB), the same as life-soak-F1 and below the 24 MiB envelope. In the saturated worst case (4,096 values, 2 MiB charged roots, 64 vulnerabilities, a 19 KB event), live heap measured inside the request is +2.48 MB over baseline. This matches the 2 MiB root charge plus the event. Under default config, the worst case is +2.10 MB. The typical request holds +8.4 KB live, against +2.1 KB in the plain build.
- Evidence: `summary.txt` columns `one_time_init_heap` and `live_in_request_over_end`; `prof/s100-typical-vs-s0.top.txt` (store.New and NewManager lines).
- Fix: None required. Note that an idle sampled-out process never pays the 14 MB, while a single sampled request pins it for the process lifetime.

## Checked and found correct
- No retention after requests. Across all variants, including plain, the post-GC heap after n requests differs from post-warmup by 9-50 KB in total (17-100 B per request), which is the same noise level as the plain build (17-64 B per request). `gauges_end` is zero everywhere: store values, charged bytes, permits, span annotations, event-source bytes, and owner-span bindings. Tombstones remain, but they sit in fixed pointer-free tables.
- IAST disabled (`DD_IAST_ENABLED=false`) costs +173-228 B and +6-7 objects per request, which is weaving-only (context and GLS wrapping). This is consistent with perf-disabled.
- The saturated worst case enforces its bounds. The diagnostic owner shows `owner_values=4096` (RequestValueLimit), `owner_charged_bytes=2,094,048` (below 2 MiB) with `Bytes: 244` and `Full: 11,767` drops, the event is capped at 64 vulnerabilities and 19,221 B (below 25,000), and nothing panicked. With the default quota of 2 and dedup off, the worst case emits exactly 2 vulnerabilities (`woven-s100-nodedup worst`).
- Deduplicated reporting emits no event bytes after the first finding (`diag_event_json_bytes=0`), and span annotation cleanup keeps the map empty between sequential requests.

## Not covered / open questions
- In the worst-case run, 200 JSON strings decoded through `json.NewDecoder(r.Body).Decode` from a 46.6 KB `httptest` body came out untainted (`stages.sources`: tainted=78 of 278). I did not investigate why. This belongs to sink-json-sources and life-json-decoder.
- The mocktracer rejects meta-structs, so events use the `_dd.iast.json` encoding/json fallback rather than msgp. Production event encoding cost may differ slightly (`msgp.Require` also appears in the profiles).
- Orchestrion injects `tracer.Start` into the woven `main`, which makes background agent connection attempts. The `idle` rows show no measurable background allocation inside the handler window.
- Measurements are sequential. Concurrent-request memory, meaning up to 64 owners x 2 MiB against the 8 MiB process cap, was not measured here; see perf-contention and crash-stress-app.
- No wall-clock timings were taken, per the brief.

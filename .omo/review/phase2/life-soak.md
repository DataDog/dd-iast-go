# life-soak: Request-lifecycle soak test for memory and goroutine leaks
Verdict: No leak found. Over 320k (mocktracer) plus 220k (real tracer) plus 210k (product defaults) plus 70k (race) woven requests, post-GC heap, heap object count, goroutine count, and every IAST lifecycle gauge (permits, live slots, store values and charged bytes, overflow blocks, span annotations, event-source bytes, owner-span bindings) stay flat or return to zero after every 10k batch. Serial probes show no gradual self-disable, and the race detector reports 0 races. No Critical or High issue.
Scope covered: Ran a woven executable (`iast/integration/testapp/cmd/soak`, private copy) through the real `net/http` server path (`iast/net/http/orchestrion.yml:16-45` serverHandler advice, `:81-122` handler fallback, `:50-75` StartSpanFromContext binding), root-executable SQL/exec sink bootstrap, propagation advice, `encoding/json`, `io.ReadAll`, and the lazy form/cookie/path sources. I read `internal/taint/request/scope.go`, `request/owner.go:1-110`, `store/owner.go:15-69`, `store/store.go:190-270`, `spans/annotation.go`, `spans/orchestrion.go`, `spans/owner.go`, `spans/tainted.go:120-320`, and `vulnerability/tainted.go`. Gauges came from two review-only read accessors added in the private copy (`evidence/life-soak/request_soak_export.go`, `spans_soak_export.go`).

## Soak curves (post-GC samples every 10k requests; full CSVs in `.omo/review/evidence/life-soak/`)
| Run | Requests | HeapAlloc min to max | Slope | HeapObjects first to last | Goroutines | Serial probe hits/200 |
|---|---|---|---|---|---|---|
| mocktracer, 50% sampling, 8 permits, 16 clients | 320k | 16.30 to 16.49 MB | 0.20 B/req | 10110 to 9914 | 6 (constant) | 90-112 (expected ~100) |
| real tracer, same config | 220k | 26.12 to 26.35 MB | 0.35 B/req | 14503 to 14592 | 15 (constant) | 90-120 |
| real tracer, product defaults (30%, 2 permits, dedup on) | 210k | 21.3 to 26.8 MB (noisy, no trend) | -5.2 B/req | 14619 to 14880 | 15 (constant) | 49-83 (expected ~60) |
| IAST disabled (same woven binary), baseline | 120k | 1.98 to 2.05 MB | 0.25 B/req | 9512 to 9593 | 6 | 0 |
| race detector, 50%/8 permits | 70k | 16.16 to 16.31 MB | (6 samples) | 9845 to 10088 | 6 | 90-112; 0 DATA RACE |

The residual +0.2 B/req slope with IAST on is the same as the +0.25 B/req slope with IAST off, so it is runtime/harness noise and not IAST retention. HeapAlloc also returns to its early values (for example 16.36 MB at 160k and at 320k). Every soak row across all IAST-on runs showed `permits_used=0`, `live_slots=0`, `store_values=0`, `store_charged=0`, `annotations=0`, `event_source_bytes=0`, `owner_bindings=0`, and `overflow_free=256`. Store tombstones stayed bounded (at most 4781) without growing. End-to-end reporting was live throughout: about 2,000-2,600 IAST JSON events and 1,800-2,400 handler-observed tainted SQL queries per 10k requests (mock run), with no downward trend.

## Findings
### life-soak-F1: Enabled-IAST steady-state footprint is ~14 MB live and ~31 MB peak HeapSys over baseline (bounded)
- Severity: Info
- Category: memory-bound
- Location: internal/taint/request/scope.go:47-59
- Claim: With the same woven binary and workload, post-GC HeapAlloc is ~2.0 MB with IAST off and ~16.4 MB with IAST on (mocktracer). That is +14.3 MB, allocated once when `defaultManager` initializes on the first sampled request and flat afterwards. Peak HeapSys plateaus at 53 MB off and 84.5 MB on, with transient garbage from evidence, payload, and stack capture. Both plateau, and the live figure is inside the documented 24 MiB fixed-plus-managed envelope. It is recorded as a measured datum for the envelope claim, not a defect.
- Evidence: .omo/review/evidence/life-soak/soak-mock.csv and soak-disabled.csv (columns heap_alloc, heap_sys). Commands are in README.txt. Key lines: `soak,320000,16361680,...` (on) vs `soak,120000,1993000,...` (off). heap_sys is 84.5 MiB vs 53.1 MiB.
- Fix: None required. Optionally record this measured number next to the plan's 22.6 MB claim.

### life-soak-F2: Soak run corroborates perf-contention-F1: owner-lock contention drops ~0.9% of sampled requests while permits are free
- Severity: Info
- Category: false-negative
- Location: internal/taint/store/owner.go:24-27
- Claim: `Store.Acquire` `TryLock` failures (`acquireDrops`) grew steadily: 1384 over 320k requests (~160k sampled) at 16 clients with 8 permits, 623 over 220k with the real tracer, and 33 over 210k at product defaults. Quiescent `permits_used` was always 0, so this is not a leaked slot and not growth in retained state. It is the silent contention drop already reported as perf-contention-F1. It is not re-rated here.
- Evidence: .omo/review/evidence/life-soak/soak-mock.csv column acquire_drops (38 to 1384, monotonic cumulative counter). Serial probe column stays at ~50%, which shows the drops need concurrency.
- Fix: See perf-contention-F1.

### life-soak-F3: No lifecycle soak or leak regression exists in the repository
- Severity: Low
- Category: test-gap
- Location: iast/integration/testapp/e2e_test.go:1
- Claim: The integration tests each drive a single request (`captureRequestEvent` starts a fresh mocktracer and server per test). No test runs many woven requests and then asserts that permits, store values and charges, annotations, event-source bytes, and owner bindings return to zero, or that heap and goroutines plateau. The bounds are proven only by per-package unit tests. A regression that leaks one permit per panicking handler or retains annotations would not be caught by CI. This soak found none today, but the harness lives only in review evidence.
- Evidence: .omo/review/evidence/life-soak/soak_main.go is a working woven harness (320k requests in ~41 s). Test inventory: in `iast/integration/testapp/*_test.go` the only loops are the two JSON `b.Loop` benchmarks in `e2e_test.go`. No test loops over requests.
- Fix: Add a short (for example 20k-request) woven integration test that runs the mixed workload, including panics, early returns, and late goroutines. After it, assert the quiescent gauges are zero, using test-only accessors, and assert that post-GC heap after the second half does not exceed the first half by more than a small tolerance.

## Checked and found correct
- Panicking handlers (20k, both `http.ErrAbortHandler` and string panics after a sink call) release the permit, store owner, annotation, and event-source charge. The deferred `httpbridge.Finish` runs on unwind (`iast/net/http/orchestrion.yml:29-33`), and the gauges are 0 after every batch.
- Early-returning handlers (POST body never read, no span; and `http.Error` with a span) leave no residue, and no body is eagerly consumed (no failures).
- Late goroutines (20k) that run a SQL sink 2 ms after their request finished neither leak, crash, nor race. `ReportTainted` returns early on a finished scope (`internal/vulnerability/tainted.go:45-47`).
- Orphan reporting (handler without a span): the orphan span is finished and deleted from the weak-key map (`vulnerability/tainted.go:69-74`), and `annotations` is 0 at every sample.
- Span annotation map: finished spans delete their entry (`spans/orchestrion.go:27-28`). With the real tracer (spans collected normally), the map never retained entries. `processEventSourceBytes` returns to 0, so the 2 MiB process budget never ratchets, and reporting did not decay over 220k requests.
- No gradual self-disable: a 200-request serial probe after each batch keeps hitting at the configured sampling rate (about 50% and about 30%) through the end of every run.
- Goroutine count is constant (6 with mocktracer, 15 with the real tracer) after closing idle connections. IAST starts no per-request or background goroutines.
- The race detector found no race in 70k mixed requests (`soak-race.race-count.txt` = 0).
- Store fixed tables: `overflow_free` is always 256, and tombstones stay bounded by compaction.

## Not covered / open questions
- Handlers that never return (streaming or stalled) were deliberately excluded. Their permit retention is life-admission-F1.
- Unfinished-but-retained spans (a customer leaks or holds spans, or nests request spans under a long-lived root). The annotation map is bounded by `config.MaxConcurrentRequests` with weak-key trimming (`spans/annotation.go:227-250`), but a live, never-finished root would pin one annotation and its event indefinitely. This was not soaked.
- Only HTTP/1.1 over loopback was exercised, not HTTP/2, h2c, or hijacked connections. Only Go 1.26.6 was used; Go 1.27 was not run.
- Wall-clock overhead was not measured (shared machine). Timing columns are informational only.
- Gauges are sampled at quiescence. In-flight peaks of store values and charges were not sampled.

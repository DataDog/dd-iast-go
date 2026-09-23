# fx-life-spans-F4: weak-crypto `Report` has no cheap gate (orphan span per call, no process dedup, capture before quota)

## Verdict per finding
- **life-spans-F4: CONFIRMED. Severity stays High.** A woven md5/sha1 call outside any span starts and finishes one `vulnerability` span per call, before the sampling decision. Sampled calls re-emit the same finding with a forced keep.
- **sink-vuln-report-F1: CONFIRMED. Severity stays High.** This is an exact duplicate of life-spans-F4 (same code, same claim). It observed about 30% sampled; I measured 287/1000 and 327/1000 at the default rate. `Report` never consults a process dedup set.
- **perf-allocs-matrix-F1: CONFIRMED. Severity stays High.** It is the in-span manifestation of the same root cause. Inside a sampled request, every call after the finding is recorded still pays UUID, stack capture and the model build: 28 allocs per call, against 0 with IAST disabled. The side claim of a telemetry log per dropped call holds only at Warn level for quota drops (event.go:57). Dedup drops log at Debug (event.go:62), so that part is minor.

All three share one root cause: `vulnerability.Report` runs its expensive stages before every cheap rejection, and it has no process-level dedup.

## Reproduction
My own woven reproducer runs through the real surface: woven `crypto/md5` and `crypto/sha1` hooks, a woven `net/http` server, and both mocktracer and a real tracer with a fake agent.
- Test: `.omo/review/evidence/fx-life-spans-F4/zz_fx_life_spans_f4_test.go`, copied into `benchmarks/overhead/` of a private copy at HEAD 2e23b46.
- Build: `cd benchmarks/overhead && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l go tool orchestrion go test -c -o fx.test .` (exit 0, peak RSS 426-466 MB).
- Run: `env <VARS> ./fx.test -test.run TestFx -test.v`.
- Output: `fx-woven-own.out.txt` and `fx-woven-realtracer.out.txt`.

Key lines. The background worker makes 500 md5.Sum and 500 sha1.Sum calls, from 2 call sites, with no span:
- Default settings (sampling 30): `finished spans=1000 names=map[vulnerability:1000]`, then `spans carrying _dd.iast.json=287, forced-keep (_sampling_priority_v1=2)=287, vulnerabilities=287, distinct type/hash=2`, then `finding WEAK_HASH/126497080 emitted 149 times`.
- `DD_IAST_REQUEST_SAMPLING=100`: 1000 spans, 1000 forced-keep, `emitted 500 times` for each of the 2 hashes.
- `DD_IAST_REQUEST_SAMPLING=0`: `finished spans=1000`, `_dd.iast.json=0`. Spans are still created even though nothing is ever reported.
- `DD_IAST_ENABLED=false` (control on the same binary): `finished spans=0`, `allocs ... 0.0`.

Allocations per `md5.Sum` outside a span:

| Tracer | sampling 0 | default | sampling 100 | disabled |
|---|---|---|---|---|
| mocktracer | 59 | 69 | 97 (91 with stacks off) | 0 |
| real tracer + fake agent | 29 | 41 | 68 | 0 |

The real-tracer benchmark numbers are indicative only on this shared machine: about 9.0 / 16.7 / 22.0 us per op, against 0.198 us per op disabled.

In-request case (perf-allocs-matrix-F1): one woven HTTP request makes 1002 `md5.Sum` calls from 2 sites. Output: `withPayload=1 vulnerabilities=2` (quota 2, one per site) and `later (already-recorded) calls avg over 1000=28.0` allocs. With stacks off it is still 28.0. At sampling 0 it is 1.0, and with IAST disabled 0.0.

These results agree with the finders' own reproducers: life-spans repro.out.txt (100 calls, 100 orphan spans, 59 allocs), and sink-vuln-report and perf-allocs-matrix, whose outputs are in their evidence directories. A previous lost attempt of this node left `repro-woven.out.txt` and `repro-internal.out.txt` in this evidence directory with matching numbers (200 calls, 200 spans, 200 findings). This report relies only on the two files named above.

## Reachability
- **Default configuration, supported toolchain: yes.** The root `orchestrion.tool.go` imports `iast/crypto/hash` and `iast/crypto/cipher`. Every hook passes a nil ctx (`iast/crypto/hash/orchestrion.yml:39,77,91,122,136`; `iast/crypto/cipher/orchestrion.yml:39-199`). Inside a woven request handler, the GLS span is found and no orphan is created. The finding covers any md5/sha1/DES/RC4 use outside a traced span: background workers, queue consumers without spans, startup and cache warm-up, `uuid.NewMD5`/`NewSHA1`, ETag and Content-MD5 helpers, and git or checksum libraries. This needs only a started tracer, which IAST requires anyway.
- **Documented limitation: no.** README:94-96 and 01-design-intent.md:118-121 document orphans only for *tainted* reports, and those are bounded per location by `taintedReportDedup` (tainted.go:25,83-104). Nothing documents a span per weak-crypto call, or trace retention forced by repeats of the same finding. Rule 2 (expensive work gated behind cheap checks) is broken. `ManualKeep` on every sampled orphan also overrides the customer's trace sampling, so trace volume and ingestion grow with md5 call frequency.
- **perf-allocs-matrix-F1** is reachable in any IAST-sampled request (30% by default) that calls a weak hash more than `VulnerabilitiesPerRequest` times, or repeatedly at one site.
- **Cross-tracer comparison:** dd-trace-java checks `overheadController.consumeQuota(REPORT_VULNERABILITY, span, type)` before reporting (SinkModuleBase.java:60-65,73-76).

## Adjusted severity
- life-spans-F4 is **High**. A hot-path cost of +29 to 68 allocs and about 9 to 22 us per md5 call replaces a cheap dedup check, and the same finding produces unbounded forced-keep traces.
- sink-vuln-report-F1 is **High**. It duplicates life-spans-F4 and has the same root cause.
- perf-allocs-matrix-F1 is **High**, the weakest of the three. The capture is ungated and its result is discarded (+28 allocs per call, a 50x+ slowdown on `md5.Sum`). It is limited to sampled requests and does not inflate trace volume. Medium would be defensible if the cost on sampled requests is accepted.

All three share one root cause. The first two are exact duplicates. The third is a second symptom of the same missing gate, and one fix covers it.

## Root cause (file:line, HEAD 2e23b46)
- `internal/vulnerability/report.go:45-49`: `tracer.SpanFromContext` fails for a nil ctx, so `spans.NewOrphanVulnerabilitySpan()` (`internal/spans/vulnerability.go:17-19`) runs, with `defer span.Finish()`, before the sampling check at `report.go:51-54`. The orphan's annotation (`AnnotationFor`, `annotation.go:133-142`) also takes a store slot until `Finished`.
- `report.go:60-95`: the UUID, the stack capture (full depth when stacks are on) and `model.NewVulnerability` all run before the quota and event dedup check at `report.go:97-105` (`model/event.go:51-66`).
- `report.go:30-109`: there is no `dedup.Set` use at all, unlike `ReportTainted` (`tainted.go:25,90-104`). Each orphan event holds one vulnerability, so event-local dedup never triggers, and `spans.Finished` sets `ManualKeep` on each one (`orchestrion.go:44-45,52`).

## Minimal fix
1. Compute the location hash first. Use the cheap depth-1 capture that already exists for stacks-off at `report.go:75-83`, since the hash is type plus location. Check a process `dedup.Set` for weak reports (a shared or separate `weakReportDedup`), and return on `CheckPresent` before creating any span or UUID. Call `Add` after a successful commit, mirroring `commitTainted`.
2. When no span exists, make the sampling decision before `tracer.StartSpan`. Create the orphan span, pre-paired with its annotation in the style of `NewOrphanTaintedSpan`, only after the call is sampled and passes dedup. Check `trimStore()` before `StartSpan`.
3. With a span, check under `ann.RLock()` whether the event is full or already holds the hash (a `WouldDrop(hash)` helper) before the full-depth stack capture and UUID. Capture the full stack only for a report that will be committed.

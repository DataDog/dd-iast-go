# sink-systemtests: system-tests IAST expectations mapped onto dd-iast-go
Verdict: The IAST tests that CI actually enables (weak hash, weak cipher, deduplication) should pass. When I emulated them in a woven harness, SQLi, CMDi, weak hash/cipher, and 11 of 13 source shapes produced events that satisfy the system-tests assertions and `vulnerability_schema.json`. The weak spots are coverage and metadata, not detection: CI never runs a SQLi, CMDi, or source test. Source telemetry is never emitted, so every source `test_telemetry_*` would fail. `http.request.uri` uses a different value format from the other tracers (TestURI would fail). A system-tests manifest edit also enables two weak-cipher classes on every Go weblog.

Mode: static mapping plus a targeted woven reproduction. I did **not** run system-tests itself. Docker is available, but its VM has 2 CPUs and 5.8 GiB of memory. A from-scratch woven `net-http-orchestrion` weblog build (with `orchestrion/all` contribs) needs a private-module token and does not fit the 25-minute, single-heavy-build budget. Instead, I copied the weblog's endpoint shapes into a non-test root-module package of `iast/integration/testapp` (private copy) and ran it woven: `go tool orchestrion go test` on go1.26.6, 65 s wall time, max RSS 368 MB. I captured the real `_dd.iast.json` event and the `_dd.stack` value for each request, then replayed the exact `tests/appsec/iast/utils.py` assertions in Python (`evidence/sink-systemtests/check_shapes.py`).

Scope covered: system-tests `romain.marcadier/dd-iast-go` @4dcd3b8 (the ref CI uses): `tests/appsec/iast/{utils.py,test_vulnerability_schema.py,vulnerability_schema.json}`, `sink/test_{sql_injection,command_injection,weak_hash,weak_cipher}.py`, `source/test_*.py` (body, cookie name/value, header name/value, parameter name/value, path, path parameter, uri, multipart), `manifests/golang.yml` (plus its diff against merge-base 3005271 and origin/main), `utils/_context/{containers.py,_scenarios/*}` (IAST env), `utils/interfaces/_library/core.py::assert_iast_implemented`, `utils/build/docker/golang/{net-http-orchestrion.Dockerfile,install_orchestrion.sh,app/net-http-orchestrion/*}`. In dd-iast-go @2e23b46: `.github/workflows/system-tests.yml`, `iast/crypto/{hash,cipher}/*`, `iast/database/sql/*`, `iast/net/http/orchestrion.yml`, `internal/taint/request/{http,lazy}.go`, `internal/vulnerability/{report,tainted}.go`, `internal/vulnerability/stacktrace/stacktrace.go`, `internal/spans/{annotation,orchestrion,payload,constants}.go`, `internal/model/*`, `internal/instrumentation/**`, `internal/config/config.go`. In dd-trace-go v2.11.0-rc.1: `internal/stacktrace`, `instrumentation.CaptureStackTrace/RecordStackTrace`, `SpanFromContext`, `SetMetaStruct`, and the known common metrics.

## Expected pass/fail per test (net-http-orchestrion; DEFAULT scenario env: sampling 100, dedup off, 10 vulns/request)
| Test | Manifest @4dcd3b8 | Prediction if the endpoint exists | Basis |
|---|---|---|---|
| TestWeakHash insecure/secure | enabled (v2.11.0-dev) | PASS: evidence `MD5`, location = handler file | harness + weblog main.go:125 |
| TestWeakHash telemetry instrumented/executed.sink | enabled | PASS (`vulnerability_type:WEAK_HASH`, common count) | annotation.go:298-319, knownmetrics |
| TestWeakHash_StackTrace / _ExtendedLocation | enabled | PASS: 8 frames, location matches a frame under the Go rule | harness |
| TestDeduplication (IAST_DEDUPLICATION) | enabled | PASS: 10x same line gives 1; md5+sha1 on 2 lines gives 2 (event-local hash of type+line+path) | model/event.go:48-58, vulnerability.go:24-49 |
| TestWeakCipher insecure/secure/telemetry | enabled | PASS (`RC4`; AES not reported) | harness |
| TestWeakCipher_StackTrace / _ExtendedLocation | **undeclared, so enabled for ALL Go weblogs** | PASS on net-http-orchestrion; FAIL on every other Go weblog (F4) | harness, manifest diff |
| TestSqlInjection insecure/secure | missing_feature, no endpoint | PASS (redacted literals, 2 sources) | harness |
| TestSqlInjection telemetry sink | missing_feature | PASS (`+= 11` instrumented, executed per call) | sql.go:36,54 |
| TestSqlInjection_StackTrace / _ExtendedLocation | missing_feature | PASS | harness |
| TestCommandInjection (all 3 classes) | missing_feature, no endpoint | PASS | harness |
| TestHeaderValue | missing_feature | PASS, but the source name is `Table` (F5) | harness |
| TestHeaderName | missing_feature | PASS, but name and value are `User` (F5) | harness |
| TestCookieName / TestCookieValue | missing_feature | PASS | harness |
| TestParameterName GET/POST | missing_feature | PASS | harness |
| TestParameterValue GET (FormValue or URL.Query) / POST | missing_feature | PASS (`http.request.parameter`) | harness |
| TestPath | missing_feature | PASS | harness |
| TestPathParameter | missing_feature | PASS (`r.PathValue`) | harness |
| TestURI | missing_feature | **FAIL**: value is `/iast/source/uri/test`, not an absolute URL (F3) | harness |
| TestRequestBody | missing_feature | PASS (source value = whole JSON body) | harness |
| TestMultipart (file part) | missing_feature | **FAIL**: file parts are not sources (documented) (F9) | harness, lazy.go:112 |
| All source `test_telemetry_metric_{instrumented,executed}_source` | missing_feature | **FAIL**: metrics never emitted (F2) | grep |
| TestIastVulnerabilitySchema | v0.0.0 | PASS, but vacuous for Go (F8); every harness event validated VALID | check_shapes.out.txt |

## Findings
### sink-systemtests-F1: system-tests CI never exercises taint tracking (SQLi, CMDi, sources)
- Severity: Medium
- Category: test-gap
- Location: .github/workflows/system-tests.yml:162-170; system-tests `manifests/golang.yml:127-129,177-179,223-238` and `app/net-http-orchestrion/main.go:106-151` @4dcd3b8
- Claim: The only IAST routes in the weblog are `/iast/insecure_hashing/*` and `/iast/insecure_cipher/*`. Every SQLi, CMDi, and source test is `missing_feature`, and the "Verify IAST tests executed" gate only requires weak hash, weak cipher, and deduplication. None of the branch's main functionality (HTTP sources, propagation, the SQL/exec sinks, redaction, and the meta_struct path through a real agent) is covered end-to-end by the cross-tracer suite. Regressions there would stay green.
- Evidence: evidence/sink-systemtests/weblog_iast_routes.txt (grep of routes and manifest entries). The harness shows these tests would pass if the endpoints existed (check_shapes.out.txt).
- Fix: Add `/iast/sqli/test_{insecure,secure}`, `/iast/cmdi/test_{insecure,secure}`, and `/iast/source/*` handlers to the net-http-orchestrion `main` package. They must live in the root module, not `_shared` (see F10). Enable those manifest entries for `net-http-orchestrion`, and add them to the workflow's expected-executed list.

### sink-systemtests-F2: `instrumented.source` / `executed.source` telemetry is never produced
- Severity: Medium
- Category: quality
- Location: internal/instrumentation/telemetry/telemetry.go:25,38; internal/spans/annotation.go:294-311
- Claim: `telemetry.InstrumentedSource` and the `ExecutedSource` counters are only iterated, never incremented. No `orchestrion.yml` or production `.go` file writes them. Every source class's `test_telemetry_metric_instrumented_source` and `_executed_source` would fail with "Got no series for metric". The `iast` source metrics are declared as common metrics in dd-trace-go, so the backend expects them.
- Evidence: evidence/sink-systemtests/telemetry_source_grep.txt. The grep over non-test `.go`/`.yml` files shows only the declarations and the heartbeat iteration.
- Fix: Increment `InstrumentedSource[origin]` from the net/http and net/url advice `init` blocks (like `InstrumentedSink`), and increment `ExecutedSource.<Origin>` when a source is published (`request/owner.go` source commit).

### sink-systemtests-F3: `http.request.uri` value is the origin-form RequestURI, not the absolute URL other tracers report
- Severity: Medium
- Category: provenance
- Location: internal/taint/request/http.go:70; iast/net/http/orchestrion.yml:42,116
- Claim: The URI source taints `r.RequestURI` (`/iast/source/uri/test`). TestURI expects `http://localhost:7777/iast/source/uri/test` for every language, which is the servlet `getRequestURL` convention. A Go weblog cannot fix this: `r.URL.String()` gets no taint at all, because it is rebuilt inside non-root `net/url`, and prefixing an untainted `r.Host` leaves the source value unchanged. The same origin name therefore carries different semantics across tracers.
- Evidence: evidence/sink-systemtests/shapes.json cases `source_uri_requesturi` (source `{"origin":"http.request.uri","value":"/iast/source/uri/test"}`) and `source_uri_urlstring` (no event). check_shapes.out.txt shows `TestURI (RequestURI) FAIL: value ... not in`.
- Fix: Decide on the contract. Either publish a scheme://host + RequestURI source (cloned root) for `http.request.uri`, or document the divergence and mark TestURI `irrelevant` for Go.

### sink-systemtests-F4: system-tests manifest edit enables TestWeakCipher_StackTrace/_ExtendedLocation on all Go weblogs
- Severity: Medium
- Category: ci
- Location: system-tests manifests/golang.yml:201-204 @4dcd3b8 (diff vs 3005271)
- Claim: The branch replaced three `missing_feature` lines with a `weblog_declaration` for `TestWeakCipher` only. `TestWeakCipher_StackTrace` and `TestWeakCipher_ExtendedLocation` now have no golang entry, so they are enabled for gin, echo, chi, net-http, and the others. Those weblogs have no `/iast/insecure_cipher` route and no IAST, so the tests will fail there. Weak hash was declared at file level and is not affected.
- Evidence: evidence/sink-systemtests/manifest_diff.txt. At 4dcd3b8 the only `test_weak_cipher` line is `::TestWeakCipher:`.
- Fix: Declare `tests/appsec/iast/sink/test_weak_cipher.py:` at file level, like weak hash, with `"*": missing_feature` and `net-http-orchestrion: v2.11.0-dev`.

### sink-systemtests-F5: header source names are canonical MIME names (`Table`, `User`)
- Severity: Low
- Category: provenance
- Location: internal/taint/request/http.go:126,136
- Claim: Go's canonicalized header keys become the source `name` (and, for header names, the `value`). The system-tests classes intend `table`/`user` but misspell the attribute as `source_name` instead of `source_names`, so names are not checked today. Fixing that typo, or backend correlation by name, would break Go.
- Evidence: shapes.json `source_header_value` gives `{"name":"Table","value":"user"}` and `source_header_name` gives `{"name":"User","value":"User"}`. check_shapes.out.txt shows the "intended name" rows FAIL.
- Fix: Emit lowercased header names, which matches the HTTP/2 wire form and the other tracers, or document the Go casing in the test.

### sink-systemtests-F6: location `class` for pointer receivers does not match the system-tests Go frame matcher
- Severity: Low
- Category: test-gap
- Location: internal/vulnerability/stacktrace/stacktrace.go:39-42 vs system-tests tests/appsec/iast/utils.py:282-297,368-377
- Claim: For `pkg.(*T).M`, dd-iast-go emits `class: "pkg.(*T)"`. The system-tests Go branch reconstructs `f"{ns}.{class_name}"` = `pkg.*T`, so StackTrace/ExtendedLocation would fail for any vulnerability located in a pointer-receiver method. The weblog's closures, and value receivers (`pkg.T`), match.
- Evidence: static reasoning only (NEEDS-REPRO). dd-trace-go `parseSymbol` returns Receiver `*T` (internal/stacktrace/stacktrace.go:158-172).
- Fix: Align one side. Either emit `pkg.*T`, or teach the system-tests matcher to wrap `*`-receivers in parentheses, mirroring dd-trace-go `Format`.

### sink-systemtests-F7: `instrumented.*` counts are resubmitted every heartbeat; `request.tainted` is always 0
- Severity: Low
- Category: quality
- Location: internal/spans/annotation.go:215-221,294-298
- Claim: Build-time totals (`InstrumentedSink`, `InstrumentedPropagation`) are submitted as `count` on every heartbeat, which inflates backend sums in proportion to uptime. `Annotation.RequestTainted` is never incremented (grep), so `request.tainted` always reports 0.
- Evidence: evidence/sink-systemtests/telemetry_source_grep.txt (the RequestTainted lines). The heartbeat code is static reasoning only.
- Fix: Submit the instrumented counts once (for example on the first heartbeat), and either wire `RequestTainted` at scope finish or drop the metric.

### sink-systemtests-F8: TestIastVulnerabilitySchema is vacuous for Go; the manifest comment is stale
- Severity: Low
- Category: test-gap
- Location: system-tests tests/appsec/iast/test_vulnerability_schema.py:16-19; manifests/golang.yml:241; internal/spans/orchestrion.go:41-54
- Claim: The test validates only `meta["_dd.iast.json"]`. dd-iast-go writes meta_struct `iast` whenever the agent supports it, so no Go event is schema-checked in CI. The line "Compliant because no IAST support" is no longer true.
- Evidence: check_shapes.out.txt. All 20 harness JSON events are VALID under Draft7, which covers the JSON fallback encoding only. The msgpack meta_struct form is not validated by CI.
- Fix: Extend the schema test to `meta_struct.iast`, and update the manifest comment.

### sink-systemtests-F9: TestMultipart (file upload, Java-style names) cannot pass
- Severity: Info
- Category: doc
- Location: internal/taint/request/lazy.go:110-129
- Claim: Multipart file parts are intentionally not sources, and the expected names `name`/`Content-Disposition` are servlet-part header semantics. Keep this one `missing_feature` or `irrelevant`.
- Evidence: shapes.json `source_multipart_file` produced no event.
- Fix: Mark it irrelevant for Go, or add a Go-specific variant with a value part.

### sink-systemtests-F10: propagation only in root-module non-test packages constrains weblog and test authoring
- Severity: Info
- Category: doc
- Location: iast/propagation/orchestrion.yml:15 (all operator aspects)
- Claim: The weblog `_shared/*` packages belong to module `systemtests.weblog`, which is not the root module. Concatenation there would not propagate, so SQLi/source endpoints must be written in `net-http-orchestrion/main.go`. Separately, in my first run a string concat inside a root-module external test file (`package testapp_test`) did not propagate. Direct sources did.
- Evidence: shapes.json `sqli_testfile_concat` produced no event, while `sqli_direct_nonconcat` and the same concat in the non-test `zz_systemtests_mux.go` both reported.
- Fix: Document both points in the README and the system-tests weblog notes.

### sink-systemtests-F11: CI depends on a mutable, unmerged system-tests branch
- Severity: Low
- Category: ci
- Location: .github/workflows/system-tests.yml:13,25,50
- Claim: The default `romain.marcadier/dd-iast-go` ref (last commit 2026-08-20) can drift or disappear, and its weblog `go.mod` pins stale dd-iast-go/orchestrion versions that `install_orchestrion.sh` has to override. Nightly and main runs are therefore not reproducible from a SHA.
- Evidence: static reasoning only.
- Fix: Pin a SHA, or land the system-tests PR and track `main`.

## Checked and found correct
- Origin strings (`internal/model/constants/origin.go`) and vulnerability type strings are exactly the schema enums. Every one of the 20 captured events validates against `vulnerability_schema.json`, including redacted source/evidence parts with `pattern`, `redacted`, and `source` indexes.
- The SQLi evidence format matches cross-tracer redaction: quoted literals from tainted parameters are replaced by `{pattern, redacted, source}` parts, and the sources carry `pattern`/`redacted` with no value. The CMDi evidence is `valueParts` on argv.
- Weak hash with `Report(nil ctx)` finds the request span through the Orchestrion GLS (`SpanFromContext` wraps the context under orchestrion). The event goes to the root span with evidence `MD5`. The location skips the `<generated>` md5 frame and points at the handler line. That satisfies the golang `_expected_location` form `/app/<variant>/main.go` given the Docker build path.
- The stack trace (`meta_struct._dd.stack.vulnerability`) has language `go` and 8 frames (≤32). `location.path/line/method` equals a frame under both Go matchers for closures and value receivers.
- The DEFAULT/IAST_DEDUPLICATION env vars (`DD_IAST_ENABLED`, `DD_IAST_REQUEST_SAMPLING=100`, `DD_IAST_MAX_CONCURRENT_REQUESTS=10`, `DD_IAST_DEDUPLICATION_ENABLED`, `DD_IAST_VULNERABILITIES_PER_REQUEST=10`) all map onto dd-iast-go config names. `_dd.iast.enabled` is set as a numeric tag, so it lands in metrics and `assert_iast_implemented` finds it.
- Sink telemetry: `instrumented.sink`/`executed.sink` carry `vulnerability_type:<TYPE>` (matched case-insensitively) and are common count metrics in dd-trace-go.
- Secure controls: parameterized SQL, a literal `ls` command, sha256, and AES produce no event.

## Not covered / open questions
- No real system-tests run: the agent/meta_struct msgpack path, the weblog Docker build (golang:1.26-alpine must be ≥1.26.6 with `GOTOOLCHAIN=local`), and heartbeat timing are unverified.
- Telemetry `common: true` and `len(points)==1` were checked against the dd-trace-go known-metrics list, not observed on the wire.
- Whether excluding root-module `_test.go` packages from operator weaving is intended Orchestrion behavior (F10) was not traced into orchestrion's package-filter code.
- Sources for `http.request.query`, gRPC, Kafka, GraphQL, and SQL rows have no Go weblog shape and were not mapped.

# Part "sink": sources, sinks, evidence, redaction, vulnerability reporting

Scope: iast/net/http, iast/database/sql, iast/os/exec, iast/encoding/json, internal/taint/evidence, internal/taint/redaction, internal/vulnerability, internal/model (plus the internal/taint/request code that these sources call, where it shares a root cause). HEAD 2e23b46.

**Counts after dedup: Critical 7, High 6 confirmed + 1 DISPUTED (life-admission-F1), Medium 15.** Every Critical and High entry cites its phase-3 `fx-*` verdict. The phase-3 adjusted severity is used throughout. Section 2b lists cross-part High root causes that this part's sinks surface; they are not counted here.

Status legend: CONFIRMED = phase-3 CONFIRMED; REFUTED = phase-3 REFUTED; DISPUTED = contradictory phase-3 verdicts; reviewer-reported = Medium or lower, with no phase-3 check. Evidence paths are relative to `.omo/review/`.

## 1. Part verdict

Detection is sound: the sink-e2e-truepos woven demo got all 39 supported SQLi/CMDi flows right (type, origin, name, exact ranges, file:line) on both channels, and the SQL, exec, and payload wrappers keep host results intact. The part is still not shippable. Three default-config redaction paths leak secrets (C1-C3). The HTTP source advice changes header aliasing and adds races to repeated form parsing (C4, C6). The JSON advice breaks every woven Go 1.27 build (C5). The report path can panic during init and does unbounded per-call work for weak crypto (C7, H3). Memory caps hold (64 vulnerabilities, 25,000 B payload, fixed dedup array, 256-range and 256 KiB evidence), except that evidence parts pin whole snapshots at 5.48x the 24 MiB ceiling (H5). Provenance has two confirmed High defects: tainted `Cmd.Path` is never inspected (H1), and query attribution uses `*url.URL` identity instead of content (H2).

## 2. Findings by root cause

### C1. SQL comment bodies are never redacted, so an injected `--` exposes later literals. Critical, CONFIRMED
- Location: internal/taint/redaction/sql.go:83-100 (`sqlSensitiveToken` has no COMMENT/MULTILINE_COMMENT case) and analyzer_test.go:30, which enshrines the behavior.
- Ids: sink-e2e-truepos-F1, sink-redaction-source-F3, crash-hostile-input-F1, crash-fuzz-redaction-F2. Verdicts: fx-sink-e2e-truepos-F1, covering sink-redaction-source-F3, and fx-crash-hostile-input-F1, both Critical.
- Mechanism: only string, number, boolean, and null tokens are sensitive. With payload `admin' --`, the application's trailing literals (`'app-secret-literal-7f3a' AND tenant = 42`) become comment text and ship verbatim; the input `alice` redacts them. A tainted secret in a comment (`SELECT 1 -- hunter2`) also leaves raw. dd-trace-java and the shared corpus redact comments.
- Repro: evidence/fx-sink-e2e-truepos-F1/woven-output.txt and unit-output.txt (`go test ./internal/taint/redaction -run TestFXCommentRedaction -v`). Woven e2e: evidence/fx-crash-hostile-input-F1/ (`cd iast/integration/testapp && go tool orchestrion go test -run TestFx -v .`).
- Fix: return the comment body interval (excluding `--`, `#`, `/*`, `*/`) for COMMENT and MULTILINE_COMMENT in every dialect, and return `AnalysisDropped` when a comment cannot be classified. Replace analyzer_test.go:30 with shared-corpus cases.

### C2. The context-free Oracle q-quote pre-pass desynchronizes all dialect lexers and leaks later literals. Critical, CONFIRMED
- Location: internal/taint/redaction/sql.go:27-43 (split per segment) and 108-156 (`scanOracleQuotes`).
- Ids: sink-redaction-sql-cmd-F1, crash-fuzz-redaction-F1. The fuzz-oracle blind spot, sink-redaction-sql-cmd-F2 and crash-fuzz-redaction-F3 (Medium, reviewer-reported), is folded in. Verdict: fx-crash-fuzz-redaction-F1 (Critical; it covers both).
- Mechanism: the pre-pass finds `q'` spans on raw bytes, even inside ordinary strings, deletes them, and lexes the segments per dialect, so later literals fall out of the sensitive intervals (source.go:66 redacts only overlapping sources). Under default config, the note `(urgent) call me back` in `INSERT ... VALUES ('Q','1','<note>','<email>')` sent both tainted sources raw. The fuzz oracle (fuzz_test.go:34-68) reuses `scanOracleQuotes`.
- Repro: evidence/fx-crash-fuzz-redaction-F1/woven_default_config.out.txt (`go tool orchestrion go test -run TestFx3 -v .` in iast/integration/testapp), unit_repro.out.txt, and evidence/sink-redaction-sql-cmd/malformed_oracle_quote.out.txt.
- Fix: recognize q-quotes only in code context (one stateful scan that skips strings and comments), in the Oracle pass only. Return `AnalysisDropped` on ambiguity. Make the fuzz oracle independent of the splitter.

### C3. The deterministic redaction pattern can equal the secret. Critical, CONFIRMED
- Location: internal/taint/redaction/source.go:110 (`alphanumericPattern(len(source.Value))`) and source.go:213-214,279-293 (evidence patterns use the same alphabet).
- Ids: sink-redaction-source-F1. Verdict: fx-sink-redaction-source-F1 (Critical).
- Mechanism: the pattern is a prefix or slice of a fixed `abcdef...` alphabet, and nothing compares it with the value. A password source whose value is `abc` serializes `"pattern":"abc","redacted":true` in both the source and the evidence part.
- Repro: evidence/fx-sink-redaction-source-F1/woven-e2e-pattern-leak.out.txt (`go tool orchestrion go test -run TestFXPasswordPatternLeakE2E -v .` in iast/integration/testapp) and evidence/sink-redaction-source/default-redaction-leaks.out.txt.
- Fix: use a mask that does not derive from content, such as `*` repeated to the retained length, for both source and evidence patterns.

### C4. Eager header rebuilding replaces `Request.Header`, which breaks caller-visible aliasing. Critical, CONFIRMED
- Location: iast/net/http/orchestrion.yml:109-118 (`req = req.WithContext(...)`, then `req.Header = iastrequest.EagerHTTP(...)`) and internal/taint/request/http.go:142-155.
- Ids: sink-http-sources-F1. Verdict: fx-sink-http-sources-F1 (Critical).
- Mechanism: the woven code assigns a new header map, so header mutations by the handler, or by a directly called helper, no longer reach aliases the caller holds; plain Go preserves them. Default config reaches this (rule 1).
- Repro: evidence/fx-sink-http-sources-F1/controls-go1.26.6.txt (plain vs woven `go test ./iast/net/http`) and evidence/sink-http-sources/review_alias.out.txt.
- Fix: keep the original map object and insert managed strings in place without changing its identity. Where aliasing cannot be preserved, drop header provenance.

### C5. Go 1.27 JSONv2: the Decoder advice references `dec.r`/`dec.d`, so every woven build fails. Critical, CONFIRMED
- Location: iast/encoding/json/orchestrion.yml:36-47 (line 41 uses `recv.r`, `&recv.d`); whole advice block 28-117.
- Ids: sink-json-sources-F1, base-test-127-F1, hooks-compile-matrix-F2, hooks-compile-matrix-F6. Verdicts: fx-sink-json-sources-F1 (Critical) and fx-base-test-127-F1 (Critical; covers F2 and F6).
- Mechanism: the default Go 1.27.0 JSONv2 `Decoder` has no `r` or `d` field. Woven `encoding/json` fails to compile, and so does every target in the dd-iast-go closure, even a main importing only `strings`. One JSON-free build hit 24,120,426,496 B max RSS and failed with `nats: maximum payload exceeded` (426 MB under `GOEXPERIMENT=nojsonv2`). The README limits JSON coverage to Go 1.26, but it does not permit build failure.
- Repro: evidence/fx-sink-json-sources-F1/woven-go127-output.txt (`GOTOOLCHAIN=go1.27.0 go -C <repro> tool orchestrion go build .`), evidence/fx-base-test-127-F1/json127-compiler.txt, and build127-default.txt.
- Fix: gate all legacy `encoding/json` advice off when JSONv2 is selected, and add a CI woven build on every supported toolchain.

### C6. The ParseForm/ParseMultipartForm advice writes request fields on every call, which races with form readers. Critical, CONFIRMED (contradiction noted)
- Location: iast/net/http/orchestrion.yml:152-162 and 177-186 (multipart), plus request/lazy.go:119-141 (element writes at :141).
- Ids: life-lazy-reader-F1, crash-race-hunt-F1. Verdicts: fx-life-lazy-reader-F1 (Critical) and fx-crash-race-hunt-F1 (High). **Contradiction:** fx-crash-race-hunt-F1 cut the narrower Form/PostForm reassignment to High because the same pointer is written back. fx-life-lazy-reader-F1 also covers element and `MultipartForm.Value` writes and keeps Critical under the brief's production data race rule. This entry uses Critical.
- Mechanism: in plain Go, a repeated parse is read-only. The woven code rewrites the maps and slice elements, so concurrent readers race, even for sampled-out requests. The values are identical, but customer `-race` runs fail.
- Repro: evidence/fx-life-lazy-reader-F1/repeated-parse-race-go1.26.6.out.txt and evidence/fx-crash-race-hunt-F1/woven_repro.out.
- Fix: record at entry whether the form was already parsed and skip management on a no-op re-parse. Assign only when `httpbridge.Form` changed something.

### C7. Weak-crypto hooks call `vulnerability.Report` during package init, before the tracer exists, and panic. Critical, CONFIRMED (primarily owned by crypto hooks)
- Location: internal/vulnerability/report.go:37-52, spans/vulnerability.go:18, and the go:linkname injection in iast/crypto/{hash,cipher}/orchestrion.yml.
- Ids: crash-panic-static-F1. Verdict: fx-crash-panic-static-F1 (Critical).
- Mechanism: woven hash and cipher bodies reach Report through linkname, without importing the tracer. When an application package calls md5, sha1, des, or rc4 in its own `init`, before tracer init, the nil global-tracer type assertion in `StartSpan` panics. IAST is enabled by default.
- Repro: evidence/fx-crash-panic-static-F1/initcrash2-default.out.txt (`go tool orchestrion go build -o initcrash2 . && ./initcrash2`).
- Fix: route crypto reports through a dependency-minimal `atomic.Pointer` callback bridge that iast/crypto registers in its own `init()`, as sqlbridge and commandbridge do.

### H1. A tainted `Cmd.Path` that differs from `Args[0]` runs without being inspected. High, CONFIRMED
- Location: iast/os/exec/orchestrion.yml:59-78 (line 71 forwards only argv) and iast/os/exec/exec.go:42-60.
- Ids: sink-exec-F1. Verdict: fx-sink-exec-F1 (High).
- Mechanism: `Cmd.Start` executes `lp := c.Path`, but evidence covers argv only. A tainted `cmd.Path` with a clean `Args[0]` ran an attacker-chosen binary with `FINDINGS=0` on 1.26.6 and 1.27.0, although the README claims every Start attempt is covered.
- Repro: evidence/fx-sink-exec-F1/fxf1_repro_test.go (`go tool orchestrion go test -run TestFxF1 -v .` in iast/os/exec/testapp).
- Fix: pass `{{ .Function.Receiver }}.Path` into Report and gate on `MayContain(path)`. When `path != argv[0]`, analyze `[]string{path, argv[1:]...}`.

### H2. URL-query attribution is keyed on `*url.URL` identity, not on the provenance of `RawQuery`. High, CONFIRMED (two symptoms)
- Location: internal/taint/request/lazy.go:28-46 (`ManageURLQuery`) and request/http.go:69-77.
- Ids: sink-http-sources-F2 (false positive), life-async-F1 (false negative), and store-binding-F1 (Low, same binding-by-address mechanism). Verdicts: fx-sink-http-sources-F2 (High), fx-life-async-F1 (High), and fx-store-binding-F1 (Low).
- Mechanism: `URL.Query()` results are tainted whenever the URL object is bound, whatever its content. After the handler sets `RawQuery` to a literal, `Query().Get` and `FormValue` return `created_at` tainted as `http.request.parameter`, a false SQLi source. Conversely, a copied URL (`http.StripPrefix`, `Request.Clone`) has no binding, so real query values come back clean.
- Repro: evidence/fx-sink-http-sources-F2/fx_f2_review.out.txt (`go tool orchestrion go test -run TestFxF2_ -v ./iast/net/http`) and evidence/fx-life-async-F1/run2-go1266.out.txt (`TestFxURLQueryBehindStdlibRouting` in iast/integration/testapp).
- Fix: attribute by the taint of `u.RawQuery` itself (a managed source clone with a single live owner) instead of URL-object binding. This fixes both symptoms.

### H3. Weak-crypto `Report` starts an orphan span on every call and has no process-level dedup. High, CONFIRMED
- Location: internal/vulnerability/report.go:41-58 (orphan span before the `ann.Sampled` check; no `dedup.Set`).
- Ids: sink-vuln-report-F1, life-spans-F4, perf-allocs-matrix-F1, and perf-allocs-matrix-F3 (Medium). Verdict: fx-life-spans-F4 (High; covers all three High ids).
- Mechanism: 1000 md5/sha1 calls outside a span produced 1000 vulnerability spans at every sampling rate. At 30%, 287 were force-kept while carrying only 2 distinct findings. Each call costs +41 allocs with the real tracer, versus 0 disabled, and 28 allocs inside a request even after the quota.
- Repro: evidence/fx-life-spans-F4/fx-woven-own.out.txt (`go tool orchestrion go test -c` in benchmarks/overhead) and evidence/sink-vuln-report/repro_external_test.go (`TestReproWeakHashOrphanPerCallNoProcessDedup`).
- Fix: compute a shallow location and hash first, check the process dedup set and sampling before creating any orphan span.

### H4. The tainted sink path does full evidence, lexing, redaction, and stack work before the dedup and quota checks. High, CONFIRMED
- Location: iast/database/sql/sql.go:34-49 and vulnerability/tainted.go:57-100 (`dedup.Check` only at :93; the quota only in `TryCommitTainted`).
- Ids: crash-hostile-input-F2, perf-memory-F1, sink-vuln-report-F7 (Low, orphan span before dedup), and sink-vuln-report-F8 (Low, full stack walked with traces off). Verdicts: fx-crash-hostile-input-F2 (High) and fx-perf-memory-F1 (High).
- Mechanism: the SQLi hash uses only type and location, yet every tainted query pays the full pipeline (about 18 KB per sampled tainted request). In one test, 40 tainted reports were fully processed but only 2 were committed at the default quota.
- Repro: evidence/fx-crash-hostile-input-F2/quota-repro.log and evidence/fx-perf-memory-F1/ (`dedupprobe`, woven vs plain).
- Fix: add a cheap "annotation full" flag, a shallow location capture, and `dedup.Check`/quota before CollectString and AnalyzeSQL in both sinks.

### H5. Short evidence parts pin full sink snapshots outside the memory budget. High, CONFIRMED
- Location: internal/taint/redaction/source.go:187-207, evidence/evidence.go:293-300, and spans/tainted.go:114-162.
- Ids: store-memory-bounds-F3. Verdict: fx-store-memory-bounds-F3 (High).
- Mechanism: evidence part strings are substrings of the collected snapshot, so a committed event keeps the whole backing array alive until the span finishes. At supported maximum limits, retention added 137,895,936 B HeapInuse, 5.48x the 24 MiB ceiling. This is not a documented retention.
- Repro: evidence/fx-store-memory-bounds-F3/01-independent-sql-retention.txt.
- Fix: clone the retained evidence substrings into compact owned storage and charge their real size against a process budget before commit.

### H6. The command-evidence collector rehashes the full source for every range. High, CONFIRMED
- Location: internal/taint/evidence/evidence.go:209-240,277-291.
- Ids: perf-algorithmic-F1. Verdict: fx-perf-algorithmic-F1 (High).
- Mechanism: 10 disjoint ranges from one 64 KiB HTTP source cost 10-19x the collection time of a single range. `sourceHash` accounts for 47.78% of CPU samples.
- Repro: evidence/fx-perf-algorithmic-F1/command-source-output.txt (`go test -bench BenchmarkReviewCommandRepeatedSource ./internal/taint/evidence`).
- Fix: carry a stable owner-local source id in `ResolvedRange` and cache index resolution for the duration of one collection.

### H7. Disconnected stalled handlers keep their admission slots until the handler returns. High, DISPUTED
- Location: iast/net/http/orchestrion.yml:27-33 (the deferred `Finish` is the only release) and request/scope.go:209-222.
- Ids: life-admission-F1, and res-digest-F1 (Low: long-lived streaming handlers hold one of the 2 default permits).
- Verdicts: fx-life-admission-F1.json currently says CONFIRMED High (HTTP/1 disconnect and HTTP/2 cancel repros). Per the coordinator, an earlier falsifier REFUTED it and the re-run overwrote the file; no trace of the refutation survives.
- Mechanism: nothing watches `req.Context().Done()`. Two stalled, disconnected handlers disable IAST for all later requests until they return. The host is unaffected.
- Repro: evidence/fx-life-admission-F1/zz_fx_life_admission_test.go and independent-repro-go1.27.0.log.
- Fix: release the analysis permit on context cancellation (`context.AfterFunc` with an idempotent finish), or document it. A third falsifier should settle the severity.

### Medium entries

| # | Title | Location | Ids | Status | Evidence | Minimal fix |
|---|---|---|---|---|---|---|
| M1 | Name-sensitive source keeps its full name on the wire | redaction/source.go:107-115; model/source.go:33-40 | sink-redaction-source-F2 | CONFIRMED, Critical to Medium (fx-sink-redaction-source-F2) | evidence/fx-sink-redaction-source-F2/woven-run.out.txt | Mask or omit `model.Source.Name` when the name triggered redaction. |
| M2 | Joined command evidence keeps only 4 owner identities, so a 5th owner's bound span gets an orphan report | evidence/evidence.go:339,404-413; vulnerability/tainted.go:110-125 | sink-evidence-F1 | CONFIRMED, High to Medium, not reachable by default (fx-sink-evidence-F1) | evidence/fx-sink-evidence-F1/zz_fx_verify_owner_fanout_test.go | Use a joined-collection owner bound separate from `MaxSnapshotOwners`, or fail collection explicitly. |
| M3 | A tainted part starting past the 250-char truncation serializes with no required `value` | redaction/source.go:188-208 | sink-parity-F1 | CONFIRMED, High to Medium (fx-sink-parity-F1) | evidence/fx-sink-parity-F1/independent_boundary.out.txt | Do not emit a zero-length tainted part at the boundary. Mark the last kept part truncated instead. |
| M4 | Unsalted evidence source index allows offline-crafted collisions (32,640 probes; about 2x cost) | evidence/evidence.go:240-277 | perf-algorithmic-F2 | CONFIRMED, High to Medium (fx-perf-algorithmic-F2) | evidence/fx-perf-algorithmic-F2/review_collision_independent_test.go | Use a `hash/maphash` process seed. Keep the 512 slots. |
| M5 | Dedup hash is type plus location only, and location is unreliable: location-less findings collide for 1h; a deferred SQL report during a panic is located at `runtime/panic.go`; ORM frames are not skipped | vulnerability/report.go:155-158; iast/database/sql/orchestrion.yml:54-117; iast/database/sql/sql.go:20-30 | sink-vuln-report-F2, F3, F4 (F4 NEEDS-REPRO) | reviewer-reported | evidence/sink-vuln-report/repro_internal_test.go (`TestReproLocationlessHashCollision`), repro_external_test.go (`TestReproDeferredSinkPanicLocation`) | Skip dedup for path-less locations. Add `runtime` to `sqlSkip`. Skip known ORM and driver-wrapper frames when a customer frame exists. |
| M6 | Hash and reported location include the absolute build path, so it changes per build dir | model/vulnerability.go:36-41 | sink-vuln-report-F5 | reviewer-reported | evidence/sink-vuln-report/repro-output.txt | Hash and report a module-relative path. |
| M7 | `ReportTainted` context-scope veto: a finished or detached-context scope vetoes a live request's taint | vulnerability/tainted.go:45-47; request/scope.go:79-104 | life-async-F2, life-async-F3 | reviewer-reported | none (static and life-async report) | Treat a finished or foreign context scope as missing and continue with owner-based selection. |
| M8 | Deferred ParseForm advice can replace a host panic with an IAST callback panic | iast/net/http/orchestrion.yml:131-158 | hooks-panic-safety-F3 | CONFIRMED, Critical to Medium, not reachable by default (fx-hooks-panic-safety-F3) | evidence/fx-hooks-panic-safety-F3/independent_deferred_panic_test.go | Recover inside the deferred advice when a panic is already unwinding. |
| M9 | Query and header caps are all-or-nothing: more than 48 query or 32 header names removes all taint (evasion) | request/lazy.go:163-173; request/http.go:97-106 | perf-memory-F4 | reviewer-reported | evidence/perf-memory/results.jsonl | Taint the first N in deterministic order and count the rest, or document the cap. |
| M10 | Windows `SysProcAttr.CmdLine` replaces argv but is never inspected | iast/os/exec/orchestrion.yml:59-78 | sink-exec-F2 | reviewer-reported, NEEDS-REPRO | none | Add a Windows-only helper that collects from `CmdLine`, or document the gap. |
| M11 | system-tests CI never exercises SQLi, CMDi, or sources; the schema test validates only `_dd.iast.json`, while Go normally emits meta_struct | .github/workflows/system-tests.yml:162-170; system-tests test_vulnerability_schema.py:13-21 | sink-systemtests-F1, sink-parity-F2, sink-systemtests-F8 (Low) | reviewer-reported | evidence/sink-systemtests/weblog_iast_routes.txt | Add root-module weblog routes and enable the manifests. Validate `meta_struct.iast`. |
| M12 | Checked-in suites miss risky paths (non-context SQL calls, `driver.Valuer`, exec Path/nil Args, contrib spans, msgpack meta_struct), and "Active" benchmarks only hit the clean path | iast/database/sql/testapp/sql_test.go:63-100; iast/os/exec/testapp/exec_test.go; iast/integration/testapp/request_event_test.go:22-50; iast/*/..._test.go benchmarks | sink-sql-F1, sink-exec-F3 (Low), sink-e2e-truepos-F4 (Low), perf-bench-quality-F1 | reviewer-reported | evidence/sink-sql/review-sql-output.txt, evidence/sink-exec/review_sinkexec_test.go, evidence/perf-bench-quality/sql-report-tainted-vs-clean.out.txt | Promote the private reviewer tests and harness into the repository, and add tainted-hit benchmarks. |
| M13 | `instrumented.source` and `executed.source` telemetry are never incremented | internal/instrumentation/telemetry/telemetry.go:25,38 | sink-systemtests-F2 | reviewer-reported | evidence/sink-systemtests/telemetry_source_grep.txt | Increment them from the net/http and net/url advice `init` blocks and at source publish. |
| M14 | `http.request.uri` value is the origin-form `RequestURI`, but every other language uses an absolute URL | request/http.go:70 | sink-systemtests-F3 | reviewer-reported | evidence/sink-systemtests/shapes.json | Publish scheme://host+RequestURI, or mark TestURI irrelevant for Go. |
| M15 | system-tests manifest enables `TestWeakCipher_StackTrace/_ExtendedLocation` for all Go weblogs | system-tests manifests/golang.yml:201-204 @4dcd3b8 | sink-systemtests-F4 | reviewer-reported | evidence/sink-systemtests/manifest_diff.txt | Declare the file at file level with `"*": missing_feature`. |

### 2b. Cross-part High root causes seen through these sinks (not counted)
- Coarse fmt attribution ignores whether the tainted argument emitted bytes. sink-e2e-truepos-F2 (`%T`, Medium locally) shares this root cause with prop-semantics-parity-F2, CONFIRMED High (fx-prop-semantics-parity-F2). The Stringer variants (prop-string-coarse-F1, crash-diff-strings-F1) are also CONFIRMED High. Location: propagation/string_coarse.go:115-145. Owned by prop.
- Byte roots are keyed by (ptr, len) with no content check. sink-e2e-truepos-F3 (a clean `copy` over an `io.ReadAll` body still reports SQLi, Medium locally) shares this root cause with life-cross-request-F1, CONFIRMED High and documented (fx-life-cross-request-F1). Location: request/reader.go:67-125. Owned by life.
- Annotation-slot starvation drops reports at vulnerability/tainted.go:62-68: crash-stress-app-F1, life-spans-F1, and life-weak-gc-F1, all CONFIRMED High, rooted in spans/annotation.go.
- prop-owner-isolation-F1 (CONFIRMED Critical race: request/owner.go:82 writes, request/http.go:33 reads). hooks-scope-root-F1 (CONFIRMED Critical, located at iast/database/sql/orchestrion.yml:16-31, but the root cause is Orchestrion OnLink).

## 3. Low / Info and code quality
- Low: sink-systemtests-F5 (header source names are canonical MIME, not lowercase), sink-systemtests-F6 (NEEDS-REPRO: class `pkg.(*T)` vs the matcher's `pkg.*T`), sink-systemtests-F7 (instrumented counts resent every heartbeat; `request.tainted` always 0), sink-systemtests-F11 (CI tracks a mutable system-tests branch).
- Low: sink-vuln-report-F6 (raw structs through `slog.Any` at report.go:102-103; `%#v` at event.go:109), crash-hostile-input-F3 (spans/tainted.go:264 sizes the pattern by bytes, 3-4x the 250-rune truncation), crash-panic-static-F2 (`vulnerability.Report` has no panic boundary).
- Low: life-spans-F7 (a negative annotation short-circuits owner fallback, tainted.go:111-114), life-async-F4 (reports between root finish and owner finish become orphans), crash-fuzz-redaction-F4 and F5 (weak fuzz oracles), crash-race-hunt-F3 (flaky TestCommitTaintedSkippedDedup), light-model-F1 (fixture names a nonexistent source), perf-bench-quality-F5 (missing ReportAllocs).
- Info: sink-exec-F4 and F5 (argv joined without boundaries; tainted argv[0] in clear, as in Java), sink-e2e-truepos-F5 (fmt queries mark the whole template), sink-systemtests-F9 and F10, life-bridges-F4 (sink callbacks only in woven root-main executables), prop-owner-isolation-F4 and life-cross-request-F5 (context-less sinks attribute to a foreign owner's span), base-bootstrap-F1 (+20 MB binaries).
- Info: sink-e2e-truepos-F6 (6 of 32 burst requests unanalyzed) matches perf-contention-F1, which phase 3 REFUTED as a defect (fx-perf-contention-F1, Info).

## 4. Verified correct
- sink-e2e-truepos: 39 supported flows correct on both channels (exact ranges, file:line); 16 of 17 clean controls silent; name/value patterns, literal masking, argv[0]-only command evidence, and the unterminated-`/*` fallback work.
- sink-sql: every DB/Conn/Tx/Stmt entry point reaches the instrumented bodies; results and errors survive retry, panic, and cancel; `driver.Valuer` is not evidence; secure marks suppress collection; passes on 1.26.6 and 1.27.0.
- sink-exec: one report per Start attempt, none on validation failure or a pre-canceled context; Start-twice, evaluation order, and results preserved; LookPath and owner fallback work; callback panic recovered.
- sink-evidence: `matchesJoin` bounds, full-tuple source identity, 256-range and 256 KiB drop, `PartValue` bounds, at most 513 parts, rune-safe truncation, 32 KiB analysis cap.
- sink-redaction-*: argv offsets cannot overflow; lexer errors rejected; a 30 s FuzzAnalyzeSQL run found no panic; non-OK analysis and part-cap overflow give full redaction; bad regexps fall back to defaults (RE2).
- sink-payload-model: JSON and msgpack share one model; `BuildLimitedPayload` re-encodes and never slices; every output is at most 25,000 B, including 64 vulnerabilities; `go generate` produced no diff.
- sink-vuln-report: `dedup.Set` is a fixed `[1000]int32`, TryLock-only and race-clean; the commit is transactional; lock order is annotation then span; the recapture loop is bounded at 8.
- sink-parity, sink-systemtests: origin and type strings match the schema and the other tracers; all 20 harness events validate; weak-hash location and stack meet the matchers.
- sink-http-sources, sink-json-sources: nil URL guarded; no eager form or body read; parse errors preserved; origins correct; JSON advice skips decode errors and custom unmarshalers.
- evidence/bench/micro-benchstat.txt: sql and exec `ReportActiveClean` take 6-11 ns with 0 allocs.

## 5. Coverage gaps
- There is no woven end-to-end sink run on Go 1.27, because C5 blocks it.
- The e2e runs forced 100% sampling, so the defaults (30% sampling, concurrency 2) were not exercised end to end.
- No real database driver or Datadog agent/backend was used. Backend meta_struct acceptance, the impact of M3, and the impact of M6 are unverified.
- There were no gin, echo, chi, gRPC, or ORM fixtures (M5's ORM claim is unproven), no woven run of the deferred-panic location (M5), and no Windows run (M10).
- Direct `os.StartProcess`/`syscall.Exec` sinks are documented as out of scope. The gRPC, Kafka, and SQL-row sources are unmapped.
- Not measured: header and URL management cost, JSON decoder-slot saturation, a JSONv2 design, and admin regexp size.
- The life-admission-F1 REFUTED reasoning is missing from the artifacts.

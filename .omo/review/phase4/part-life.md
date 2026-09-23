# Part "life": request/owner/span lifecycle and bridges

Scope: `internal/taint/request`, `internal/spans`, `internal/taint/*bridge`, `taint/`, and the `iast/net/http` advice that drives them. HEAD 2e23b46.

**Counts after dedup: 5 Critical, 14 High (1 of them DISPUTED), 15 Medium.** Low/Info items are listed as bullets. Every Critical and High entry cites its phase-3 `fx-*` verdict. Two Critical entries (C3, C5) and several contributing ids belong mainly to other parts. They are listed here because their root cause sits in this part's code.

## 1. Part verdict

Not ready for customers. **Crash-safety:** no natural panic was found in the lifecycle code, and host panics survive deferred bridge calls. But four production data races or host-behavior changes were reproduced: form re-parse writes, `SetMetaStruct` after a double Finish, the `slot.index` write, and header-map replacement. Separately, weak-crypto hooks can kill the process during init. Five of nine bridges are unshielded (phase 3 rated this defense-in-depth). **Memory:** the soak found no leak over roughly 800k requests. But the annotation cap is a TOCTOU (5.5x at defaults, unbounded when forced), and weak-hash calls outside a span emit one trace span each. **Provenance** is the weakest area. It is correct after Finish, but not while requests overlap. Sampled-out requests starve admitted ones of annotation slots. Late child spans resurrect annotations whose findings are lost. A retained finished context disables analysis. URL-query attribution by `*url.URL` identity gives both false negatives and false positives. Recycled memory (pooled `io.ReadAll` slices, pooled `bytes.NewBuffer`, `Builder` after GC) moves request A's source onto request B's span. The JSON slot table loses taint under ordinary concurrency.

## 2. Findings by root cause

### Critical

**C1. Woven `ParseForm`/`ParseMultipartForm` advice writes request form state on re-parse (data race)**
- Severity: **Critical** per fx-life-lazy-reader-F1. **Conflict:** fx-crash-race-hunt-F1 downgraded the same mechanism to **High**, because the store writes an identical value. This report keeps the higher rating, since the brief classifies a data race in production code as Critical.
- Status: CONFIRMED (both).
- Location: `internal/taint/request/lazy.go:141` (`copy(target[start:], managed)`), `iast/net/http/orchestrion.yml:152-162,179-186`.
- Ids: life-lazy-reader-F1, crash-race-hunt-F1.
- Mechanism: in plain Go, a repeated parse only reads. The woven deferred closure instead reassigns `r.Form`/`r.PostForm`/`MultipartForm.Value` on every call, and `replaceMatchingSuffix` rewrites slice elements. Goroutines reading the form concurrently therefore race. The race reproduces with IAST sampled out, and also with `config.Enabled=false`. The written values are identical, so results do not change, but customer `-race` runs fail.
- Repro: `evidence/fx-life-lazy-reader-F1/repeated-parse-race-go1.26.6.out.txt` (`go tool orchestrion go test -race -run '^TestFxRepeatedParse$' ./iast/net/http`). Also `evidence/fx-crash-race-hunt-F1/woven_repro.out`.
- Fix: snapshot on entry whether the form was already parsed (`Form != nil` / `MultipartForm != nil`), and skip all management when it was. Assign fields only when the bridge returns a changed map.

**C2. Double `Finish()` on a root with a resurrected annotation calls `SetMetaStruct` on a finished span**
- Severity: **Critical**. Status: CONFIRMED (fx-life-spans-F2.json, entry life-spans-F3).
- Location: `internal/spans/orchestrion.go:27-46` (L44 `span.SetMetaStruct`).
- Ids: life-spans-F3.
- Mechanism: `Finished` runs on every `Span.Finish`. After H2 re-creates a sampled annotation under a finished root, a second `Finish()` (supported by dd-trace-go) builds a payload and calls `SetMetaStruct`/`SetTag` on a span the writer is already encoding without the span lock. The result is a race on `span.metaStruct` (a concurrent map write and iteration, which can be fatal) and on `Event`. Phase 3 observed 30 DATA RACE reports with a real tracer and an agent that advertises meta_struct. Both controls were race-free (double Finish without a late bind, and a late bind with a single Finish).
- Repro: `evidence/fx-life-spans-F2/rerun.out.txt`, `zz_fx_life_spans_f2_test.go` (`-run '^TestFxDoubleFinishRace$'` in `iast/integration/testapp`).
- Fix: `Finished` returns immediately when the loaded entry is already closed. Fix H2 with a closed tombstone.

**C3. Eager header tainting replaces the caller-visible `Header` map and value slices**
- Severity: **Critical**. Status: CONFIRMED (fx-sink-http-sources-F1). Primary owner: the sink part.
- Location: `internal/taint/request/http.go:142-155`, `iast/net/http/orchestrion.yml:109-119`.
- Ids: sink-http-sources-F1.
- Mechanism: `EagerHTTP` rebuilds `r.Header` with managed strings after `WithContext` clones the request. Handler header mutations therefore no longer reach aliases held by the caller. Plain Go preserves those mutations. Calling the helper directly fails too.
- Repro: `evidence/fx-sink-http-sources-F1/controls-go1.26.6.txt`.
- Fix: do not replace caller-owned maps or slices at fallback entry. Drop eager header provenance where exclusive ownership cannot be proven, and restore coverage through source-extraction hooks that return managed strings.

**C4. `analysisSlot.index` is written on every `Acquire` and read without synchronization**
- Severity: **Critical** (phase 3 calls it "the least severe Critical": `-race` builds only, never a wrong result). Status: CONFIRMED (fx-prop-owner-isolation-F1).
- Location: `internal/taint/request/owner.go:82` (write) vs `internal/taint/request/http.go:33` (read in `analysisForOwner`).
- Ids: prop-owner-isolation-F1.
- Mechanism: a detached goroutine calls `r.URL.Query()` or `io.ReadAll` while its request finishes and another request re-acquires the permit. That is a plain write racing a plain read.
- Repro: `evidence/fx-prop-owner-isolation-F1/woven-detached-query-race-go1.26.6.out.txt`.
- Fix: initialize `index` once in `NewManager` (verified by phase 3 under `-race`).

**C5. Weak-crypto hooks crash the process when md5/sha1/des/rc4 run during package init**
- Severity: **Critical**. Status: CONFIRMED (fx-crash-panic-static-F1). Primary owner: the crash/hooks part. Listed here because the crash is in the spans orphan-span path it shares with H6.
- Location: `internal/vulnerability/report.go:37-52`, `internal/spans/vulnerability.go:18`.
- Ids: crash-panic-static-F1.
- Mechanism: linkname-injected crypto hooks call `vulnerability.Report` before the tracer and `internal/spans` have initialized. `tracer.StartSpan`'s nil-global-tracer type assertion then panics with no recover, and the process exits 2 before `main`. Default config triggers it.
- Repro: `evidence/fx-crash-panic-static-F1/initcrash2-default.out.txt`.
- Fix: add a per-package `ready atomic.Bool`, set at the end of `init()` and checked first in `ReportWeakHash`/`ReportWeakCipher`. Add a recover shield like the SQL/command bridges have.

### High

**H1. Disconnected but stalled handlers keep their admission permit**
- Severity: **High, DISPUTED**. One falsifier REFUTED it, and a re-run CONFIRMED it High and overwrote the file. Only the CONFIRMED verdict survives in `phase3/fx-life-admission-F1.json`/`.md`, so the REFUTED reasoning is not available in the artifacts.
- Location: `iast/net/http/orchestrion.yml:27-33` (the only release is the deferred `iasthttpbridge.Finish`), `internal/taint/request/scope.go:79-104,209-222`.
- Ids: life-admission-F1.
- Mechanism: nothing watches `ctx.Done()`. A handler that is still blocked after an HTTP/1 disconnect or an HTTP/2 cancel keeps its permit. At the default limit of 2, two such handlers capacity-drop every later request until they return. The surviving fx notes the slot does come back when the handler returns and the host is unaffected. So "permanent" holds only while the handlers stay stalled.
- Repro: `evidence/fx-life-admission-F1/zz_fx_life_admission_test.go`, `fx_repro_go1.26.6.out.txt` (`-run TestFxDisconnectSlotRetention ./iast/net/http`). Finder: `evidence/life-admission/disconnect.out.txt`.
- Fix: release the analysis (not the scope object) on request-context cancellation, for example via `context.AfterFunc`, keeping it idempotent with `Scope.Finish`. Alternatively, document the handler-lifetime semantics and resolve the dispute.

**H2. Sampled-out requests fill the 2-slot annotation store, and admitted requests lose all findings**
- Severity: **High**. Status: CONFIRMED (fx-life-spans-F1, fx-life-weak-gc-F1, fx-crash-stress-app-F1).
- Location: `internal/spans/annotation.go:198-212` (stores `Sampled: active` for negative decisions), `annotation.go:227-236`.
- Ids: life-spans-F1, life-weak-gc-F1, crash-stress-app-F1.
- Mechanism: since 87ecf02, `BindScope` stores negative decisions in a map capped at `MaxConcurrentRequests` (default 2), the same number as analysis permits. At the default 30% sampling, 70% of requests take slots. A permit-holding request then gets `_dd.iast.enabled=0` and no owner binding. `NewOrphanTaintedSpan` finds no slot either, so it emits an empty orphan span and drops the finding. Weak findings drop via `nonSampledAnnotation`. Measured: 0/10 victims reported with 2 held sampled-out requests, 0/90 under load against an 89/89 control, and 30-70% loss at 3-16 in-flight requests.
- Repro: `evidence/fx-crash-stress-app-F1/annrepro_deterministic.out`, `evidence/fx-life-spans-F1/repro_combined.out.txt`, `evidence/fx-life-weak-gc-F1/review_independent_starvation_test.go`.
- Fix: do not count negative decisions against the active bound. Give them the shared `nonSampledAnnotation` sentinel or a separate cache, which also removes M9's 3.2-3.5 KB allocation. In `NewOrphanTaintedSpan`, check capacity before `tracer.StartSpan`.

**H3. A bind after root `Finish` resurrects an open annotation that is never flushed**
- Severity: **High**. Status: CONFIRMED (fx-life-spans-F2, fx-life-weak-gc-F2, fx-crash-unsafe-F1).
- Location: `internal/spans/orchestrion.go:28` (`LoadAndDelete`, no tombstone), `internal/spans/annotation.go:190-205`.
- Ids: life-spans-F2, life-weak-gc-F2, crash-unsafe-F1.
- Mechanism: a child span started from a finished root's context (woven `BindStartSpan` → `BindScope`) runs `LoadOrCompute` again on the root key. A tainted SQLi then commits into the new annotation (and its hash enters the one-hour dedup set), but 0 vulnerabilities are emitted. The entry also holds a slot and its source-byte charge until GC plus a trim, and two stale entries deny a later active request. Phase 3 refuted the weak-crypto nil-context trigger in the original claim; the child-span trigger is reachable. This entry is the precondition for C2 and H5.
- Repro: `evidence/fx-life-spans-F2/rerun.out.txt` (`-run '^TestFxLateBindAfterRootFinish$'`), `evidence/fx-life-weak-gc-F2/`, `evidence/fx-crash-unsafe-F1/`.
- Fix: replace the entry with a closed tombstone that is excluded from the capacity count and reaped when the weak key dies. `BindScope`/`AnnotationFor` treat a closed entry as absent, so callers fall back to the orphan path. H5's ID check is still required.

**H4. The annotation-store capacity check is not atomic with insertion**
- Severity: **High** (store-memory-bounds-F2 was Critical and phase 3 downgraded it, because the excess tracks live roots and disappears at Finish). Status: CONFIRMED (fx-store-memory-bounds-F2).
- Location: `internal/spans/annotation.go:131-143,198-205,227-236`.
- Ids: store-memory-bounds-F2, life-spans-F5, crash-unsafe-F2.
- Mechanism: `trimStore()`'s `Size()` check runs before `LoadOrCompute`, so concurrent first binds of distinct roots all insert. Measured 7 and 11 entries against a cap of 2 (5.5x) with no patch, and 2048 against 64 with a scheduling barrier. The excess has no code-imposed bound. **Conflict:** life-spans-F5 called it Medium ("bounded by concurrency, self-corrects"). The phase-3 High rating governs.
- Repro: `evidence/fx-store-memory-bounds-F2/01-noPatch-admission.txt`, `evidence/life-spans/toctou.out.txt`.
- Fix: reserve with an atomic live-entry counter before insertion, give the slot back if another caller won the key, and decrement in `Finished` and `releaseDeadAnnotation`.

**H5. With dd-trace-go's span pool, a recycled root inherits another trace's annotation**
- Severity: **High** (`reachable_default: false`; needs the opt-in `WithSpanPool`/`DD_TRACER_EXPERIMENTAL_SPAN_POOL_ENABLED`). Status: CONFIRMED (fx-life-weak-gc-F3).
- Location: `internal/spans/annotation.go:190-197`.
- Ids: life-weak-gc-F3.
- Mechanism: the key is only `weak.Pointer[tracer.Span]`. A stale entry left by H3 on a pooled span object is inherited by the next request. The agent then received request A's SQLi on request B's span, or B's own finding was dropped.
- Repro: `evidence/fx-life-weak-gc-F3/review_f3_pool_test.go` (`-run TestReviewF3WovenSpanPool`).
- Fix: record the root span ID in the annotation and compare it on every load, deleting the entry on a mismatch. Phase 3 warns that an H3 tombstone without this check makes pool mode worse.

**H6. Weak-crypto reports outside a span create and finish one orphan trace span per call before sampling or dedup**
- Severity: **High**. Status: CONFIRMED (fx-life-spans-F4, covering life-spans-F4, sink-vuln-report-F1 and perf-allocs-matrix-F1).
- Location: `internal/vulnerability/report.go:44-54`, `internal/spans/vulnerability.go:17-19`.
- Ids: life-spans-F4, sink-vuln-report-F1, perf-allocs-matrix-F1, perf-allocs-matrix-F3 (Medium, same site).
- Mechanism: 1000 md5/sha1 calls produced 1000 spans at every sampling rate, including 0. At the default rate, 287 spans were ManualKeep with only 2 distinct findings. The real tracer adds 41 allocs/call against 0 with IAST disabled. Report has no process-level dedup. Inside a sampled request, already-recorded calls still cost 28 allocs each.
- Repro: `evidence/fx-life-spans-F4/fx-woven-own.out.txt`.
- Fix: decide sampling, dedup and quota before building the model or starting a span. Do not start orphan spans for weak reports without a context. This also mitigates C5.

**H7. A retained finished context silently disables analysis for later requests**
- Severity: **High**. Status: CONFIRMED (fx-life-owner-scope-F1).
- Location: `internal/taint/request/scope.go:83-84`.
- Ids: life-owner-scope-F1.
- Mechanism: `begin` reuses any scope found in the context without a liveness check. Re-dispatching a stored `*http.Request` (or reusing a parent context that holds a finished scope) returns `created=false` and an inactive analysis. The woven advice gates `EagerHTTP` on `created`, so no source is ever tainted, despite free capacity.
- Repro: `evidence/fx-life-owner-scope-F1/` (`TestFXWovenEntryReusesFinishedScopeFromRetainedContext`, woven `TestFXWovenRedispatchOfStoredRequestLosesSourceTaint`).
- Fix: add a `finished` flag set in `Finish`, and in `begin` reuse only `existing != nil && !existing.Finished()`.

**H8. URL-query attribution is keyed on `*url.URL` identity rather than content**
- Severity: **High**. Status: CONFIRMED (fx-life-async-F1, fx-sink-http-sources-F2).
- Location: `internal/taint/request/lazy.go:31-46`, `internal/taint/request/http.go:69-77`.
- Ids: life-async-F1 (false negative), sink-http-sources-F2 (false positive).
- Mechanism: `ManageURLQuery` taints `URL.Query()` results only when the URL object has exactly one bound owner. `http.StripPrefix` and `Request.Clone` forward a copied URL with no binding, so query values come back clean while `RawQuery` is still tainted (0 SQLi against 1 in controls). Conversely, after the application replaces `RawQuery` with a trusted literal, the literal is still reported as `http.request.parameter`. `ManageForm`/`ManageParameter` share the problem of gating on context only.
- Repro: `evidence/fx-life-async-F1/run2-go1266.out.txt`, `evidence/fx-sink-http-sources-F2/fx_f2_review.out.txt`.
- Fix: derive query taint from the taint of the `RawQuery` string (propagate through parsing), or bind to the `(URL, RawQuery)` pair and revalidate `RawQuery` identity at `Query()` time.

**H9. A mixed `io.MultiReader` marks trusted bytes as request body**
- Severity: **High**. Status: CONFIRMED (fx-life-lazy-reader-F2).
- Location: `internal/taint/request/reader.go:27-45,67-88`, `iast/io/orchestrion.yml:46-68`.
- Ids: life-lazy-reader-F2, hooks-io-bufio-F2 (Medium, same root).
- Mechanism: the composite reader is bound when any of its first 8 inputs is bound, and `ReadAllBytes` adopts the whole result as one body source. Phase 3 observed `"trusted-attacker"` coming back as a single `[0,16)` `http.request.body` range. A bound but empty body makes a fully clean result tainted. The existing test enshrines the merged source value.
- Repro: `evidence/fx-life-lazy-reader-F2/go1.26.6.out.txt`.
- Fix: bind the MultiReader only when all inputs are bound to the same owner, or track per-component offsets. Otherwise drop the binding.

**H10. A pooled `io.ReadAll` body slice gives A's body to a concurrent request B**
- Severity: **High** (phase 3 put it at the low end of High; `documented_limitation: true` for the stale-range part, not for cross-request attribution). Status: CONFIRMED (fx-life-cross-request-F1).
- Location: `internal/taint/request/reader.go:67-88,119`, `internal/taint/store/lookup.go:120-196`.
- Ids: life-cross-request-F1, sink-e2e-truepos-F3 (Medium, same-request symptom), life-cross-request-F5 (Info, doc).
- Mechanism: `ReadAllBytes` adopts the application-owned slice under the exact key `(ptr,len)`. B refills A's recycled slice to the same length with un-hooked `append`, then calls `string()`. That matches A's key, and `Lookup` accepts the active foreign owner without a content check, so B's span reports SQLi sourced from A's body. Within one request, `copy(body, cleanConstant)` likewise reports the constant as body.
- Repro: `evidence/fx-life-cross-request-F1/run-go1.26.6-count3.log` (3/3), `evidence/sink-e2e-truepos/agent-output.txt`.
- Fix: never adopt application-owned buffers as roots. Clone the body (bounded) or store a content fingerprint and verify it on lookup. At minimum, refuse foreign-owner hits for adopted byte roots.

**H11. `bytes.Buffer` view matching across receivers gives A's writer ranges to B's new Buffer over a recycled slice**
- Severity: **High**. Status: CONFIRMED (fx-life-cross-request-F3).
- Location: `internal/taint/store/writer.go:448-462` (`writerViewIndexLocked`), `internal/taint/propagation/writer.go:202-237`.
- Ids: life-cross-request-F3.
- Mechanism: any receiver whose `(ptr,len,cap,backing,anchor)` equals a tracked view matches it. `bytes.NewBuffer(pooled)` refilled by `append` in B returns a clean string that carries A's ranges. The behavior is deterministic and needs no GC. Reproduced 3/3; the sequential control was clean.
- Repro: `evidence/fx-life-cross-request-F3/zz_f3repro_test.go`.
- Fix: keep an incremental content fingerprint in `writerRecord` and verify it on cross-receiver matches, or restrict view matches to hooked copies made by the same owner.

**H12. A pooled `strings.Builder` with an un-woven reset inherits A's source after GC address reuse**
- Severity: **High**. Status: CONFIRMED (fx-store-identity-gc-F1, which covers life-cross-request-F2).
- Location: `iast/propagation/writer.go:202-205`, `internal/taint/store/writer.go:23-34,448-462`.
- Ids: life-cross-request-F2, store-identity-gc-F1.
- Mechanism: Builder views carry no `Anchor`, and Builder has no native invalidation hook. After an un-woven reset and GC, a same-address, same-len/cap clean write matches the stale view.
- Repro: `evidence/fx-store-identity-gc-F1/independent-woven-go1.26.6.out.txt`.
- Fix: anchor the Builder backing (see `evidence/store-identity-gc/builder-anchor-fix.diff`) or add the same fingerprint check as H11.

**H13. A nested JSON `Bind` claims a freed earlier probe, so an admitted `Decoder.Decode` loses its document**
- Severity: **High**. Status: CONFIRMED (fx-life-json-decoder-F1).
- Location: `internal/taint/jsonbridge/bridge.go:210-224`.
- Ids: life-json-decoder-F1.
- Mechanism: `addDecoderState` CASes the first free probe before scanning later probes for the existing pointer. When A frees a probe ahead of B's slot, B's nested `decodeState.unmarshal` Bind creates a duplicate slot with no document, and B's value comes out untainted (0/20; 20/20 with the fix).
- Repro: `evidence/fx-life-json-decoder-F1/head-go1.26.6.out.txt`.
- Fix: scan all 4 probes for `pointer` first, then claim a free one (validated by `evidence/life-json-decoder/fix-and-diagnostics.diff`).

**H14. Embedded NULs make distinct source tuples hash identically, forcing full probe chains**
- Severity: **High** (perf). Status: CONFIRMED (fx-life-table-lookup-F1).
- Location: `internal/taint/request/table.go:130-151,208-220`.
- Ids: life-table-lookup-F1.
- Mechanism: the hash input joins name and value with NUL delimiters. Moving an attacker-controlled NUL across that boundary yields 256 tuples with the same hash bytes for every seed. Admission then costs 32,896 probes in one request. Full equality still keeps identities distinct.
- Repro: `evidence/fx-life-table-lookup-F1/independent_go1.26.6.out.txt`.
- Fix: length-prefix the name and value in the hash input instead of using a NUL delimiter.

### Medium (reviewer-reported unless noted)

- **M1. Five bridges have no panic shield** (CONFIRMED but downgraded Critical→Medium, `reachable_default: false`, by fx-hooks-panic-safety-F1/F2/F3). Location: `internal/taint/{httpbridge/bridge.go:73-156, iobridge/bridge.go:29-43, urlbridge/bridge.go:24-31, writerbridge/bridge.go:77-91, scopebridge/bridge.go:24-30}`. Ids: life-bridges-F1, hooks-panic-safety-F1/F2/F3, crash-panic-static-F2. Injected panics escape `io.ReadAll`, abort Buffer writes (leaking `lifecycleMu`), and replace host panics. No natural trigger. Evidence: `evidence/fx-hooks-panic-safety-F{1,2}/`. Fix: a nested-frame `recover` per bridge.
- **M2. A middleware-detached context opens a second scope** (life-async-F2). Location: `iast/net/http/orchestrion.yml:81-121`, `scope.go:79-104`. One request takes two permits and loses reports (0/2 or 1/2). Evidence: `evidence/life-async/final-race.out.txt`. Fix: look up the outer owner via bindings before sampling again.
- **M3. A sink context holding a finished request's scope vetoes a live request's taint** (life-async-F3). Location: `internal/vulnerability/tainted.go:45-47`. Evidence: same file as M2. Fix: apply the inactive-scope veto only to evidence owned by that scope's owner.
- **M4. A second concurrent `Scope.Finish` returns before cleanup completes** (life-owner-scope-F2). Location: `scope.go:210-223`. Evidence: `evidence/life-owner-scope/lifecycle-review-output.txt`. Fix: have the second caller wait on a done channel or `sync.Once`.
- **M5. The JSON slot hash clusters real Decoders into 8 buckets, so effective capacity is 32, not 64** (life-json-decoder-F2). Location: `jsonbridge/bridge.go:210`. Evidence: `evidence/life-json-decoder/more.out.txt`. Fix: use a multiplicative hash over the full pointer.
- **M6. JSON slot admission is not gated on relevance** (life-json-decoder-F3). Location: `jsonbridge/bridge.go:60-72`. Static analysis only. Fix: bind only bound or tainted inputs.
- **M7. Query and header name caps are all-or-nothing** (perf-memory-F4). Location: `lazy.go:163-173`, `http.go:97-106`. 39 filler parameters remove all query taint and the SQLi report, and this is undocumented. Evidence: `evidence/perf-memory/results.jsonl`. Fix: taint up to the cap, then drop the rest.
- **M8. `copySources` TryLocks the per-slot mutex on the read path** (perf-contention-F2). Location: `request/lookup.go:143-157`. Concurrent visitors miss taint (up to 19.8%, and 91-99% while racing adds). Evidence: `evidence/perf-contention/`. Fix: `RWMutex`/`TryRLock`.
- **M9. Sampled-out requests allocate a full 3.2-3.5 KB `Annotation`** (perf-memory-F2, perf-allocs-matrix-F2). Location: `annotation.go:198-205`. Evidence: `evidence/perf-allocs-matrix/http-sampled-out.pprof-space.txt`. Fix: use the `nonSampledAnnotation` sentinel (the H2 fix).
- **M10. `trimStore` does a blocking full-map sweep on every bind above 3/4 capacity** (crash-stress-app-F3). Location: `annotation.go:34,227-236`. 48-63 goroutines were blocked there in stress dumps (`evidence/crash-stress-app/dump-analysis.txt`). Fix: rate-limit the trim.
- **M11. `Finished` calls `weak.Make` on every span in the process, even with IAST disabled** (life-weak-gc-F4). Location: `orchestrion.go:27-31`. 1 alloc/op. Evidence: `evidence/life-weak-gc/review-run.log`. Fix: gate on `config.Enabled` and a non-empty store.
- **M12. Oversized sources are hashed before the 64 KiB root limit is checked** (life-table-lookup-F2, NEEDS-REPRO). Location: `request/owner.go:146,180,213`. Fix: check the length first.
- **M13. The range limit falls back to `DefaultLimit` (10) on the duplicate-body path** (prop-ranges-fuzz-F1, which also covers coarse propagation outside this part). Location: `request/reader.go:110`. **Conflict:** life-lazy-reader judged this branch safe (one range). Both can hold, since the problem is the inherited limit of 10 for later operations. Evidence: `evidence/prop-ranges-fuzz/range-limit-repro.log`. Fix: pass `config.MaxRangeCount`.
- **M14. The `http.request.uri` source value is origin-form, not an absolute URL** (sink-systemtests-F3). Location: `http.go:70`. The system-test `TestURI` cannot pass. Evidence: `evidence/sink-systemtests/shapes.json`. Fix: taint the reconstructed absolute URL.
- **M15. Lifecycle test gaps** (life-spans-F6, life-weak-gc-F6, life-cross-request-F4, perf-bench-quality-F2 Medium; life-soak-F3 Low). The spans tests use mocktracer only, at cap 64. There are no tests for GC or recycling, post-finish binds, double Finish, concurrent requests sharing recycled memory, or soak/leak regression, and no request/spans/bridge benchmarks. Fix: adopt the reproducers under `evidence/life-*/` and `evidence/fx-life-*/` as regression tests.

## 3. Low / Info and code quality

- life-async-F4 (Low): reports between root and owner Finish become ManualKeep orphan traces (27-191 per 24 requests, dedup off). None went to a wrong request.
- **Owner-lock contention drops admissions** (`store/owner.go:24-27`). **REFUTED** as a defect by fx-perf-contention-F1 (High→Info, documented), although it observed 2384/29805 rejections. **Conflict:** life-weak-gc-F5 rated it Medium, crash-race-hunt-F2 Low. life-soak-F2 and sink-e2e-truepos-F6 corroborate the drops.
- life-bridges-F3 + crash-panic-static-F3: `_ = recover()` is silent, and manual unlocks could leak locks after a recovered panic. life-bridges-F2: `jsonbridge.Register` accepts nil. life-bridges-F5: bridge tests leak fake registrations. life-bridges-F4 (Info): sink/JSON bridges are registered only in woven binaries with a root `main`, which the README does not say.
- life-spans-F7: a negative annotation short-circuits the owner fallback (NEEDS-REPRO). life-spans-F8 + sink-systemtests-F7: `RequestTainted` is never incremented, and counts are re-submitted every heartbeat.
- life-weak-gc-F7 + perf-gc-F1: a dead annotation's charge waits for a later trim. life-weak-gc-F8: the owner binding pins a closed annotation (bounded).
- life-json-decoder-F4: stream sources include whitespace. life-json-decoder-F5: slots rely on escape analysis, and nothing pins it.
- life-public-api-F1..F4: `IsTaintedBytes(nil)` cannot infer T. The invalid-Origin drop is undocumented. `go doc` hides alias methods. There is no production caller.
- life-soak-F1 (Info): +14.3 MB live, +31 MB peak HeapSys, flat, within the 24 MiB envelope.
- sink-systemtests-F5/F9, perf-disabled-F1, hooks-io-bufio-F4, prop-owner-isolation-F4/F5, crash-fuzz-redaction-F6: minor shape, allocation and coverage notes.
- Cross-refs owned by other parts that touch this code (not counted above): hooks-io-bufio-F1 High (reader binding keyed by wrapper address, `reader.go`), store-concurrency-F1 / store-stress-F1 High (stale owner handle; life-async notes late goroutines can reach it), store-writer-F1 High, store-lookup-F1 High→Medium, crash-hostile-input-F2 High and store-memory-bounds-F3 High (`spans/tainted.go` report path), base-test-127-F1 (the Go 1.27 JSON-v2 compile break blocks `jsonbridge`).

## 4. Verified correct

- Permit accounting (CAS plus rollback, Finish ordering, stale-generation rejection): life-admission, life-owner-scope, life-table-lookup.
- Permits are released on return, panic unwind, early return, HTTP/1, TLS HTTP/2, h2c and a returning hijack: life-admission, life-soak.
- No leak over roughly 820k woven requests. All gauges return to zero, there is no self-disable, and 0 races in 70k `-race` requests: life-soak.
- Isolation after Finish (late goroutines, globals, late lazy sources, owner end racing a sink): life-async, life-cross-request.
- Pooled `bytes.Buffer` invalidation across all tested reset styles: life-cross-request.
- Weak-pointer mechanics: no loss or retention over roughly 3,300 GC-interleaved lifecycles: life-weak-gc.
- Span lock order (no deadlock), transactional `TryCommitTainted`, payload ≤25,000 bytes with redacted fallback: life-spans.
- Race-free `atomic.Pointer` registration, nil no-ops, host panics preserved: life-bridges.
- Source table full-tuple equality and bounded probes: life-table-lookup. JSON panic cleanup, >64 KiB documents, streaming: life-json-decoder. Public API nil/concurrency safety: life-public-api. `EagerHTTP` does not consume the body: life-lazy-reader.

## 5. Coverage gaps

- Go 1.27.0 woven runs were largely blocked by the JSON-v2 compile break, so most lifecycle repros are Go 1.26.6 only. `GOEXPERIMENT=jsonv2` on 1.26.6 was not built.
- The cross-request and JSON repros were not run under `-race`. How often the equal-length refill precondition (H10) occurs in the field was not measured.
- Websocket and long-lived hijacked handlers, HTTP/2 soak, and never-finished or long-lived retained roots were not exercised.
- Reverse attribution was not reproduced: a scope-less background sink putting B's evidence into A's trace (noted in life-cross-request).
- No search for a concrete panicking input in `EagerHTTP`/`Manage*`/`ReadAllBytes`/`InvalidateBuffer`. Finding one would raise M1 to Critical.
- The frequency of real-world double `Finish` (the C2 precondition) is unknown. The distribution of the sampling RNG was not measured.
- The H1 dispute cannot be resolved from the artifacts, because the REFUTED verdict was overwritten.
- life-weak-gc and life-bridges ran unwoven. Phase 3 supplied the woven confirmation only for the High and Critical items.

# Part report: crash (fuzzing, differential testing, stress, unsafe, races, deadlocks, hostile input, config extremes)

Counts after root-cause dedup: **5 Critical, 8 High, 5 Medium** (plus Low/Info notes below). Every Critical and High entry cites its phase-3 `fx-*` verdict file; Medium and below are "reviewer-reported" unless a phase-3 verdict adjusted them.

## 1. Part verdict

Crash-safety of the host application is **not yet acceptable for customer rollout**: one init-order panic from the woven crypto hooks kills the process before `main` (CONFIRMED Critical), and the woven `net/http` form advice introduces production data races in code that is race-free in plain Go. Memory-bounds behavior is solid — every audited limit drops provenance instead of retaining memory, fuzz campaigns (~128M execs total) found no crashers, and 5-minute 256-client stress runs (≈127k requests) showed no deadlock, permit leak, or heap drift. Behavior fidelity of wrapped stdlib calls is excellent: ~1.09M writer scopes, ~3.8M bytes-function scopes, and a 792k-exec string/fmt/strconv/url differential campaign produced zero divergences. However, provenance/behavior verification (phase 3) confirmed two unredacted-secret leaks (SQL comments, Oracle q-quote desync) and four High false-positive/false-negative mechanisms (fmt coarse taint, unanchored Builder view, cross-receiver Buffer view matching, stale owner generation). Config extremes never panic and always clamp to documented bounds.

## 2. Findings by root cause

### C1. Weak-crypto hooks panic during package init: IAST runs before spans/tracer exist — **Critical, CONFIRMED**
- Location: `iast/crypto/hash/orchestrion.yml` + `iast/crypto/cipher/orchestrion.yml` (`go:linkname` into `md5/sha1/des/rc4` bodies); `internal/vulnerability/report.go:37-52`; `internal/spans/vulnerability.go:18`; `internal/spans/annotation.go:29-31,52`
- Contributing ids: `crash-panic-static-F1`
- Phase-3: `fx-crash-panic-static-F1` (CONFIRMED, Critical, reachable in default config)
- Mechanism: `links:` in orchestrion adds a link dependency, not an import, so `iast/crypto/hash` and its `vulnerability`/`spans`/dd-trace-go dependencies never initialize before customer `init()` code that hashes. `config.Enabled` defaults true, `vulnerability.Report` passes its only gate, and `tracer.StartSpan`'s nil-global-tracer type assertion panics — process dies before `main`. Any package (incl. transitive deps) that computes a digest in `init()`/var initializers in the window between `internal/config` and `internal/spans` init hits it. `DD_IAST_ENABLED=false` avoids it.
- Repro: `.omo/review/evidence/fx-crash-panic-static-F1/initcrash2-default.out.txt`; `GOFLAGS='-p=4 -mod=mod' GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -o initcrash2 . && ./initcrash2` → `panic: interface conversion: interface {} is nil, not *tracer.Tracer`, `EXIT=2`.
- Fix: route `ReportWeakHash/ReportWeakCipher` through a dependency-minimal `atomic.Pointer` callback registered in the crypto packages' own `init()` (like `sqlbridge`/`commandbridge`), no-op until registered, plus `defer recover()`. Add a woven regression test with an init-time `md5.Sum`.

### C2. SQL comment bodies are never redacted — secrets leak in clear — **Critical, CONFIRMED**
- Location: `internal/taint/redaction/sql.go:83-100` (no case for `sqllexer.COMMENT`/`MULTILINE_COMMENT`); pinned by `internal/taint/redaction/analyzer_test.go:30`
- Contributing ids: `crash-hostile-input-F1` (Critical), `crash-fuzz-redaction-F2` (Medium, same root cause)
- Phase-3: `fx-crash-hostile-input-F1` (CONFIRMED, Critical, default redaction config)
- Mechanism: `sqlSensitiveToken` marks only STRING/DOLLAR_QUOTED/NUMBER/BOOLEAN/NULL tokens; comment bodies fall to `default: return Interval{}, false`. In the classic exploit `' OR TRUE --`, everything after `--` (e.g. a password hash) is emitted verbatim as span evidence. The shared cross-tracer corpus (dd-trace-js/py `evidence-redaction-suite.json`, dd-trace-java `SqlRegexpTokenizer`) redacts comment bodies; the repo's own test asserts the leak.
- Repro: `.omo/review/evidence/fx-crash-hostile-input-F1/` — unit: `go test -run 'TestFx' ./internal/taint/redaction/`; woven e2e (HTTP source → woven concat → `database/sql` → span payload) ships `"value": "' AND password = '81dc9bdb...'"` unredacted.
- Fix: treat `sqllexer.COMMENT`/`MULTILINE_COMMENT` bodies (minus delimiters) as sensitive intervals; replace the `analyzer_test.go:30` expectation with the shared-corpus expectation.

### C3. Oracle q-quote pre-scan desynchronizes the SQL lexer — later literals, including tainted values, leave unredacted — **Critical, CONFIRMED**
- Location: `internal/taint/redaction/sql.go:27-43, 108-151` (`scanOracleQuotes` is context-free; destructive split at 37-43 shared by all 6 dialects)
- Contributing ids: `crash-fuzz-redaction-F1` (Critical), `sink-redaction-sql-cmd-F1` (Critical, duplicate)
- Phase-3: `fx-crash-fuzz-redaction-F1` (CONFIRMED, Critical, ordinary attacker-forceable trigger, default config)
- Mechanism: `scanOracleQuotes` scans raw bytes for `q'`/`Q'` without string-literal state; a standard literal ending in q/Q (e.g. `'Q'`) plus a later `<open>'` pair creates a bogus q-quote span. Splitting there puts every dialect lexer out of phase: real literal bodies are lexed as bare identifiers (not sensitive) and are emitted raw. All six dialect passes share the split, so the union doesn't help.
- Repro: `.omo/review/evidence/fx-crash-fuzz-redaction-F1/woven_default_config.out.txt` — woven `database/sql` build, INSERT with note `'(urgent) call me back'` leaks both tainted sources raw (`exposed=9/9` for the sink-parity shape); control without leading punctuation fully redacted. Unit: same dir `unit_repro.out.txt`.
- Fix: single left-to-right scan that skips `'...'`/`"..."`/comments before testing `q'` (dd-trace-java's approach), Oracle pass only; or fail closed by lexing the unsplit query too and taking the union of both interpretations. Add the F1 queries as regressions.

### C4. Woven net/http form advice re-stores Form/PostForm on every (re-)parse — production data race even with IAST disabled — **Critical (merged; ParseForm-only variant phase-3-adjusted High), CONFIRMED**
- Location: `iast/net/http/orchestrion.yml:152-186` (ParseForm + ParseMultipartForm deferred advice); `internal/taint/request/lazy.go:119-141`
- Contributing ids: `crash-race-hunt-F1` (Critical → adjusted High), `life-lazy-reader-F1` (Critical, cross-ref from life part, same root cause)
- Phase-3: `fx-crash-race-hunt-F1` (CONFIRMED, adjusted High: identical-pointer writes, no value corruption, but fails customer `-race` runs), `fx-life-lazy-reader-F1` (CONFIRMED, Critical: multipart advice also writes slice elements and `req.MultipartForm.Value`, fires when sampled out)
- Mechanism: in plain Go 1.26.6 a re-`ParseForm` on an already-parsed request is a read-only no-op; handlers commonly re-parse while other goroutines read the form. The woven deferred closure unconditionally writes `r.Form`/`r.PostForm` (and multipart equivalents) on every call — even when IAST is disabled/sampled out — racing with all concurrent readers.
- Repro: `.omo/review/evidence/fx-crash-race-hunt-F1/woven_repro.out` — minimal customer module, `go tool orchestrion go test -race` → 2 DATA RACE woven, 0 plain. Multipart: `.omo/review/evidence/fx-life-lazy-reader-F1/repeated-parse-race-go1.26.6.out.txt`.
- Fix: assign only on first parse (or only when `httpbridge.Form` actually replaced a map); apply to both ParseForm and ParseMultipartForm advice.

### C5. Annotation re-created under a finished root — lost findings and a Critical race on the finished span — **Critical, CONFIRMED**
- Location: `internal/spans/annotation.go:119-149, 184-211, 227-236`; `internal/spans/orchestrion.go:27-46`
- Contributing ids: `crash-unsafe-F1` (High), `life-spans-F2` (High), `life-spans-F3` (Critical, cross-ref from life part)
- Phase-3: `fx-crash-unsafe-F1` (CONFIRMED High — woven: live child re-creates an open annotation under a finished root; committed findings never emitted; two retained replacements hold both `MaxConcurrentRequests` slots and deny a fresh 100%-sampled request), `fx-life-spans-F2` (CONFIRMED: F2 High and F3 Critical — root.Finish deletes the entry with no tombstone and `LoadOrCompute` re-creates it; a double Finish then calls `SetMetaStruct` on the finished span, racing the trace writer: 30 DATA RACE reports with a real tracer + span_meta_structs agent)
- Mechanism: `Finished(root)` deletes/closes the root-keyed annotation; a still-live child's `AnnotationFor`/`BindScope` re-inserts an open annotation under the finished root key. Findings committed to it are never flushed, and a second root `Finish()` writes metadata to an already-finished span concurrently with the trace writer.
- Repro: `.omo/review/evidence/fx-crash-unsafe-F1/` (internal-API + woven); `.omo/review/evidence/fx-life-spans-F2/rerun.out.txt` (`go tool orchestrion go test -race -run '^TestFxLateBindAfterRootFinish$'`).
- Fix: make annotation admission trace-lifecycle-aware — reject creation once the root is finished (immutable trace/lifecycle generation, not a pooled `*tracer.Span` key); removal at trace completion only.

### H1. Non-analyzed requests' spans fill the annotation map — analyzed requests lose their reports — **High, CONFIRMED**
- Location: `internal/spans/annotation.go:182-214, 227-236`; `internal/spans/vulnerability.go:23-35`; `internal/taint/request/scope.go:86-105`
- Contributing ids: `crash-stress-app-F1`, `life-spans-F1` (cross-ref, same root cause)
- Phase-3: `fx-crash-stress-app-F1`, `fx-life-spans-F1` (both CONFIRMED High, default config)
- Mechanism: `BindScope` stores `Sampled:false` annotations for sampled-out/capacity-dropped scopes; `trimStore` caps the map at `MaxConcurrentRequests` (default 2 — same number as analysis permits); entries leave only on root-span finish. Live non-analyzed roots can occupy every slot, so a later analyzed request gets `_dd.iast.enabled=0` and its reports fall through to `NewOrphanTaintedSpan`, which emits an empty span and drops the finding.
- Repro: `.omo/review/evidence/fx-crash-stress-app-F1/annrepro_deterministic.out` — 2 held sampled-out requests → 0/10 (and under load 0/90) analyzed victims reported; control 89/89.
- Fix: don't consume annotation capacity for non-active scopes (tag `_dd.iast.enabled=0` without storing, or size the map by `store.MaxOwners` + separate orphan budget); in `NewOrphanTaintedSpan`, check capacity before starting the span.

### H2. fmt coarse propagation taints output that never rendered the tainted argument — false SQLi on a supported path — **High, CONFIRMED**
- Location: `internal/taint/propagation/string_coarse.go:88-121, 206-219` (`formatArgumentKey`, `CoarseFormat*`); `iast/propagation/coarse.go:48-61`
- Contributing ids: `crash-diff-strings-F1`, `prop-string-coarse-F1`/`F2`, `hooks-yml-fmt-strconv-url-F1`/`F4`, `prop-semantics-parity-F2` (cross-refs)
- Phase-3: `fx-crash-diff-strings-F1`, `fx-prop-string-coarse-F1` (both CONFIRMED High; woven HTTP→SQL reproducers with real `fmt` call sites)
- Mechanism: `formatArgumentKey` keys any reflect String/[]byte-kind argument, then the whole result is tainted whether or not its bytes were rendered. A named-string type whose `String()` maps attacker input to a fixed safe constant (common sanitizing idiom) still yields a fully tainted constant; `%T`, `%.0s`, `%[2]s`-skipping do the same. The tainted constant is accepted by `evidence.CollectString` and produces a false `SQL_INJECTION`.
- Repro: `.omo/review/evidence/fx-crash-diff-strings-F1/woven-go1.26.6.log`; `.omo/review/evidence/fx-prop-string-coarse-F1/woven-go126.txt`.
- Fix: in `formatArgumentKey`, skip arguments implementing `fmt.Formatter`/`fmt.Stringer`/`error`; when feasible, taint only if the output contains the argument bytes; parse verbs/argument indexes that don't render.

### H3. Unanchored `strings.Builder` writer view revives stale/cross-request taint on clean content — **High, CONFIRMED**
- Location: `iast/propagation/writer.go:202-205` (`builderView` sets no `Anchor`); `internal/taint/store/writer.go:23-34, 234-262, 448-462`; `internal/taint/propagation/writer.go:191-230`
- Contributing ids: `crash-diff-bytes-F1`, `store-identity-gc-F1`, `store-writer-F2`, `life-cross-request-F2` (cross-refs, all same root cause)
- Phase-3: `fx-crash-diff-bytes-F1` (CONFIRMED High — also confirms `store-writer-F2` as duplicate), `fx-store-identity-gc-F1` (CONFIRMED High — also confirms `life-cross-request-F2`)
- Mechanism: Builder views are matched numerically (pointer+len+cap) with no anchor, and Builder has no native reset hook. After an unwoven reset (`*w = rowWriter{}` or method-value `Reset`), the freed backing address can be handed back by GC to a clean value with the same len/cap; `publishWriterString` then adopts the previous request's source ranges over entirely clean bytes — a false-positive SQLi attributed to the wrong request. Conditional on address reuse, it fired 88/88, 163/163, 1/1, 1/1 in the falsifier's woven reproducer; 0 without reuse or with the woven-Reset control.
- Repro: `.omo/review/evidence/fx-crash-diff-bytes-F1/repro-woven-http-sql-go1.26.6.txt`; `.omo/review/evidence/fx-store-identity-gc-F1/independent-woven-go1.26.6.out.txt`.
- Fix: anchor the builder backing in `builderView` exactly as `bufferView` does (`Anchor = unsafe.StringData(value)`), so a tracked address cannot be reused while its record exists. Records are already bounded (8/owner) and capacity is charged.

### H4. Buffer writer view matches any receiver — cross-request taint adoption, deterministic — **High, CONFIRMED**
- Location: `internal/taint/store/writer.go:448-462` (`writerViewIndexLocked` full-view equality, adopts into the donor owner), `internal/taint/propagation/writer.go:202-237`
- Contributing ids: `life-cross-request-F3` (cross-ref from life part; code is this part's writer surface)
- Phase-3: `fx-life-cross-request-F3` (CONFIRMED High; woven two-request reproducer, 3/3 runs, no GC or timing needed)
- Mechanism: view matching ignores receiver identity, so request B's new `bytes.Buffer` over a recycled pooled `[]byte` full-view-equals request A's tracked view and inherits A's attacker input as source — B's clean constant query gets an `SQL_INJECTION` with A's raw input as evidence. Distinct from H3 (no GC race; deterministic adoption across receivers).
- Repro: `.omo/review/evidence/fx-life-cross-request-F3/zz_f3repro_test.go` — `go tool orchestrion go test -run TestF3PooledNewBufferCrossRequest -count=3` (3/3 tainted, sequential control clean 3/3).
- Fix: scope view matching to the owning receiver/request (reject adoption across owners, or key on receiver identity in addition to the numeric view).

### H5. Stale owner handle can publish into a successor owner generation — cross-owner provenance — **High, CONFIRMED**
- Location: `internal/taint/store/owner.go:20-60` (`Acquire` recycles a Dead slot without `lifecycleMu`), `internal/taint/store/binding.go:77-108, 168-207`; two-load validation at `owner.go:127-149`
- Contributing ids: `crash-deadlock-F1`, `store-concurrency-F1` (cross-ref, same root cause)
- Phase-3: `fx-store-concurrency-F1` (CONFIRMED High for both ids — deterministic seam reproducer plus natural failure of the finder's reproducer in 47s)
- Mechanism: `Store.Acquire` flips a dead slot Dead→Active without the slot's lifecycle lock; `BindObject`/writer APIs validate a stale handle with two independent atomic loads (old generation + new active state) and publish without re-check. A finished request's handle can bind a fresh object into the successor generation's binding table, and the successor can read the finished request's provenance back — cross-owner taint association on a supported binding path. No deadlock found on these paths (see §4).
- Repro: `.omo/review/evidence/fx-store-concurrency-F1/fx-seam-deterministic.txt` (`go test -run 'TestFxSeam|TestFxControl' ./internal/taint/store/`); natural: `REVIEW_STRESS=90s go test -run TestReviewStaleHandleBindAfterSlotReuse -v ./internal/taint/store`.
- Fix: serialize Dead→Active reactivation under the slot's lifecycle lock and make generation/state validation + publication one revalidated lifecycle-protected operation.

### H6. Full sink-analysis pipeline runs after the per-request vulnerability quota is full — **High, CONFIRMED**
- Location: `iast/database/sql/sql.go:34-49`; `internal/vulnerability/tainted.go:57-83`; `internal/spans/tainted.go:69` (quota checked only inside `TryCommitTainted`)
- Contributing ids: `crash-hostile-input-F2`
- Phase-3: `fx-crash-hostile-input-F2` (CONFIRMED High; woven repro processed 40 tainted reports, committed only 2 at default quota)
- Mechanism: `sql.Report` always runs `evidence.CollectString` → `redaction.AnalyzeSQL` (6 dialect lexings of ≤32 KiB) → `BuildWithSensitive` → stack capture → dedup, and only then checks the quota. After the default 2 reports, every further tainted sink call in the request pays the full pipeline for an always-discarded result (woven/plain ≈24x on a 40-part multipart case; Java checks the quota before sink analysis).
- Repro: `.omo/review/evidence/fx-crash-hostile-input-F2/quota-repro.log` (`go tool orchestrion go build ./cmd/quota-repro && ... -operations=40 -payload-bytes=30000`).
- Fix: add a cheap quota-full atomic check before `CollectString`/`AnalyzeSQL` in the SQL and command sinks; compute the dedup hash from location before running the analyzer.

### H7. The stdlib `bytes.Buffer` invalidation hook scans the owner table on every Buffer mutation in the process — **High, CONFIRMED**
- Location: `iast/propagation/orchestrion.yml:1553-1595`; `internal/taint/writerbridge/bridge.go:75-96`; `internal/taint/store/writer.go:366-432`
- Contributing ids: `crash-stress-app-F2`
- Phase-3: `fx-crash-stress-app-F2` (CONFIRMED High; median 6→475 ns/op with one tracked owner, 5→1838 at 64 owners; controls back to baseline)
- Mechanism: the woven invalidate-backing advice runs for every `Write*`/`Grow`/`ReadFrom` by every caller in the process (dependencies, tracer encoders, request-less goroutines), gated only by process-wide `activeStates > 0`. Once any writer state exists, each call does CAS probes plus an `InvalidateBuffer` loop over all 64 owner records (~1,700 atomic ops per `WriteByte` at 64 owners) even for untracked buffers — unrelated clean code slows ~9-78x.
- Repro: `.omo/review/evidence/fx-crash-stress-app-F2/default.out` (`go tool orchestrion go build -o fxwriter ./cmd/fxwriter && GOMAXPROCS=2 ./fxwriter 2`).
- Fix: keep a store-level atomic bitmask of owners with `writerCount > 0` and scan only those; add a small fixed filter of tracked receiver pointers/backing ranges checked before the owner loop.

### H8. Disconnected/stalled handlers retain admission slots indefinitely — **High, DISPUTED**
- Location: `iast/net/http/orchestrion.yml:27-33` (only release path is the deferred `iasthttpbridge.Finish` in `serverHandler.ServeHTTP`)
- Contributing ids: `life-admission-F1` (cross-ref from life part; liveness/crash-hunting adjacent)
- Phase-3: **DISPUTED** — one falsifier REFUTED the finding; a re-run then CONFIRMED it High and overwrote `fx-life-admission-F1.json`, which now reads CONFIRMED High with an independent woven reproducer (raw-socket disconnect observed server-side → scope still Active → with the default limit of 2, two stalled handlers disable IAST analysis for all later requests until they return; nothing registers a context-cancellation release).
- Mechanism: no `req.Context().Done()`-keyed release, so a client disconnect that leaves the handler blocked holds a permit forever (brief rule: permanent IAST self-disable = High). Note: `crash-stress-app`'s client-cancellation cases all completed handler-side and saw permits recover — not contradictory, but the stalled-handler shape was not stressed by that node.
- Repro (per the confirming run): `.omo/review/evidence/fx-life-admission-F1/zz_fx_life_admission_test.go`.
- Fix: release the admission slot on request-context cancellation (e.g. a goroutine or context callback keyed to `Scope`/permit acquisition).
- Action: re-adjudicate before GA — the two phase-3 verdicts contradict.

### Medium (reviewer-reported; no phase-3 falsification)
- **`crash-stress-app-F3`** — `trimStore` blocking full-map sweep (`xsync.DeleteMatching`) on every span bind once past 3/4 capacity: lock convoy (48-63 of ~1,300 goroutines blocked under load). `internal/spans/annotation.go:34,199,227-236`. Evidence: `.omo/review/evidence/crash-stress-app/goroutine-dumps.tgz` (`dump-analysis.txt`). Fix: best-effort rate-limited trimming via `TryLock` + atomic occupancy counter. (Compounded by H1.)
- **`crash-unsafe-F2` + `life-spans-F5`** (same root cause, NEEDS-REPRO) — annotation capacity admission is a TOCTOU (`trimStore` size-check before distinct-key `LoadOrCompute`), so `MaxConcurrentRequests` is not a hard bound under concurrent first binds. `internal/spans/annotation.go:126-145,190-236`. Fix: reserve capacity atomically as part of new-key admission.
- **`crash-fuzz-engine-F1`** — the engine fuzzer can never reach the exact-to-coarse, drop, case, window, concat, JSON, or writer paths (Join always 2 elements, Replace always 1-byte `old`, count clamped ≤32): 0.0% coverage on the riskiest engine area. `internal/taint/propagation/sequence_operations_test.go:18,131,138`. Fix: extend the operation table and unclamp the bounds.
- **`crash-fuzz-redaction-F3`** — `FuzzAnalyzeSQL`'s oracle reuses the production q-quote splitter, so it was blind to C3 (20M execs PASS on a reproducible 70-byte leak). `internal/taint/redaction/fuzz_test.go:46-54`. Fix: independent oracle lexing the unsplit query; seed with C3 queries.
- **`crash-config-extremes-F1`** — README omits the hard 64 cap on `DD_IAST_VULNERABILITIES_PER_REQUEST` (`README.md:117` vs `internal/config/config.go:34,75`). Evidence: `.omo/review/evidence/crash-config-extremes/configdump_matrix_results.json`. Fix: document `Integer from 1 to 64`.

## 3. Low / Info and code-quality notes
- `crash-panic-static-F2` (Low): only `sqlbridge`/`commandbridge`/`jsonbridge`/`TryCommitTainted` have `recover`; HTTP/reader/URL/writer/operator/span-finish hooks run unshielded — no reachable panic today (per-site proofs only), but no structural guarantee.
- `crash-panic-static-F3` (Info): manual `TryLock` unlocks in store/request code — a recovered sink panic would leak a shard/owner lock (latent; critical sections are provably panic-free today).
- `crash-race-hunt-F2` + `perf-contention-F1` (REFUTED as a defect, phase-3 adjusted Info, documented limitation): global `ownerMu.TryLock` in `Store.Acquire` drops begins under contention even with free capacity (`internal/taint/store/owner.go:24-27`); design allows contention drops, no permit leak.
- `crash-hostile-input-F3` (Low): retroactive source redaction patterns are built from byte length, exceeding the 250-**rune** truncation up to 4x (`internal/spans/tainted.go:264`) — truncation inconsistency/byte side channel only.
- `crash-diff-bytes-F2` (Low): `bytes.Join` >16 parts silently switches to coarse prefix-only provenance; README lists Join as exact without the caveat. `crash-diff-bytes-F3` (Low): writer bound is on capacity — a pooled Buffer that ever exceeded 64 KiB is permanently untracked (`Reset` keeps capacity).
- `crash-race-hunt-F3` (Low): `TestCommitTaintedSkippedDedup` flaky (telemetry coalescing timing). `crash-fuzz-redaction-F4/F5` (Low): redaction/evidence fuzz oracles check length/budget, not the redaction property or marks/generations. `crash-fuzz-redaction-F6`, `crash-fuzz-engine-F2` (Info): `FuzzAdd`/`FuzzOwnerLifecycle` cover only isolated/fixed paths.
- `crash-diff-strings-F2` (Info): tainted `strings.Join` of one element clones where native aliases (dup of `hooks-fidelity-strings-F2`). `crash-diff-strings-F3` (Info): window derivation drops under sustained per-root load — fits documented per-root/value caps, not a logic bug; telemetry counter suggested.
- `crash-stress-app-F4` (Info): woven stress app ~4x lower throughput at 100% sampling (client also woven; noisy machine).

## 4. What was verified correct
- **No behavior divergence in wrapped stdlib**: 1,083,943 writer scopes + 3,763,280 bytes-function scopes (58.3M calls) and 792,544 string/fmt/strconv/url execs returned byte-identical results/errors/panics/aliasing vs unwoven twins, including invalid UTF-8, nil receivers, out-of-range Grow/Truncate, and 17+-operand concat (`crash-diff-bytes`, `crash-diff-strings`).
- **No crashers in ~128M fuzz execs**: 47.5M redaction/evidence/request + 62.3M ranges + 18.3M engine executions — 0 panics, 0 invariant failures (`crash-fuzz-redaction`, `crash-fuzz-ranges`, `crash-fuzz-engine`).
- **Internal machinery race-free**: 1,300+ plain `-race` package runs, woven `-race` sql/exec/integration suites, store churn (24 workers, 19k live handles) and end-to-end report stress — 0 races apart from C4 (`crash-race-hunt`).
- **No panic/deadlock/leak under load**: 127k requests across 5-min 256-client runs, incl. ~9k handler panics, ~4k cancellations, post-handler sinks — store drained to `values=0 charged=0`, heap returned to 23-24 MiB, 0 cross-request bleed checks (71k) (`crash-stress-app`); hostile-input 58-case matrix: 0 panics, 0 races, identical status codes, heap bounded (17.5→19.8 MB) (`crash-hostile-input`).
- **Every enumerated panic site is safe or behind a verified recover**; fixed-array indexes, ranges algebra, slices, divisions, makes all bounded; recover semantics don't swallow host panics (`crash-panic-static`).
- **unsafe audit**: no `uintptr`→pointer reconstruction; store keys carry typed anchors/generations; checkptr + `-race` suites pass; weak pointers made only from heap `*tracer.Span` (`crash-unsafe`).
- **Lock graph acyclic; no IAST-owned goroutines/channels/SetFinalizer**; span-finish lock order `Annotation → Span.mu` has no inverse; all audited blocking paths release (`crash-deadlock`).
- **Config extremes never panic** — 57-combination matrix clamps to documented bounds with warnings; malformed regexes fall back safely; woven pipeline correct under post-clamp values (`crash-config-extremes`).

## 5. Coverage gaps
- **Go 1.27 woven builds untestable**: the encoding/json advice compile failure (`base-test-127-F1` / `hooks-compile-matrix`, owned by the hooks part) blocked every woven 1.27 race/diff/stress run; `bytes.CutLast` and 1.27 Buffer internals were never diffed.
- **Concurrency not fuzzed**: differential harnesses are single-goroutine; multi-goroutine writer/buffer sharing and the writerbridge 128-slot saturation were out of scope (`crash-diff-bytes`, `crash-diff-strings`).
- **Engine fuzz coverage is 0%** on coarse/drop/case/window/concat/JSON/writer paths (see Medium `crash-fuzz-engine-F1`), so the "no crasher" result says little about the riskiest area.
- **Race-detector limits**: absence of reports is not proof for statically described torn-generation windows (`store-concurrency-F2/F3`, `prop-owner-isolation-F1` did not fire in the woven stress).
- Not exercised: the real msgpack `meta_struct` path beyond one fake agent (C5), HTTP/2 and slow-body permit-exhaustion attacks, `-asan` (unsupported on darwin/arm64), a survey of real third-party modules hashing in `init()` (C1 blast radius), and C3's full trigger shape enumeration. Cross-request bleed through pooled `io.ReadAll` body slices (`life-cross-request-F1`, CONFIRMED High) lives in the reader path and is covered by the life part, not re-reviewed here.

# sink-vuln-report: Vulnerability reporting (report, tainted commit, dedup, location, stack)
Verdict: The dedup design is memory-bounded, race-free (race run is clean) and never blocks. The tainted commit path is transactionally correct. However, location selection feeds the dedup hash, and that hash is unsafe in three ways: location-less findings collide, deferred-SQL panics collide, and paths are absolute build paths. Separately, the weak-crypto `Report` path gets no process-level dedup and starts an orphan span on every call. That is High overhead and trace-volume behavior.
Scope covered: internal/vulnerability/{report.go,tainted.go}, dedup/dedup.go, stacktrace/stacktrace.go and all their tests; callers iast/database/sql/sql.go, iast/os/exec/exec.go, iast/crypto/{hash,cipher}/*.go and their orchestrion.yml; internal/model/{vulnerability.go,event.go}; internal/spans/{tainted.go,annotation.go,vulnerability.go,orchestrion.go,orchestrion.yml}; dd-trace-go v2.11.0-rc.1 instrumentation.CaptureStackTrace and internal/stacktrace (iterator, skipFrame, top/bottom split, Index semantics) and internal/telemetry/log; dd-trace-js path-line.js and sql-injection-analyzer.js; dd-trace-java Vulnerability.java. Ran: reproducers (below); `go test -race ./internal/vulnerability/...` (pass); the panic repro under `-gcflags='all=-N -l'`.

## Findings
### sink-vuln-report-F1: Weak-hash/cipher reports start an orphan span on every call, with no process dedup
- Severity: High
- Category: perf
- Location: internal/vulnerability/report.go:41-58,96-108; iast/crypto/hash/orchestrion.yml (`__dd__iast_ReportWeakHash__(nil, crypto.MD5)` and every other weak-hash aspect); iast/crypto/hash/hash.go:18-25
- Claim: The woven crypto advice always passes a nil context, so `Report` never finds a span. Every `md5.New`/`md5.Sum`/`sha1.*`/weak-cipher call in the process calls `tracer.StartSpan` and `AnnotationFor`, and it makes a fresh sampling draw (30% by default). Each sampled call captures a stack/location, adds one vulnerability, and gets `ManualKeep` in `spans.Finished`. `Report` never consults the process dedup set (`taintedReportDedup` is used only by `ReportTainted`). Event-local dedup is meaningless because each orphan event holds exactly one vulnerability, so `DD_IAST_DEDUPLICATION_ENABLED=true` has no effect on weak crypto. Hot library users of MD5/SHA1 (S3 Content-MD5, ETags, cache keys, UUIDv3/v5, DB auth) therefore produce one span per call and about 30% force-kept traces for one identical finding. Java deduplicates every vulnerability type through a global hash set. Orphan annotations also transiently occupy the `MaxConcurrentRequests` annotation store (default 2, trim threshold 1), which request admission shares (static reasoning).
- Evidence: .omo/review/evidence/sink-vuln-report/repro_external_test.go `TestReproWeakHashOrphanPerCallNoProcessDedup` (it mirrors the nil-ctx advice). Command: `cd <private copy> && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -count=1 -run TestRepro -v ./internal/vulnerability/`. Output (.omo/review/evidence/sink-vuln-report/repro-output.txt): `sampling=100%: 1000 identical weak-hash calls -> 1000 orphan spans started, 1000 sampled vulnerability events`; `sampling=30%: ... 1000 orphan spans started, 314 sampled vulnerability events`; `allocations per instrumented md5 call (sampled): 85`.
- Fix: Check `taintedReportDedup` (or a shared process set) by hash before creating the orphan span. This needs the location/hash computed first (a depth-1 capture is cheap), plus `Add` after commit. Ideally, also skip the orphan span entirely when dedup hits, and add a cheap per-process rate gate for no-context sinks.

### sink-vuln-report-F2: Every location-less finding of a type shares one hash, so the first one suppresses the rest process-wide for up to 1h
- Severity: Medium
- Category: false-negative
- Location: internal/vulnerability/report.go:155-158 (`locationFromTrace(spanID, nil)`); internal/model/vulnerability.go:35-42
- Claim: When `firstApplicationFrame` fails, `CaptureLocationSkipWhile` returns a location with only SpanID. Failure cases are: a frame gap above `MaxFrameGap` (0 for SQL), where dd-trace-go filtered a `<generated>` or DD/Orchestrion frame; a 32-frame window full of skipped namespaces; or dd-trace-go's top/bottom split creating an index jump. SpanID is not hashed, so every such vulnerability hashes to `fnv(type || int64(0) || "")`. The process dedup (tainted.go:92-95) then drops every later location-less finding of that type, from any request and any sink call site, for up to one hour. Reachability is uncommon on the plain database/sql path, which is why this is Medium.
- Evidence: .omo/review/evidence/sink-vuln-report/repro_internal_test.go `TestReproLocationlessHashCollision`. Command: `cd <private copy> && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -count=1 -run TestRepro -v ./internal/vulnerability/`. Output: `location-less hashes: a=1491529353 b=1491529353 equal=true`; `process dedup Check(b) after committing a: 2 (2 == CheckPresent)`.
- Fix: Skip the process dedup (and event-local dedup) when the location has no path. Alternatively, hash a stable fallback (for example the redacted evidence value or the sink kind) for location-less findings.

### sink-vuln-report-F3: A deferred SQL report that runs during a driver panic uses `runtime.gopanic` as its location, so all such findings collide
- Severity: Medium
- Category: provenance
- Location: iast/database/sql/orchestrion.yml:54-117 (`defer __dd__iast_ReportSQL__(...)`); iast/database/sql/sql.go:20-30 (`sqlSkip` lacks `runtime`); internal/vulnerability/report.go:172-194
- Claim: The SQL sink runs as a deferred call. If the driver or database/sql panics, the defer runs from `runtime.gopanic`. dd-trace-go does not filter runtime frames, and `sqlSkip` does not list `runtime`, so the first "application" frame is `runtime/panic.go:860 runtime.gopanic`. Every such SQLi then hashes the same, and dedup reduces them to one per hour. The reported location is also meaningless. net/http recovers handler panics, so the customer recover is not exotic. Unoptimized builds (`-N -l`) do not show the problem on the non-panic path.
- Evidence: .omo/review/evidence/sink-vuln-report/reprosink/sink.go (the defer shape mirrors the woven advice) and .omo/review/evidence/sink-vuln-report/repro_external_test.go `TestReproDeferredSinkPanicLocation`. Command: `cd <private copy> && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -count=1 -run TestRepro -v ./internal/vulnerability/`. Output: `normal path=.../repro_external_test.go line=70` versus `panicA path=.../src/runtime/panic.go line=860 method=runtime.gopanic hash=-1603347292` and `panicB ... hash=-1603347292`.
- Fix: Add `runtime` to `sqlSkip`, and allow the gap that runtime panic frames introduce. Alternatively, skip reporting when `recover` would observe a panic, since the query likely never ran.

### sink-vuln-report-F4: The location and hash point at ORM/driver-wrapper frames instead of customer code, so all SQLi through one ORM line collapse into one finding
- Severity: Medium
- Category: false-negative
- Location: iast/database/sql/sql.go:20-30; iast/os/exec/exec.go:26-38; internal/vulnerability/report.go:172-194
- Claim: `SkipWhile` skips only IAST, dd-trace-go and stdlib sink namespaces. For gorm, sqlx, ent, bun, pgx/stdlib, squirrel and similar libraries, the first unskipped frame is inside the library (for example `gorm.io/gorm/callbacks/query.go:NN`). The location is therefore wrong for the user. The hash is location-only, so every tainted query the application issues through that library line becomes a single finding per process per hour. dd-trace-js explicitly excludes SQL library frames from locations (`sql-injection-analyzer.js:9`, `getNodeModulesPaths('mysql','mysql2','sequelize','pg-pool','knex')`). dd-trace-go already classifies known third-party packages (`internal/stacktrace.isKnownThirdPartyLibrary`).
- Evidence: static reasoning only (NEEDS-REPRO for a woven gorm/sqlx app).
- Fix: Skip known third-party/ORM frames when a customer frame exists further down the stack, as JS does with client frames and a fallback to all frames. Keep the bounded depth.

### sink-vuln-report-F5: The vulnerability hash includes the absolute build path, so it changes whenever the build directory or `-trimpath` setting changes
- Severity: Medium
- Category: config
- Location: internal/model/vulnerability.go:36-41; internal/vulnerability/report.go:253-267
- Claim: `Location.Path` is `runtime.Frame.File`, an absolute path on the build machine (for example `/tmp/ddiast-review/wt/sink-vuln-report/...` in the repro, versus `/Users/.../dd-iast-go/...` for the same source). The hash therefore differs between builds of identical code whenever CI uses a varying workspace or `-trimpath` changes. The backend then sees new vulnerabilities on every deploy. The absolute builder path is also shipped as the location. Java hashes stable class names, and JS uses cwd-relative paths.
- Evidence: .omo/review/evidence/sink-vuln-report/repro-output.txt (the location path is the private-copy absolute path; the hash input is that path). Otherwise static reasoning.
- Fix: Hash a module-relative path (strip GOROOT/GOMODCACHE/module root, or use `namespace + file base`), and report that same normalized path.

### sink-vuln-report-F6: Telemetry logs pass raw structs through `slog.Any`
- Severity: Low
- Category: quality
- Location: internal/vulnerability/report.go:102-103; internal/model/event.go:103,109
- Claim: dd-trace-go's telemetry log contract says "slog.Any() only allowed with LogValuer implementations". `slog.Any("vulnerability", vuln)` renders a struct with pointer fields, so evidence is not leaked (only pointer addresses and hash). However, it produces high-cardinality messages that defeat telemetry log dedup, and it runs on every capacity drop. event.go:109 also has a `%#v` verb inside a constant message.
- Evidence: static reasoning; dd-trace-go internal/telemetry/log/log.go:17 and backend.go:184-209.
- Fix: Log only the type (and at most a counter). Drop the `%#v`.

### sink-vuln-report-F7: A duplicate tainted report without a span still starts and finishes an empty orphan span
- Severity: Low
- Category: perf
- Location: internal/vulnerability/tainted.go:62-76,83-95
- Claim: `selectTaintedAnnotation` creates the orphan span, and takes an annotation-store slot, before `commitTainted` runs the dedup check. A process-dedup hit therefore emits an empty `vulnerability` span. This is rare because an owner-to-span binding usually exists.
- Evidence: static reasoning only.
- Fix: Run the dedup `Check` on the computed hash before creating the orphan span.

### sink-vuln-report-F8: `CaptureLocationSkipWhile` walks the whole stack even with stack traces disabled
- Severity: Low
- Category: perf
- Location: internal/vulnerability/report.go:138-154
- Claim: With depth 32, dd-trace-go reserves 8 "top" slots and iterates and symbolicates the entire goroutine stack to fill them (stacktrace.go:353-386). `Report` explicitly avoids this with depth 1 ("not traversing the entire stack"). The tainted path pays this on every report, including dedup hits, in deep framework stacks. It is bounded by the sink rate, not by dedup.
- Evidence: static reasoning; dd-trace-go internal/stacktrace/stacktrace.go:353-386,436-440.
- Fix: When stack traces are disabled, capture incrementally with depth 1 and skip-advance (as `selectLocationTrace` does), or use a depth whose `topFrameDepth` is 0.

## Checked and found correct
- dedup.Set: a fixed `[1000]int32` array with no growth. It clears completely when full or after 1h, and a backwards clock also resets it. All entry points use `TryLock`, so they never block. It is nil-safe, and the checklocks annotations are consistent. `go test -race ./internal/vulnerability/...` passes.
- commitTainted: `Add` runs only after a successful `TryCommitTainted`. Contention returns `CheckSkipped`/`AddSkipped`, which never suppresses a report. A concurrent Check/Add race can only yield a benign duplicate.
- The event-local dedup and the per-request cap (`min(VulnerabilitiesPerRequest, 64)`) are applied under the annotation lock in both paths.
- The hash is final before commit. `StackID` is set only after `RecordStackTrace` succeeds, and on the private location copy (spans/tainted.go:264-311), so it never feeds the hash.
- Lock order is annotation, then span (`RecordStackTrace`/`SetMetaStruct`) in `Report`, `ReportTainted` and `Finished`. The finish hook is prepended before tracer locking, so there is no inversion.
- `firstApplicationFrame`: indexes must increase strictly, the gap budget is cumulative, and namespace matching respects segments (`os` does not match `osiris.io`). Rebasing Index after trimming yields a 0-based stack (covered by existing tests).
- `selectLocationTrace`: the recapture loop is bounded at 8 captures. `Index+1` correctly counts raw frames, including frames dd-trace-go filtered.
- Orphan tainted spans: `spans.Finished` is idempotent (`LoadAndDelete`), so the explicit call followed by the woven hook is safe.
- `LocationFromFrame` and `Matches` handle pointer receivers, value receivers and joined-function layouts.
- Unoptimized builds (`-N -l`) still yield the customer frame for the deferred SQL report on the normal path (repro-output.txt).

## Not covered / open questions
- I did not run a woven end-to-end check of F3 or F4 (to avoid the heavy orchestrion build). F4 needs a gorm/sqlx fixture.
- Whether the IAST backend keys vulnerability identity on `hash` across deployments (this determines F5's real impact).
- The cross-tracer hash algorithm differs (FNV-32a versus Java CRC32/long). I assumed the backend treats the hash as opaque.
- The README orphan caveat is documented. Tainted orphans are bounded per location by process dedup, but weak-crypto orphans are not (see F1).

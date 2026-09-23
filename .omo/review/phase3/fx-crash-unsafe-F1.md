# fx-crash-unsafe-F1: verification of crash-unsafe-F1 — a live child recreates an open annotation after its root finishes

## Verdict per finding

### crash-unsafe-F1 — CONFIRMED
The claimed mechanism is real at HEAD `2e23b46`. `Finished(root)` (`internal/spans/orchestrion.go:27-36`, woven as a prepend on every `(*tracer.Span).Finish` by `internal/spans/orchestrion.yml:14-30`) does `store.LoadAndDelete(weak.Make(span))`, deleting and closing the root-keyed annotation when the root finishes. A live child of that root still resolves `span.Root()` to the finished root (dd-trace-go `span.go:623-636` returns `ctx.trace.root`; finishing does not clear it, and the trace struct keeps the root span strongly referenced). `AnnotationFor` (`internal/spans/annotation.go:118-149`) and `BindScope` (`annotation.go:182-211`) then recreate a brand-new open annotation under the already-finished root key. `Finished(child)` deletes `weak.Make(child)` — a different key — so the replacement is never closed, never emitted, and never removed except by dead-key trim, which cannot fire while any span of the trace keeps the root alive. Exactly as claimed (cited line ranges are off by one: `AnnotationFor` starts at 118, `BindScope` at 182). No duplicate findings were listed under this node; the single root cause is shared by all manifestations below.

## Reproduction

All runs in the private copy `/tmp/ddiast-review/wt/fx-crash-unsafe-F1`, Go 1.26.6, `GOFLAGS=-p=4`.

**1. Finder's reproducer, re-run independently** (`TestReproFinishedRootAcceptsReplacementFromLiveChild`, copied verbatim into my copy):
```
$ env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 GOCACHE=... GOTMPDIR=... go test -count=1 -v -run 'TestFX|TestReproFinishedRoot' -timeout=5m ./internal/spans
    finder_repro_test.go:58: live child recreated an open annotation for an already-finished root
    finder_repro_test.go:70: post-child-finish root-key replacement retained=true closed=false
--- FAIL: TestReproFinishedRootAcceptsReplacementFromLiveChild
```

**2. My own internal-API reproducer** (`.omo/review/evidence/fx-crash-unsafe-F1/fx_f1_repro_test.go`, plain test):
- `TestFXLiveChildRecreatesOpenAnnotationAfterRootFinish`: after `Finished(root)`, `AnnotationFor(child)` creates a new **sampled, open** replacement under the finished root key; a finding committed to it (`TryCommitTainted`) is **never emitted** (no finished span carries an IAST payload) and survives `Finished(child)`:
  `finding stranded: root-key replacement retained=true closed=false vulns=1`
- `TestFXFinishedRootReplacementLeaksAdmissionSlot`: two retained replacements under finished roots hold both `MaxConcurrentRequests=2` slots; `trimStore` cannot reclaim them (keys alive); a fresh 100%-sampled request is dropped:
  `fresh request denied IAST analysis: max concurrent requests reached (leaked slots)`

**3. My own woven reproducer** (`.omo/review/evidence/fx-crash-unsafe-F1/woven_late_child_test.go`; package `fxf1repro` deliberately outside `internal/**` so the customer-facing aspects weave its call sites). Run A (`go tool orchestrion go test -run TestWovenLateChildRecreatesAnnotationUnderFinishedRoot ./fxf1repro`), simulating a handler that leaves a background goroutine holding the request context:
```
woven surface recreated an open non-sampled annotation under finished root 0x5ab5d0858160
live 100%-sampled request 2 (root=0x5ab5d08586e0) denied IAST analysis by the stale annotation under finished root 0x5ab5d0858160
stale annotation survives late child finish: no hook keyed to the finished root remains
finished "http.request" spanID=681938523455203938: _dd.iast.enabled=1
finished "http.request" spanID=9206513498962852760: _dd.iast.enabled=<nil>
```
The recreation happens through the **real woven chain** `tracer.StartSpanFromContext` → `iast/net/http/orchestrion.yml:50-80` wrapper → `iast/net/http/http.go:23 BindStartSpan` → `spans.BindScopeFromContext` → `BindScope`, and the deletion through the real woven `Finished(root)` inside `root.Finish()`. Additionally, the woven tracer's GLS parent inference (dd-trace-go `context.go:91-233`: `SpanFromContext` falls back to the goroutine-local active span) attaches a later request's root span to the dead trace while the background goroutine's child is unfinished, so the stale marker **denies a live, active, 100%-sampled request** (its span never even gets the `_dd.iast.enabled` tag). Run B (`-run TestWovenWeakHashFindingStrandedUnderFinishedRoot`): a weak-hash finding reported through the exported public sink API `iast/crypto/hash.ReportWeakHash(ctx, crypto.MD5)` with a live-child context after root finish is committed to a new open **sampled** annotation under the finished root and never emitted:
```
weak-hash finding stranded in an open annotation under a finished root; never emitted
```
Woven build peak RSS ≈ 1.1 GB (`/usr/bin/time -l`), below the 4 GB concern threshold; cold build ≈ 186 s.

## Reachability

- **Default configuration, supported toolchain (Go 1.26.6), woven build: reachable.** The recreation path is default-woven customer surface: any handler spawning a goroutine that keeps the request context and later calls `tracer.StartSpanFromContext` after the request root span finished (a normal background-work pattern) triggers `BindStartSpan`→`BindScope` with a finished root (run A). The replacement is non-sampled there (the scope already finished), but it is retained under the finished root key, cannot be trimmed (`releaseDeadAnnotation`, `annotation.go:239-249`, only removes dead keys; the child keeps the root alive via `trace.root`), consumes an admission slot, and — via GLS attach or plain map exhaustion — denies IAST analysis to later live requests. With the default `DD_IAST_MAX_CONCURRENT_REQUESTS=2`, two such lingering traces permanently disable annotation admission.
- **False-negative (stranded finding) variant:** requires a *sampled* replacement, reachable through the exported public sink functions (`iast/crypto/hash.ReportWeakHash`, `iast/crypto/cipher.ReportWeakCipher`) called with a span context whose child belongs to a finished root (run B), or any future caller of `AnnotationFor` with a live child of a finished root. The woven stdlib weak-crypto hooks pass `nil` ctx (orphan span path — safe), and the tainted SQL/CMD sinks use `ExistingForSpan`/`ExistingForOwner`, which never create annotations (`internal/vulnerability/tainted.go:105-124`) — so pure weaving degrades availability rather than losing committed findings.
- **Not a documented limitation.** Neither the README nor `.omo/review/phase1/01-design-intent.md` says anything about span-annotation lifecycle after root finish; the leak breaks the documented `DD_IAST_MAX_CONCURRENT_REQUESTS` contract ("maximum number of requests processed concurrently", consumed by finished traces) and product rules 3 (bounded retention lifetimes) and 4 (no lost findings).

## Adjusted severity

**High (unchanged).** One line: a confirmed false-negative vulnerability on a supported sink path (exported public API) plus a leaked admission slot that can permanently self-disable IAST under the default capacity of 2 — both explicit High rules in the brief.

## Root cause (file:line)

`internal/spans/orchestrion.go:27-36` (`Finished` removes the annotation keyed by the *finishing span's own* pointer, with no trace-lifecycle generation) combined with `internal/spans/annotation.go:118-149` (`AnnotationFor`) and `annotation.go:182-211` (`BindScope`), both of which admit a brand-new annotation under a root key without checking that the root/trace is still live. `annotation.go:227-235` (`trimStore`) cannot reclaim the retained entry while any span of the finished trace is alive.

## Minimal fix

Make `Finished` leave a **closed tombstone** under the root key instead of `LoadAndDelete`: keep the annotation in the map, mark `closed`, emit the payload, release source identities, and let the existing dead-key trim (`releaseDeadAnnotation`) reclaim it once the root span becomes unreachable. Then make admission lifecycle-aware: `AnnotationFor`/`BindScope` must treat a `Closed()` annotation under the key as a finished trace — return the non-sampled sentinel (or fall back to an orphan span for reporting) instead of recreating. `ExistingForSpan`, `TryUseOpen`, `TryCommitTainted`, and `Report` already tolerate closed annotations, so the change is small. This removes both the open-recreation and the stale-marker hijack of live requests. Residual: a finished trace with live children still holds one map slot until its spans die; if strict capacity semantics are required, count only *open* annotations toward admission rather than map size.

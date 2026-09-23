# fx-life-spans-F2: late bind after root Finish (F2) and double-Finish race (F3)

## Verdict per finding

### life-spans-F2: CONFIRMED (High)
The mechanism holds at HEAD 2e23b46. `Finished` (internal/spans/orchestrion.go:28) removes the root's entry with `store.LoadAndDelete` and leaves nothing behind. A later `BindScope` (annotation.go:190-205) or `AnnotationFor` (annotation.go:134-142) on the same root misses in `store.Load` and calls `LoadOrCompute`, which stores a fresh open `Annotation{Sampled: active}`. `bindOwnerSpan` then rebinds the owner to that new annotation. `ReportTainted` → `selectTaintedAnnotation` → `ExistingForSpan` finds it, `TryCommitTainted` succeeds, and the report returns true. The root's Finish prologue has already run, so nothing ever flushes the annotation.

`ReportTainted` alone never re-creates an annotation, because it uses `ExistingForSpan`/`ExistingForOwner`. Only a late bind triggers the bug: the woven `tracer.StartSpanFromContext` wrapper (`BindStartSpan`, iast/net/http/http.go:21-25), the handler-advice `BindScopeContext`, or `vulnerability.Report` through `AnnotationForContext`. Without that bind, the same finding goes to an orphan `vulnerability` span. My control run shows this.

There is also an amplifier the finder did not report (static reasoning): `commitTainted` (internal/vulnerability/tainted.go:96-106) adds the lost finding's hash to `taintedReportDedup`. Deduplication is on by default with a 1-hour window (dedup.go:17), so the same vulnerability from later, healthy requests is suppressed for up to an hour.

### life-spans-F3: CONFIRMED (Critical)
The woven prologue calls `spans.Finished` on every `Span.Finish`. dd-trace-go tolerates repeated `Finish`, but the prologue runs before its `finished` guard. When the first Finish handed the trace chunk to the writer and a late bind then re-created an annotation holding a finding, the second Finish reaches `span.SetMetaStruct` (orchestrion.go:44). `setMetaStructLocked` (dd-trace-go span.go:862-866) has no finished check, and the writer encodes finished spans without taking the span lock. The race detector reports two races:
- the `span.metaStruct` field written by `SetMetaStruct` against `metaStructMap.EncodeMsg` reading it (meta_struct.go:25);
- the IAST `Event` contents written by `TryCommitTainted` (internal/spans/tainted.go:128) against the writer's `Event.MarshalMsg` (meta_struct.go:37). The writer is serializing an event that the handler goroutine mutated with no happens-before edge.

## Reproduction
My independent reproducer is `.omo/review/evidence/fx-life-spans-F2/zz_fx_life_spans_f2_test.go`. It runs through the real woven surfaces: the net/http serverHandler scope aspect, the woven `StartSpanFromContext` wrapper, the woven `Span.Finish` prologue, and the woven `(*sql.DB).ExecContext` sink fed by a tainted `r.URL.Query()` value. It calls no internal API to drive the scenario; `spans.ExistingForSpan` is used only to observe the store. The handler shape follows the repository's own e2e harness: the handler creates its root with `tracer.StartSpanFromContext(r.Context(), ...)`.

```sh
# in a private copy, iast/integration/testapp/
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l go tool orchestrion go test -race -count=1 -timeout 20m -v \
  -run '^TestFx(LateBindAfterRootFinish|DoubleFinishRace)$' .
```
The command exits 1. Key lines from `evidence/fx-life-spans-F2/woven-race.out.txt`:
```
--- PASS: .../control-before-finish          finished span="handler.root" enabled=1 vulnerabilities=1
--- PASS: .../control-after-finish-no-new-span finished span="vulnerability" enabled=1 vulnerabilities=1
mode=late-child-span-after-finish emitted vulnerabilities=0; open annotation still stored for finished root=true holding 1 vulnerabilities
BUG(late-child-span-after-finish): SQLi on a tainted request parameter was committed=true but no finished span carries an IAST event
--- FAIL: TestFxLateBindAfterRootFinish/late-child-span-after-finish
real tracer meta_struct available = true
WARNING: DATA RACE  (30 reports)
  Write ... (*Span).setMetaStructLocked() span.go:865 <- SetMetaStruct span.go:471 <- spans.Finished() orchestrion.go:44 <- (*Span).Finish() <generated>:8 <- deferred root.Finish()
  Previous read ... (*metaStructMap).EncodeMsg() meta_struct.go:25 <- payloadV04.push <- processOutChunk tracer.go:909
  Read ... model.(*Event).MarshalMsg() <- metaStructMap.EncodeMsg meta_struct.go:37  vs  Previous write ... (*Annotation).TryCommitTainted() tainted.go:128 <- sql.Report <- (*DB).ExecContext
--- FAIL: TestFxDoubleFinishRace ... race detected during execution of test
```
The build's peak RSS was 409 MB.

**Second pass (fresh private copy):** the same command gives `evidence/fx-life-spans-F2/rerun.out.txt` (EXIT=1, peak RSS 418 MB). It reproduces F2 exactly: `mode=late-child-span-after-finish emitted vulnerabilities=0; open annotation still stored for finished root=true holding 1 vulnerabilities`, while both controls emit 1. It also reproduces the F3 metaStruct race: `setMetaStructLocked span.go:865 <- SetMetaStruct span.go:471 <- spans.Finished orchestrion.go:44 <- deferred root.Finish` against `metaStructMap.EncodeMsg meta_struct.go:25 <- processOutChunk tracer.go:909`. The Event-content race did not recur on this run; it is timing-dependent.

**Causality controls** (`zz_fx_life_spans_f2_ctl_test.go`, same real tracer and meta_struct agent, 20 requests each, `-run '^TestFxCtl'` gives `ctl.out.txt`, EXIT=0, no `DATA RACE`):
- `TestFxCtlDoubleFinishNoLateBind`: sink before Finish, then two Finish calls. No race, because the second `Finished` finds no entry and returns.
- `TestFxCtlSingleFinishLateBind`: Finish, then a late child span and the sink, with no second Finish. No race; the finding is simply lost (F2).

So F3 needs exactly F2's re-created annotation plus a repeated Finish. I did not re-run the finder's internal-API reproducers. They exercise the same mechanism through `spans.BindScope` and `vulnerability.Report`, and their recorded outputs match what I observed.

## Reachability
- **F2** needs the root span to finish while its request scope is still active, followed by a new span (or weak-hash report) derived from that root's context and then a tainted sink. dd-iast-go's `orchestrion.tool.go` weaves only `ddtrace/tracer` and no dd-trace-go net/http server integration. In that setup the customer's first `StartSpanFromContext(r.Context(), ...)` becomes the request root, which is also the repository's e2e pattern. A handler that finishes one step span and then keeps using the ctx it returned (`span, ctx := tracer.StartSpanFromContext(ctx, "auth"); ...; span.Finish(); child, ctx := tracer.StartSpanFromContext(ctx, "query"); db.ExecContext(ctx, q)`) is ordinary Go tracing code, and it reproduces the bug under default settings for any sampled request. With the dd-trace-go HTTP server integration, the server span is the root and finishes only just before the scope. The window then shrinks to goroutines spawned by the handler that start spans during that gap, so reachability is still possible but rare.
- **F3** additionally needs a second `Finish` on the root, and an agent that advertises `span_meta_structs`, which current Datadog agents do. The `defer span.Finish()` safety net combined with an explicit early `span.Finish()` is a common pattern, and dd-trace-go explicitly supports it. With an older agent, the JSON fallback uses `SetTag`, which ignores finished spans, so the result is loss only and no race. The race is not a memory-model technicality: the writer can serialize an `Event` while it is being mutated. If the root already had a non-nil meta_struct map, for example from AppSec, a `_dd.stack` entry, or the first annotation's event, the same write could become a concurrent map write during iteration. That is an unrecoverable fatal error, but I did not reproduce the fatal error itself.
- **Documented?** No. README and 01-design-intent.md exclude only taint retained *after the origin request finishes*. Here the scope is still active and the source is a supported HTTP parameter feeding a supported SQL sink. F2 breaks rule 4 (provenance), and F3 breaks rule 1 (no data race in the host).

## Adjusted severity
- life-spans-F2: **High** (unchanged). A supported source-to-sink finding is silently lost while the code reports success, and dedup then suppresses the same finding for up to an hour; the impact is data loss only, with no crash.
- life-spans-F3: **Critical** (unchanged). A reproduced data race in production code on the host's trace writer, reachable from ordinary customer code with a modern agent.
- The two findings are not duplicates, but they share **one root cause**: F3 is F2's re-created annotation plus a repeated Finish.

## Root cause (file:line)
- internal/spans/orchestrion.go:28: `store.LoadAndDelete(weak.Make(span))` leaves no marker that the root was finished.
- internal/spans/annotation.go:190-205 (`BindScope`) and 134-142 (`AnnotationFor`): `LoadOrCompute` creates an annotation for any root, whether or not it has finished.
- internal/spans/orchestrion.go:39-46: nothing records that a root already flushed once, so a later Finish writes meta_struct/tags on a finished span. The upstream `setMetaStructLocked` also has no `finished` guard (dd-trace-go span.go:862-866).

## Minimal fix
1. In `Finished`, close the annotation and replace it with a shared closed tombstone (for example `store.Store(key, finishedTombstone)`) instead of deleting it. `BindScope` and `AnnotationFor` must treat a closed existing entry as "no annotation", so callers take the orphan path. `trimStore`/`releaseDeadAnnotation` reap tombstones once the weak key dies. Tombstones should be excluded from the `MaxConcurrentRequests` count, for example with an atomic count of live entries, so that finished-but-not-yet-GC'd roots do not worsen the life-spans-F1 slot starvation.
2. Defense in depth: `Finished` returns immediately when the loaded entry is already closed, so the prologue never calls `SetMetaStruct`/`SetTag` after the root's first Finish. Report the missing finished guard in `SetMetaStruct` to dd-trace-go.
3. Add regression tests: the two woven tests in the evidence directory, with the late-child case asserting that the finding is emitted (on an orphan span) and the race test staying clean under `-race`.

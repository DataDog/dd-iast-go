# fx-store-memory-bounds-F2: verification of store-memory-bounds-F2

Target: HEAD `2e23b46`, go1.26.6 darwin/arm64. Evidence: `.omo/review/evidence/fx-store-memory-bounds-F2/`. The evidence comes from two runs of this node: an interrupted run at 16:36 (logs 01-04 `natural-*` and `finder-patched-replay`, with `zz_fx_f2_test.go`) and this run (`01-noPatch-admission.txt` and `02-finder-barrier-rerun.txt`, with `zz_fx_f2_admission_test.go`). The two test files each define `fxHeap`, so copy only one at a time.

## Verdict per finding

| id | Verdict | Original | Adjusted |
| --- | --- | --- | --- |
| store-memory-bounds-F2 | CONFIRMED (mechanism, and the cap is exceeded without any patch). The "unbounded growth" framing is overstated. | Critical | High |

The check-then-insert race is real. `trimStore()` reads `store.Size()` (`annotation.go:231,235`), and only then, holding no reservation, does `LoadOrCompute` insert (`:135-142`, and `:200-205` in `BindScope`). Every caller that reads the size before the map fills inserts its own entry. `xsync.Map` has no size ceiling; the presize at `:31` is only a hint. There are two corrections to the finding. First, the excess is not growth over time. It is bounded by how many live root spans are inside the window at the same moment, and every entry is removed at `Finished(span)` (`orchestrion.go:27-28`). Second, it is not a data race: `-race` is clean.

## Reproduction

Setup: `rsync -a --exclude .git --exclude .omo <repo>/ /tmp/ddiast-review/wt/fx-store-memory-bounds-F2/`, then copy one of the repro files into `internal/spans/`.

**A. My patch-free burst, through the production entry points** (`repro/internal/spans/zz_fx_f2_admission_test.go`). The test holds N root spans live. On the request path, each context goes through `request.BeginContext`, exactly like the woven `application.http.Handler` advice at `iast/net/http/orchestrion.yml:100-121`. A start channel releases the goroutines together, before any of them calls `BindScopeContext` or `AnnotationFor`. Nothing pauses inside the production window. The test runs 40 trials and reports the maximum occupancy.

```
env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 [DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64] timeout 900 \
  go test [-race] [-cpu 16,256] -count=1 -timeout 12m -v -run '^TestFxF2AdmissionNoPatch$' ./internal/spans
```

Key lines (`01-noPatch-admission.txt`):
- Default config (cap 2, 30% sampling): `BindScopeFromContext ... configured=2 inflight=256 trials=40 maxRetained=11 ratio=5.5x meanRetained=3.4 meanSampled=0.3`
- `AnnotationFor ... configured=2 inflight=256 maxRetained=5 ratio=2.5x meanSampled=0.8`
- Cap 64, 100% sampling: `GOMAXPROCS=16 ... maxRetained=67` on every path, and `GOMAXPROCS=256 ... AnnotationFor inflight=256 maxRetained=70 ratio=1.1x meanSampled=65.3`
- `-race` at default: maximum 6 against cap 2, `PASS` with no `WARNING: DATA RACE`
- In every trial, finish drained the map to 0 (asserted).

**B. The earlier run's harness** (`zz_fx_f2_test.go`, logs `01-03-natural-*`). A real `httptest` server whose handlers run the woven advice sequence held the map at exactly the cap in all 15 trials per configuration (`storedAnnotations=2` or `64` with 64, 256, or 1024 concurrent requests). Burst and near-capacity runs reached at most 4 against cap 2, and 67 against cap 64.

**C. The finder's barrier reproducer** (their scheduling-only patch applied in my copy, `02-finder-barrier-rerun.txt`) gave `inflight=128 retainedAnnotations=128`, `512 -> 512`, and `2048 -> 2048 ... delta=7585792 sourceCharge=0`, exit 0. That matches the reported numbers.

I did not run a woven build. The defect is in internal span storage, not in a hook. Harnesses A and B run the advice's call sequence verbatim against the real `request` and `spans` packages. A woven build would add only the `Span.Finish` hook, and the harness calls that hook's body `Finished(span)` directly.

## Reachability

- **Default config reaches it.** `config.Enabled` defaults to true, sampling to 30, and `MaxConcurrentRequests` to 2 (`config.go:74`). Every handler invocation creates a scope, sampled or not (`request/scope.go:79-103`), and calls `BindScopeContext` (`orchestrion.yml:120`), so ordinary concurrent traffic enters the racy `BindScope` path. Scope-less findings (a span in the context but no request scope) use `AnnotationFor` through `vulnerability/report.go:51`. Request permits bound neither path.
- **The natural excess is small in bytes but large relative to the cap.** A synchronized burst produced 11 entries against cap 2 (5.5x). Real HTTP serving produced none. The window is short (from `store.Size()` through `weak.Make` to one map insert), so a large excess needs many goroutines descheduled inside it at once. That can happen legally through preemption, GC, or CPU oversubscription, and the barrier run in C shows the code sets no limit. Each entry is 3,200 bytes.
- **The excess is transient.** Each entry corresponds to one live customer root span, whose own goroutine and HTTP state are much larger, and is released at span finish or by weak-key trim. Nothing accumulates under steady load.
- **Sampling of excess entries.** Excess entries on the HTTP `BindScope` path are mostly unsampled shells (`Sampled: scope.Active()`, and active scopes are permit-capped), so they hold no events. Excess entries on `AnnotationFor` are sampled (`meanSampled=65.3` against cap 64) and can each hold up to 64 vulnerabilities. That multiplies the per-event retention of store-memory-bounds-F3 by the excess.
- **Documented?** No. `README.md:116` presents the setting as a concurrency cap, and `01-design-intent.md` says nothing on annotation admission. The race breaks product rule 3: IAST storage has no constant maximum.

## Adjusted severity

High. Without any patch, the configured annotation cap was exceeded by a large factor (5.5x at default config), and the code sets no limit on the excess. It is not Critical: the excess tracks live host concurrency, is released at span finish, never grows over time, and is not a data race.

## Root cause (file:line)

- `internal/spans/annotation.go:132`: `hasSpace := trimStore()` is a snapshot taken outside the insert at `:135-142`.
- `internal/spans/annotation.go:199-205`: the same pattern in `BindScope`, the production HTTP path.
- `internal/spans/annotation.go:227-236`: `trimStore` compares `store.Size()` with `config.MaxConcurrentRequests` and holds no reservation.

## Minimal fix

Keep an `atomic.Int32` count of live annotations and reserve a slot before insertion: `if used.Add(1) > cap { used.Add(-1); trim once and retry, or drop }`. Inside the `LoadOrCompute` callback, keep the slot only if this call actually inserted, and give it back when another goroutine won the key. Decrement after a successful `LoadAndDelete` in `Finished` and in `releaseDeadAnnotation` when it deletes. This makes the count a hard bound using only cheap atomics. Re-checking `store.Size()` inside the callback is not enough, because it is not atomic across buckets. A separate issue for a provenance node, not triaged here: `BindScope` stores negative decisions in the same capped map, so unsampled requests can take the slots and leave permit-holding requests without an annotation, which drops their findings.

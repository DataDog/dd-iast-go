# fx-hooks-panic-safety-F2: native Buffer invalidation can abort the original write

## Verdict per finding
- **hooks-panic-safety-F2: CONFIRMED (mechanism). Severity downgraded from Critical to Medium.** The native `bytes.Buffer` prepend advice does run an unrecovered IAST callback before the host method body. If that callback panics, the host `Write`/`WriteString` is aborted and the IAST panic value reaches customer code. Only fault injection shows this. No natural panic source exists in the real callback path (static read plus a woven concurrent stress run with 0 panics), so no customer input can currently trigger it. That is a missing containment guard, not a reachable crash.

## Reproduction
Private copy of HEAD 2e23b46, Go 1.26.6, woven with Orchestrion. Evidence is in `.omo/review/evidence/fx-hooks-panic-safety-F2/`.

Setup:
- `zz_fx_f2_test.go` goes in `iast/propagation/`.
- `zz_review_fault.go` goes in `internal/taint/store/`.
- `store_writer_fault_hook.diff` is a scratch fault switch applied to the real `Store.InvalidateBuffer` in the private copy only:
  - mode 1 panics before any lock;
  - mode 2 panics after `lifecycleMu.TryRLock` and `writersMu.TryLock`.

Unlike the finder, who replaced the registered callback, my test keeps the production callback chain (`writerbridge.invalidateSlow`, then `propagation.invalidateBuffer`, then `Store.InvalidateBuffer`). It drives it with customer-shaped code: plain `buf.WriteString(...)` calls and an `io.Writer` interface write inside an active `request.Begin` scope, with no direct `propagation.*` calls.

Command:
```
GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 15m -count=1 -run 'TestFX_F2_' ./iast/propagation -v
```
Key output lines (`woven-go1.26.6-run2.out.txt`):
```
control: out="SELECT * FROM t WHERE a='attack'" caught=<nil> tainted=true            (PASS: weaving and taint active)
mode=1 iface=false: out="" caught=*struct { origin string } &{injected fault inside Store.InvalidateBuffer} identical=true
mode=1: IAST-internal panic escaped customer bytes.Buffer.WriteString (write aborted, out="")
mode=2 iface=false: out="SELECT * FROM t WHERE a='attack'" caught=<nil>            (locked region not reached: wrapped direct write sets preserve and skips its own entry)
mode=1 iface=true:  ... identical=true ... write aborted
mode=2 iface=true:  ... identical=true
mode=2: scope.Finish BLOCKED >3s (lifecycleMu RLock leaked by panic)
natural stress: goroutines=16 iterations=300 panics=0                              (PASS, no fault injection)
```
(The fixed log text says `WriteString`, but in the iface variants the aborted method is `Buffer.Write`.) Peak RSS was 362 MB (first, uncached woven build: 259 s real). Finder's reproducer rerun: `TestReview_InternalBufferInvalidationCannotPanicHost` FAIL with `IAST-only panic escaped bytes.Buffer.WriteString ... identical=true` (`finder-repro-rerun.out.txt`). Go 1.27.0 was not rerun: the code path is pure Go with no toolchain-dependent behavior, and the machine was heavily loaded.

## Reachability
- **Host surface: real and default-on.** `iast/propagation/orchestrion.yml:1553-1680` prepends `iastwriterbridge.Invalidate(...)` into `*bytes.Buffer` `Write/WriteString/WriteByte/WriteRune/Grow/ReadFrom`, `Reset/Truncate`, and 10 read or exposure methods, for every caller in the woven binary (stdlib and dependencies included). It runs whenever `writerbridge.Active()` is true, meaning at least one sampled request retains writer state. The slow path `invalidateSlow` (`internal/taint/writerbridge/bridge.go:84-96`) calls `callback.invalidate` with no `recover`.
- **Trigger: not naturally reachable.** The only registered callback is `propagation.invalidateBuffer` (`internal/taint/propagation/writer.go:17-37`), which calls `Store.InvalidateBuffer` (`internal/taint/store/writer.go:366-399`). That path uses only fixed-array loops (`range s.owners`, `index < MaxWriters`), atomics, `TryRLock`/`TryLock` with drop-on-contention, and bounds-checked `removeWriterLocked`/`clearDirtyWritersLocked` (`writer.go:498-526`, where `writerCount <= MaxWriters = 8`). I found no nil dereference, unchecked index, map, or allocation that could panic. The woven 16-goroutine stress test ran with no fault injection and covered every Buffer method class, value copies sharing a backing, more than MaxWriters buffers per owner, cross-request shared buffers, `WriteTo`/`ReadFrom`, and writes after `Finish`. It produced 0 panics.
- **Documented?** No. README and `01-design-intent.md` list "preserve application ... panics" and "drop IAST provenance rather than block or change host behavior" as host-safety priorities, and the sibling bridges do contain callback panics (`sqlbridge/bridge.go:60`, `commandbridge/bridge.go:51`, `jsonbridge/bridge.go:241`). The writer bridge is inconsistent with that policy. The gap would violate product rule 1 only if an internal bug is introduced later.

## Adjusted severity
**Medium** (was Critical). This is a missing guard on a pervasive, stdlib-wide hot hook, and it amplifies any future internal bug into a host panic, or a request hang (see below). The Critical bar (a crash reachable from customer code) is not met, since no input reaches a panic in the real callback. Rating it Medium rather than Low reflects the blast radius (every `bytes.Buffer` in the process) and the lock-leak amplification my reproducer uncovered.

## Root cause (file:line)
- `internal/taint/writerbridge/bridge.go:93-95`: `callback.invalidate(pointer, backing, capacity, expected)` runs without a panic boundary, and it is reached before the host method body from the prepend advice at `iast/propagation/orchestrion.yml:1553-1680`.
- Amplifier: `internal/taint/store/writer.go:375-398` uses manual (non-deferred) `writersMu.Unlock()` / `lifecycleMu.RUnlock()` after `TryLock`. A panic between lock and unlock leaks the read lock, and then `Owner.Finish` (`internal/taint/store/owner.go:165`, a blocking `lifecycleMu.Lock()`) hangs the request goroutine (reproduced: `scope.Finish BLOCKED`).

## Minimal fix
1. In `invalidateSlow`, run the callback through a small helper that recovers IAST-only panics, for example `func callSafe(cb *callback, ...) { defer func() { _ = recover() }(); cb.invalidate(...) }`. This keeps the defer off the `Active()` fast path, since `invalidateSlow` is already `//go:noinline`. The native Buffer method stays outside the helper, so genuine host panics pass through unchanged.
2. A recover alone is **not** sufficient. In `Store.InvalidateBuffer`, release `writersMu`/`lifecycleMu` via `defer` in a per-owner helper (or recover inside that helper and unlock), and on failure set `record.writerDirty.Store(true)` so the provenance is conservatively dropped. Otherwise the recovered panic turns into a `Finish` deadlock.
3. Optionally, have the recovering helper also clear the expectation marker (`consume` has already run, so no marker is leaked on this path).

# fx-prop-owner-isolation-F1: verification of prop-owner-isolation-F1 (analysisSlot.index race)

## Verdict per finding
- **prop-owner-isolation-F1: CONFIRMED.** Original severity Critical, adjusted severity Critical. The plain store at `internal/taint/request/owner.go:82` (`slot.index = uint8(index)`) and the plain load at `internal/taint/request/http.go:33` (`index: slot.index`) are not ordered by any happens-before edge when the reader is a goroutine the request does not join. I reproduced it independently in three ways: the internal API on Go 1.26.6, the internal API on Go 1.27.0, and a **woven customer-style HTTP server with default IAST config** through `go tool orchestrion go test -race`. The written value is always the same, so binaries built without `-race` behave correctly. The only effect is a race-detector report.

## Reproduction
All runs used the private copy at HEAD 2e23b46 with `GOFLAGS=-p=4`. The reproducers are in `.omo/review/evidence/fx-prop-owner-isolation-F1/`.

1. **Woven, default config (the most realistic surface).** `zzfxrepro_repro_test.go` is ordinary customer code with no dd-iast imports and no config overrides, so the defaults apply: enabled, 30% sampling, 2 concurrent analyses. It starts an `httptest` server whose handler spawns a fire-and-forget audit goroutine `go func(){ _ = len(r.URL.Query()) }()`, does some CPU work, and returns. A client sends 3,000 sequential GETs to `/audit`.
   `mkdir zzfxrepro && cp .omo/review/evidence/fx-prop-owner-isolation-F1/zzfxrepro_repro_test.go zzfxrepro/repro_test.go && GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -race -run '^TestFxWovenDetachedQuery$' -count=1 -v ./zzfxrepro`
   Output (`woven-detached-query-race-go1.26.6.out.txt`), exit 1:
   - `WARNING: DATA RACE / Write at 0x00c001280018 by goroutine 18: request.(*Manager).Acquire() owner.go:82 <- request.begin() scope.go:95 <- BeginServerContext <- httpbridge.Begin() bridge.go:77 <- net/http.serverHandler.ServeHTTP() <generated>`
   - `Previous read at 0x00c001280018 by goroutine 42: request.analysisForOwner() http.go:33 <- ManageURLQuery() lazy.go:37 <- urlbridge.Query() bridge.go:30 <- net/url.(*URL).Query.func1() <generated> <- zzfxrepro.handler.func1() repro_test.go:22`
   - `testing.go:1712: race detected during execution of test / --- FAIL: TestFxWovenDetachedQuery (0.93s)`
   - Build and run took 145 s wall time with a peak RSS of 363 MB, well under the 4 GB threshold.
2. **Internal API, one detached goroutine per request, MaxConcurrentRequests=2.** This is different from the finder's single long-lived poller.
   `cp .omo/review/evidence/fx-prop-owner-isolation-F1/request_zz_fx_slotindex_test.go internal/taint/request/zz_fx_slotindex_test.go && GOTOOLCHAIN=go1.26.6 go test -race -run '^TestFxSlotIndexRaceURLQuery$' -count=1 -v ./internal/taint/request`
   - Go 1.26.6 (`internal-urlquery-race-go1.26.6.out.txt`): `WARNING: DATA RACE ... owner.go:82 ... http.go:33 ... lazy.go:37`, then `--- FAIL: TestFxSlotIndexRaceURLQuery (0.09s)`.
   - Go 1.27.0 (`internal-urlquery-race-go1.27.0.out.txt`): the same stack, then `--- FAIL (0.14s)`.
3. **The `ReadAllBytes` path did not race in my run** (`internal-readall-norace-go1.26.6.out.txt`, PASS). This is expected, and it narrows the finder's claim. When the owner is still active after `analysisForOwner`, `adoptBodyBytes` takes `sourceMu` with a successful `TryLock`/`Unlock`. `Analysis.Finish` later takes `sourceMu.Lock()` before `used.And`, which creates a happens-before edge to the next `Acquire`. `ReadAllBytes` and `CloneReaderBytes` race only if the owner finishes between `analysisForOwner` and the `Active()` check in `adoptBodyBytes`, which is a narrow window. `ManageURLQuery` races easily, because with an empty query `manageMap` returns before taking any lock (lazy.go:167). With a non-empty query it races only when the `TryLock` in `ManageString` fails or the owner has gone inactive.
4. **Fix check** (`fix-verify-go1.26.6.out.txt`). With the minimal fix below applied in the private copy, both fx tests pass 3/3 under `-race`, and the whole `./internal/taint/request` package passes under `-race`.

## Reachability
- **Default configuration: yes.** The woven reproducer changes no config. `serverHandler.ServeHTTP` reuses a permit about every 3 requests at 30% sampling with a limit of 2, and each reuse re-executes owner.go:82.
- **Trigger:** a goroutine that is *not joined* before the handler returns and calls `r.URL.Query()` while the request's owner is live. Async logging, audit, and metrics goroutines are common and valid net/http usage, because the server does not reuse `*http.Request`. A goroutine that is joined, for example with `wg.Wait` or a channel receive before return, orders the read before `Finish` and does not race. Neither does a normal `Query()` call on the handler goroutine, since its read is sequenced before the `used.And` in its own `Finish`, and the next `Acquire`'s CAS observes that store.
- **Impact:** only builds with `-race`. The race detector prints a report blaming dd-iast internals and makes the test binary fail (`race detected during execution of test`, exit 66 for binaries). Customers who run `orchestrion go test -race` or race-enabled canaries hit it even if their own code is race-free. A production build without `-race` computes the same `uint8` value, and the byte store cannot tear. There is no wrong result, panic, or provenance error.
- **Documented limitation: no.** Neither the README nor `phase1/01-design-intent.md` mentions it. It also contradicts the design intent that the slot fields read lock-free are atomics (see the architecture map's concurrency table).
- **Toolchains:** reproduced on Go 1.26.6 and Go 1.27.0.

## Adjusted severity
**Critical, unchanged.** It is a reproduced data race in production code, reachable from ordinary woven customer code under default config, and the brief's scale lists that as Critical. The practical impact is lower than a typical Critical: it only affects `-race` builds and never changes results, so a triager could reasonably treat it as the least severe Critical. It is also a one-line fix.

## Root cause (file:line)
- `internal/taint/request/owner.go:82`: `slot.index = uint8(index)` is a plain write on every `Acquire`, after the permit CAS. The CAS orders it only against the previous holder's `used.And`, not against readers from other goroutines.
- `internal/taint/request/http.go:33`: `index: slot.index` is a plain read in `analysisForOwner`, reached from `ManageURLQuery` (lazy.go:37), `CloneReaderBytes` (reader.go:57), and `ReadAllBytes` (reader.go:79) on arbitrary goroutines. The reader's `directory[ownerIndex].Load()` only synchronizes with the *previous* `Acquire`'s `directory.Store`. Nothing orders the read before the *next* `Acquire`'s write unless the reader later touches `sourceMu`.
- `index` is a pure function of the slot's position in `m.slots`, so it never needs rewriting.

## Minimal fix
Make `index` immutable. Initialize it once in `NewManager`, which happens before the manager is published through `processManager`, and delete the write in `Acquire`. Verified in the private copy (`fix-verify-go1.26.6.out.txt`):
```go
-	return &Manager{store: taintStore}
+	m := &Manager{store: taintStore}
+	for i := range m.slots {
+		m.slots[i].index = uint8(i)
+	}
+	return m
 ...
 	slot := &m.slots[index]
-	slot.index = uint8(index)
```
`Manager` is only constructed through `NewManager`; the only `Manager{}` literal is a `unsafe.Sizeof` in a test. Keep `request_zz_fx_slotindex_test.go`'s URL-query case as a `-race` regression test. It fails at HEAD and passes with the fix.

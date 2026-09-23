# life-admission: request sampling and concurrent admission
Verdict: One High slot-retention defect: a disconnected request can hold an IAST permit indefinitely when its handler does not return; normal return, panic unwind, and tested HTTP protocol dispatch release permits.
Scope covered: `internal/taint/request/{scope.go,owner.go,scope_test.go,owner_test.go,http.go,reader.go}`, `internal/taint/httpbridge/bridge.go`, `internal/taint/store/owner.go`, `internal/config/{config.go,init.go}`, `internal/spans/{annotation.go,annotation_sampling_test.go,owner.go,orchestrion.go,orchestrion.yml}`, `internal/vulnerability/report.go`, `iast/net/http/{orchestrion.yml,http.go,http_test.go}`; Go 1.26.6 `net/http/server.go`; woven HTTP/1 and HTTP/2 reproducer and existing protocol/lifecycle tests.

## Findings

### life-admission-F1: Disconnected stalled handlers retain admission slots indefinitely
- Severity: High
- Category: leak
- Location: `iast/net/http/orchestrion.yml:27-33`; `internal/taint/request/scope.go:121-133,209-222`
- Claim: The only automatic release is the `serverHandler.ServeHTTP` defer, so cancellation of `Request.Context()` after a client disconnect does not release the analysis if a long-polling, streaming, or blocked handler remains in `ServeHTTP`. With `DD_IAST_MAX_CONCURRENT_REQUESTS=1`, every subsequent request is `DecisionCapacityDropped`; with the default limit of two, two such handlers can leave IAST disabled for all later requests until they return. This is distinct from the intended capacity limit on *live* requests: the test confirms the client is gone and the server context is canceled before probing admission. Both HTTP/1 and HTTP/2 exhibit the defect.
- Evidence: `.omo/review/evidence/life-admission/zz_life_admission_test.go` and `.omo/review/evidence/life-admission/disconnect.out.txt`. Copy the test into `iast/net/http/` of a private checkout and run `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test ./iast/net/http -run TestLifeAdmissionDisconnect -count=1 -v -timeout 4m`. Both subtests log `disconnected request still owns the single IAST slot` followed by `subsequent request decision=2 (Active=3, CapacityDropped=2)` and fail the active-admission assertion. The test uses channels to observe cancellation before issuing the probe and releases the blocked handler during cleanup.
- Fix: Register a cancellation-triggered, idempotent finish for each created request scope, stopping that registration on normal finish. Retain the existing deferred finish for normal return, panic, and hijack return; cancellation must invalidate the owner and release its permit without waiting for application handler return.

## Checked and found correct

- Configuration loads a 30% default sampling rate and two concurrent analyses (`internal/config/config.go:68-70`); `sampleDecision` uses `rand.IntN(100) < percent`, yielding 30 winning integers out of 100 before the independent capacity check (`internal/taint/request/scope.go:73-103,148-158`). Zero and 100% take deterministic branches, and sampled-out requests never call `Acquire`.
- `Manager.Acquire` CASes one of the configured permit bits and clears it on both store-acquisition failure paths; `Analysis.Finish` clears it after owner cleanup. A stale analysis cannot finish a reused generation (`internal/taint/request/owner.go:57-103,257-273`). `Scope.Finish` removes its handle under the scope lock before finishing, so concurrent finishes do not release a reused permit (`scope.go:209-222`).
- Nested handler/middleware boundaries reuse the context scope and do not perform a second finish. The woven `TestDirectNestedAndPanicLifecycle` passes, including recovery after a handler panic; `serverHandler`'s deferred finish also executes on unwind before `net/http` recovers the panic (`iast/net/http/orchestrion.yml:27-33,88-112`).
- `TestServerProtocolsReleasePerRequest` passes for HTTP/1, TLS HTTP/2, and h2c on repeated requests with capacity one. `TestH2CUpgradeDoesNotOwnConnectionScope` passes; the connection upgrade is filtered and its stream receives a fallback scope. A normal HTTP/1 hijack whose handler returns also traverses the same deferred finish: Go 1.26.6 `net/http/server.go` calls `serverHandler.ServeHTTP` before checking `c.hijacked()` (lines 2067-2073). A hijacked handler that continues serving websocket traffic retains its slot for its handler lifetime.
- Existing targeted woven command passed: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test ./iast/net/http -run "TestDirectNestedAndPanicLifecycle|TestServerProtocolsReleasePerRequest|TestH2CUpgradeDoesNotOwnConnectionScope" -count=1 -v -timeout 4m`.

## Not covered / open questions

- No separate websocket implementation was exercised. Synchronous websocket handlers that do not return remain admitted until return, which is consistent with the current handler-lifetime boundary; whether websocket traffic should have a separate admission policy is a product decision.
- The random generator's statistical distribution was not measured; the 30/100 decision and nested-scope reuse were checked from code, while the end-to-end reproducer set sampling to 100% to isolate admission.

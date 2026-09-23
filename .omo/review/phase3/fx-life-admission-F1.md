# fx-life-admission-F1: Disconnected stalled handlers retain admission slots indefinitely

Verdict: CONFIRMED — independently reproduced on a woven build (Go 1.26.6) with my own
reproducer, for HTTP/1 (real raw-socket disconnect) and HTTP/2 (client cancel). Severity
High is correct.

Scope covered: `iast/net/http/orchestrion.yml:16-45`; `internal/taint/httpbridge/bridge.go`;
`internal/taint/request/scope.go` (begin, Finish); `internal/taint/request/owner.go`
(Acquire/Finish); `internal/config/config.go`; Go 1.26.6 `net/http/server.go` ServeHTTP path.

## Verdict per finding

### life-admission-F1 — CONFIRMED (severity High, unchanged)

- The claimed mechanism is real. The ONLY release path for an analysis permit is the
  deferred `iasthttpbridge.Finish(__dd_iast_ctx, __dd_iast_created)` woven at the start of
  `net/http.serverHandler.ServeHTTP` (`iast/net/http/orchestrion.yml:27-33`, template
  `defer iasthttpbridge.Finish(...)`). `Scope.Finish`
  (`internal/taint/request/scope.go:209-222`) is the only code that clears `s.analysis` and
  calls `analysis.Finish()` (which frees the manager permit bit). Nothing anywhere in
  `scope.go`, `httpbridge/bridge.go`, or the woven template watches
  `context.Context.Done()`; `begin` (`scope.go:73-133`) never registers a cancellation
  callback. So when the client disconnects and `req.Context()` is canceled by `net/http`,
  a handler still executing in `ServeHTTP` keeps its permit until it returns.
- This matches the brief's severity scale exactly: "a permanent IAST self-disable (for
  example a leaked admission slot)" is listed under High. It is not Critical: the host
  application is unaffected (no panic/deadlock/behavior change), the slot is recovered when
  the stalled handler eventually returns, and IAST degrades by dropping analyses (its
  designed failure mode), not by breaking the host.
- Not a documented limitation: README documents `DD_IAST_MAX_CONCURRENT_REQUESTS` as
  "Maximum number of requests that IAST processes concurrently" (README.md:116) and
  `01-design-intent.md:65` frames the limit as concurrent *analyses*; neither documents
  retention after disconnect/cancellation. IAST silently disabling itself for all later
  requests violates the spirit of product rule 3 ("data is dropped when saturated" — here
  capacity is consumed by requests with no remaining client) and makes the configured
  concurrency limit wrong under ordinary load.

## Reproduction

Private copy at `/tmp/ddiast-review/wt/fx-life-admission-F1` (removed after verification).
My own reproducer (independent of the finder's): `.omo/review/evidence/fx-life-admission-F1/zz_fx_life_admission_test.go`,
placed in `iast/net/http/` of the private copy, run with:

```
GOTOOLCHAIN=go1.26.6 go tool orchestrion go test ./iast/net/http \
  -run "TestFxDisconnectSlotRetention|TestLifeAdmissionDisconnect" -count=1 -v -timeout 4m
```

(full captured output: `.omo/review/evidence/fx-life-admission-F1/fx_repro_go1.26.6.out.txt`;
peak RSS of the woven build was ~0.37 GB, well under limits)

Key output lines of MY reproducer (`TestFxDisconnectSlotRetention`):

```
CONFIRM-SIGNAL: after raw-socket disconnect was observed server-side, scope still Active (holds the only slot)
probe decision after disconnect = 2 (Disabled=0 SampledOut=1 CapacityDropped=2 Active=3)
FAIL-SIGNAL: disconnected request retains the slot; subsequent request capacity-dropped (got 2, want 3)
CONFIRM-SIGNAL: after client cancel (HTTP/2), scope still Active
probe decision after cancel = 2
```

Differences from the finder's test: my HTTP/1 case uses a REAL client disconnect (raw
`net.Dial`, request written, socket closed) rather than only a context cancel, and asserts
the handler has observed `req.Context().Done()` (server knows the client is gone) before
probing admission; the probe must then return `DecisionActive`. Both subtests fail exactly
as the finding predicts: the scope is still `Active()` after the disconnect is observed
server-side and the subsequent probe gets `DecisionCapacityDropped`. With
`DD_IAST_MAX_CONCURRENT_REQUESTS=1` (as in the test) IAST is fully disabled for later
requests while the stalled handler lives; with the default of 2, two such handlers do the
same. The finder's reproducer (`TestLifeAdmissionDisconnect`, copied in for cross-check)
also fails identically on both protocols.

## Reachability

- Reachable under default configuration: sampling 30% + max 2 concurrent (README.md:116).
  Ordinary customer code — SSE/streaming, long-poll, or any handler blocked on a slow
  upstream call while the client goes away — holds its slot for the handler lifetime. Two
  concurrent disconnected stalled handlers disable IAST analysis for every later request
  until they return. Handlers that do watch `ctx.Done()` and return promptly are fine; the
  defect needs handlers that outlive their client, which is common.
- Toolchain: reproduced on Go 1.26.6 (the targeted toolchain). A Go 1.27.0 woven build
  currently fails for an unrelated reason (`encoding/json` hook accesses removed
  `Decoder.r`/`Decoder.d` fields), so 1.27.0 reachability could not be exercised; the
  mechanism itself (defer-only release, no cancellation watcher) is toolchain-independent.
- `documented_limitation`: false (checked README.md and phase1/01-design-intent.md).

## Adjusted severity

High (unchanged). One-line: a permanent-until-handler-return IAST self-disable via leaked
admission slots on a common, supported path — the brief's own example of High.

## Root cause

- `iast/net/http/orchestrion.yml:27-33` — the woven `defer iasthttpbridge.Finish(...)` in
  `serverHandler.ServeHTTP` is the sole release trigger.
- `internal/taint/request/scope.go:73-133` (`begin`) — no `context.AfterFunc`/`Done()`
  registration; `scope.go:209-222` (`Finish`) — only deferred-call path releases the permit.

## Minimal fix

At scope creation in `begin` (after a permit is acquired), register an idempotent
cancellation release, e.g. `stop := context.AfterFunc(ctx, scope.Finish)` and have
`Scope.Finish` call `stop()` first (it is already idempotent and lock-safe: it snapshots
and clears `s.analysis` under `s.mu`, so the second caller observes an empty `Analysis` and
does not double-release the permit). Keep the existing deferred finish for normal return,
panic unwind, and hijack paths. Trade-off (acceptable): after cancellation-triggered
release, a still-running stalled handler can no longer report — analysis data is dropped,
which is this codebase's stated preference under saturation.

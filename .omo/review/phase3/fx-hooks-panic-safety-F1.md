# fx-hooks-panic-safety-F1: verification of hooks-panic-safety-F1

## Verdict per finding
- **hooks-panic-safety-F1: CONFIRMED (mechanism), severity downgraded Critical -> Medium.**
  `iobridge.Propagate`/`ReadAll` (internal/taint/iobridge/bridge.go:30-42) call the registered callbacks with no recover, and the woven `io.LimitReader`/`TeeReader`/`MultiReader`/`ReadAll` defers (iast/io/orchestrion.yml:27,44,66,85) call them directly. So any panic inside IAST reader bookkeeping reaches the host. The claim is only about **containment**. Neither the finder nor I found a natural input that makes the real callbacks (`request.PropagateReader`, `request.ReadAllBytes`) panic. Triggering the defect needs a second, currently unknown IAST bug.

## Reproduction
Private copy of HEAD 2e23b46, woven with Orchestrion, Go 1.26.6. My reproducer is `evidence/fx-hooks-panic-safety-F1/zz_fx_panic_test.go` and the full output is `woven-go1.26.6.out.txt`. The build peaked at 349 MB RSS.

```
GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 15m -count=1 -run 'TestFX_|TestReview_InternalReaderCallbackCannotPanicHost' ./iast/io -v  # after copying zz_fx_panic_test.go (and the finder's io_reader_repro_test.go as zz_review_panic_test.go) into iast/io/ of a private copy
```
Key lines:
- Part A, fault injection. I replaced both callbacks through the internal `iobridge.Register`:
  - `FAULT io.LimitReader  escaped=true value=&{propagate}` (TeeReader, MultiReader, and ReadAll behave the same)
  - `FAULT io.ReadAll(host panics) recovered=&{readAll} hostPreserved=false`: the deferred IAST fault **replaces** a host `Read` panic that is already in flight. This is the F3 mechanism, reproduced here on the io surface.
- Part B, real callbacks, active scope, bound body. Adversarial but valid inputs: typed-nil pointer, nil interface, zero-size pointer, func-typed, value-typed, and map-typed readers, a negative limit, `TeeReader(nil,nil)`, `MultiReader()`, 20 mixed readers (more than the 8-reader fanout), `ReadAll` above `MaxRootBytes`, and an empty read. **All `panic=<nil>`.** `ReadAll(host panics) hostPreserved=true`. 16 goroutines x 2000 iterations of derived readers racing `scope.Finish()`: `panics=0`.
- Part C, realistic surface. An httptest server handler runs `ReadAll(TeeReader(MultiReader(LimitReader(r.Body))))`: `handlerPanic=<nil> bodyTainted=true`.
- The finder's test fails as they reported: `IAST-only panic escaped io.LimitReader: type=*struct { origin string } ... identical=true`.
- I did not run Go 1.27.0. Plain deferred calls without recover behave the same on every Go version, so the toolchain does not affect this result.

## Reachability
- **Default config, customer code: not reachable today.** Fault injection needs `internal/taint/iobridge.Register`. Go's internal-package rule stops customer modules from importing it, and the only production registration is `request.Register(PropagateReader, ReadAllBytes)` (internal/taint/request/scope.go:140). The real callbacks are defensive:
  - `dynamicPointer` (internal/taint/store/binding.go:213-223) rejects nil, non-pointer, typed-nil, and zero-size values.
  - Locks are `TryLock`/`TryRLock`.
  - Owner refs are generation-revalidated (`OwnerRef.Handle`, `analysisForOwner`).
  - `ReadAllBytes` checks the size and capacity bounds before `uint32` conversion.
- A panic would therefore need a latent IAST bug, for example a store invariant violation. If that happened, the missing boundary would turn an IAST bug into a host crash, or into replacement of a host panic, on common stdlib reader calls.
- **Not documented** as a limitation. README and 01-design-intent only require preserving host panic behavior. It still conflicts with product rule 1 as defense in depth, because the codebase already adds such shields elsewhere (`sqlbridge.Report`, `commandbridge.Report`, and the jsonbridge `shield`).

## Adjusted severity
**Medium.** The shield is missing and the failure mode is severe, but no reachable trigger exists. The brief's Critical tier needs a panic "reachable from customer code", and my adversarial inputs and concurrency runs found none. The finding's grouping of "other unshielded source and propagation advice" is static reasoning, and my tests do not verify it.

## Root cause
- internal/taint/iobridge/bridge.go:30-35 (`Propagate`) and :38-43 (`ReadAll`) call callbacks with no `recover`.
- Callers: iast/io/orchestrion.yml:27,44,66,85; iast/bufio/orchestrion.yml:32; iast/bufio/bufio.go:23; iast/net/http/orchestrion.yml:138 (MaxBytesReader).

## Minimal fix
Shield inside the bridge, so the stdlib call and the host's panics are not touched:
```go
func Propagate(input, output any) {
	if cb := registered.Load(); cb != nil {
		defer func() { _ = recover() }() // IAST-only work; drop taint on failure
		cb.propagate(input, output)
	}
}
```
Do the same in `ReadAll`. In Go, `recover` inside the deferred advice closure never catches the host's in-flight panic. It only returns a value when the panic started below this frame. When a host panic is already unwinding, a nested IAST panic is recovered in the helper's frame, and the original host panic keeps propagating. That fixes the replacement case too. The cost is one defer on the callback-present path, and it runs only after `registered.Load()` returns non-nil. Optionally count recoveries in telemetry.

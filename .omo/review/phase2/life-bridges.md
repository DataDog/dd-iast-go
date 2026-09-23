# life-bridges: registration, nil handling, init ordering and concurrency of internal/taint/*bridge
Verdict: Correct for its scope, with no Critical or High issue. Registration is race-free (every callback is published through `atomic.Pointer`), all nil and unregistered states no-op, and deferred bridge calls keep host panics intact. The main gap is uneven panic shielding: five of the nine bridges pass callback panics straight into net/http, io, net/url and bytes.
Scope covered: all nine `internal/taint/*bridge/bridge.go` and their tests; registration sites `internal/taint/request/scope.go:47-59,138-145,209-222`, `internal/taint/propagation/writer.go:17-36`, `iast/encoding/json/json.go`, `iast/database/sql/{sql.go,orchestrion.yml}`, `iast/os/exec/{exec.go,orchestrion.yml}`, `internal/spans/owner.go:89-101`, `internal/taint/store/store.go:183-194`; call sites in `iast/{net/http,net/url,io,bufio,encoding/json}/orchestrion.yml` and `iast/propagation/orchestrion.yml:1586-1680`. I ran reproducers and the full bridge test suites under `-race` with go1.26.6 in a private copy (now deleted).

## Findings
### life-bridges-F1: Source, reader, URL, writer and scope bridges do not shield callback panics
- Severity: Medium
- Category: crash
- Location: internal/taint/httpbridge/bridge.go:73-156; iobridge/bridge.go:29-43; urlbridge/bridge.go:24-31; writerbridge/bridge.go:77-91; scopebridge/bridge.go:24-30
- Claim: `sqlbridge.Report` (:60), `commandbridge.Report` (:51) and `jsonbridge.documentSlow/literalSlow` (:219-229) recover callback panics. `httpbridge.Begin/Eager/Form/.../Finish`, `iobridge.Propagate/ReadAll`, `urlbridge.Query`, `writerbridge.invalidateSlow` and `scopebridge.Finish` call their callbacks directly, and a repo-wide grep finds no `recover()` in `internal/taint/request` or `internal/taint/propagation`. These bridges run in host-critical places: `serverHandler.ServeHTTP` (`iast/net/http/orchestrion.yml:29-44`, including a `defer Finish`), deferred closures in `io.ReadAll/LimitReader/TeeReader/MultiReader` and `http.MaxBytesReader` (`iast/io/orchestrion.yml:27,44,61-68,85`; `iast/net/http/orchestrion.yml:138`), `url.URL.Query` (`iast/net/url/orchestrion.yml:26-30`), and `bytes.Buffer` methods. A panic anywhere in the large store/propagation code would reach the customer. It could turn a successful `io.ReadAll` into a panic, or replace a handler's `http.ErrAbortHandler` with a different panic value, which changes net/http's logging. Rule 1 requires that this never happens, and the codebase applies the protection to sinks only.
- Evidence: `.omo/review/evidence/life-bridges/review_tests.out.txt`, which captures the reproducers `.omo/review/evidence/life-bridges/{http,io,url,scope,writer}bridge_zz_review_test.go`. Output: `panic escaping bridge into net/http: eager panic` and `panic escaping bridge into host: callback panic` for urlbridge, iobridge, scopebridge and writerbridge. This proves the bridge passes panics through. I did not find a concrete input that panics in the real callbacks, so reachability is NEEDS-REPRO and the finding stays Medium.
- Fix: add the same `//go:noinline` slow path with `defer shield()` to these bridges, returning the unchanged input on panic (headers, values, form maps) the way `documentSlow` does. For `Begin`, return `(ctx, false)` on panic. Keep the recover inside a function called directly by the deferred frame.

### life-bridges-F2: jsonbridge.Register accepts nil callbacks
- Severity: Low
- Category: quality
- Location: internal/taint/jsonbridge/bridge.go:52-55
- Claim: every other `Register` drops nil functions (for example `sqlbridge/bridge.go:30-34`). jsonbridge stores `&callbacks{nil,nil}`, so every active `Document`/`Literal` panics on the nil call and relies on `shield()`. The panic is contained, but each call pays the panic and recover cost, and partial registration is accepted silently.
- Evidence: `.omo/review/evidence/life-bridges/jsonbridge_zz_review_test.go` (`TestReviewNilRegisterIsShielded`). Output: `registered non-nil holder with nil funcs: true` / `no panic escaped with nil callbacks`.
- Fix: `if document == nil || literal == nil { return }`.

### life-bridges-F3: Recovered callback panics are silently discarded
- Severity: Low
- Category: quality
- Location: internal/taint/sqlbridge/bridge.go:60; commandbridge/bridge.go:51; jsonbridge/bridge.go:241
- Claim: `_ = recover()` drops the panic with no telemetry. A bug in evidence collection, redaction or reporting becomes an invisible false negative. A panic raised while a blocking lock is held further down the stack (such as the `spans` annotation `RWMutex`) would also leave that lock held.
- Evidence: static reasoning only.
- Fix: count recovered panics in `internal/instrumentation/telemetry`, and keep blocking-lock sections `defer`-unlocked.

### life-bridges-F4: Sink and JSON callbacks exist only in woven executables with a root main
- Severity: Info
- Category: config
- Location: iast/database/sql/orchestrion.yml:16-31; iast/os/exec/orchestrion.yml:15-30; iast/encoding/json/orchestrion.yml:12-25
- Claim: SQL, command and JSON callbacks are registered by `_ = pkg.Report/Activate` bootstraps in root `main` with `test-main: false`. In woven `go test` binaries and library builds, `registered` stays nil, and `Report`/`Literal` safely no-op. The bridge is safe in that state, but the README does not say so, and users may expect findings from instrumented integration tests.
- Evidence: static reasoning only, from the yml comments and the bridge nil paths. A `go list -deps` check confirmed that each of `iast/{database/sql,os/exec,encoding/json,net/http}` links `internal/taint/request`.
- Fix: document this in the README "Sink coverage" section.

### life-bridges-F5: Bridge tests leave fake callbacks registered and never cover concurrent registration
- Severity: Low
- Category: test-gap
- Location: internal/taint/writerbridge/bridge_test.go:15-117; internal/taint/httpbridge/bridge_test.go:16-56
- Claim: these tests `Register` fakes without restoring the previous holder, while the sql and json tests do restore theirs. No test covers Register racing with invocation, or a host panic passing through a deferred bridge call.
- Evidence: `.omo/review/evidence/life-bridges/sqlbridge_zz_review_test.go` and `.omo/review/evidence/life-bridges/jsonbridge_zz_review_test.go`. Both properties hold today (see below).
- Fix: adopt the reproducers as regression tests and restore `registered` in `t.Cleanup`.

## Checked and found correct
- **Registration is race-free.** Every callback set lives in one `atomic.Pointer[struct]`, so a reader sees either nil or a complete, consistent set. HTTP begin/finish/eager are published together, so `Finish` never sees a different set than `Begin`. `TestReviewConcurrentRegisterAndReport` and all bridge tests pass under `-race`.
- **Registration before first use.** `init` registration completes before `main`. A goroutine started by another package's `init` can only see nil, which no-ops (`Begin` returns `created=false`, so `Finish` does nothing). Double registration means the last writer wins, and production registers each bridge once.
- **Nil handling.** Every `Register` except json ignores nil functions (F2). Unregistered bridges return their input unchanged (`Eager` returns headers, `Query` returns values, `Form` returns both maps, parameters return the value). `scopebridge.Finish` rejects `id==0||generation==0`. `finishOwnerSpan` bounds-checks the index and clears only a matching id/generation with CAS, so a slot reused between `analysis.Finish` and `scopebridge.Finish` (`scope.go:218-221`) is never cleared.
- **Host panics survive deferred bridge calls.** The woven `defer __dd__iast_ReportSQL__` and the deferred `jsonbridge.Literal` do not swallow or replace a panicking driver or `literalStore` panic, even when the callback also panics: the recover happens in a nested frame, so it only catches the callback's own panic. Output: `host recovered=driver panic` in both sql tests, and `host recovered=literalStore panic`.
- **Fast gates.** `activeOwners`/`activeValues` are bound once inside `defaultManager` (`sync.OnceValue`) before `processManager.Store`, so sinks and JSON stay inactive until the first sampled request. The operator mirror (`store.go:183-194`) and the writer counter are bound to a fresh store at count 0, and every delta is applied to both.
- **Linkname signatures match.** `database/sql` declares `(context.Context,string,uint8,bool)` against `sqlbridge.Report(ctx,string,Kind=uint8,bool)`, and `os/exec` declares `(context.Context,[]string)`. `links:` keeps the bridge linked even when no provider is registered.
- **JSON decoder slots.** Every `Bind` is paired with a deferred `Unbind`. A slot is claimed with a CAS to the sentinel 1 and published only after its fields are reset. `findDecoderState` requires an exact pointer match, and the decoder address cannot be reused while `Unbind` holds it as an argument. Nested binds keep the outer reader. Document mapping checks address, length and bounds before slicing the clone.
- **writerbridge expectations.** The table uses exact-pointer CAS, a full table falls back conservatively to non-preserve, and `Cancel` is deferred so markers do not leak on panic.
- **httpbridge h2c filter.** Operator precedence (`PRI && * || h2c`) matches the intent, and the canonical header keys are correct.

## Not covered / open questions
- I did not try to find a concrete panicking input in `request.EagerHTTP/Manage*`, `ReadAllBytes`, `ManageURLQuery` or `store.InvalidateBuffer`. That would raise F1 to Critical, and belongs to the request/store nodes.
- I did not run an orchestrion-woven build. The bootstrap and linking conclusions come from the ymls and `go list -deps`.
- I did not analyze writerbridge nested-marker accounting for `WriteRune`→`WriteByte` (`iast/propagation/writer.go:142-144`) end to end. It belongs to the writer node.

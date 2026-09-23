# crash-deadlock: lock ordering, callbacks, and goroutine liveness

Verdict: High - a stale request owner can bind a live object into a reused owner generation, violating IAST provenance isolation. No production deadlock or IAST-owned goroutine leak was found in the reviewed paths.
Scope covered: `internal/taint/store/{store,owner,lookup,value,root,mutation,binding,writer,overflow}.go`; `internal/taint/request/{scope,owner}.go`; `internal/spans/{annotation,owner,tainted,orchestrion,payload}.go`; `internal/vulnerability/{report,tainted}.go`; `internal/vulnerability/dedup/dedup.go`; `internal/taint/{httpbridge,iobridge,jsonbridge,operatorbridge,sqlbridge,commandbridge,scopebridge,urlbridge,writerbridge}`; `internal/instrumentation/{instrumentation,telemetry}`; `iast/net/http/orchestrion.yml`; `internal/spans/orchestrion.yml`; and the corresponding dd-trace-go `ddtrace/tracer/span.go` and `instrumentation/instrumentation.go` callback paths.

## Findings

### crash-deadlock-F1: Stale owner handle can publish into a successor generation

- Severity: High
- Category: provenance
- Location: `internal/taint/store/owner.go:20-60`; `internal/taint/store/binding.go:77-108`
- Claim: `Store.Acquire` reactivates a dead owner slot by changing its generation and active state without acquiring the slot's `lifecycleMu`. `BindObject` accepts an `Owner` handle after separately checking generation and state, then publishes to that slot's binding table. A stale handle can observe the old generation and the successor's active state, causing an object to be bound to the next owner generation. That permits cross-owner provenance association on a supported object-binding path.
- Evidence: `.omo/review/evidence/crash-deadlock/owner-generation-crossover_test.go` run from the private copy with `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 REVIEW_STRESS=90s go test -count=1 -timeout=3m -run TestCrashDeadlockStaleHandleBindAfterSlotReuse -v ./internal/taint/store`; `.omo/review/evidence/crash-deadlock/owner-generation-crossover.txt` captures `stale handle generation 50302 bound object into reused generation 50303` and `cross_generation_bindings=1`.
- Fix: serialize reactivation of a dead slot with the same lifecycle lock used by stale-handle users, or make generation/state observation and publication one revalidated lifecycle-protected operation. Do not expose the successor as active until no stale handle can pass validation.

## Checked and found correct

- Apart from F1, the inspected blocking lock graph is acyclic: request source state reaches owner lifecycle state before per-owner root/writer tables; shard locks are released before lookup obtains owner state; and try-lock hot paths drop tracking rather than wait.
- `Scope.Finish` releases `Scope.mu` before finishing analysis; `Analysis.Finish` clears the source table before calling `Owner.Finish`; and owner cleanup synchronously releases writer roots, managed roots, binding tables, and accounting. These paths do not create an IAST-owned stranded goroutine.
- Span finish advice invokes `spans.Finished` before dd-trace-go's `Span.finish` takes `Span.mu`. The observed cross-package edge is `Annotation.RWMutex -> Span.mu`; no inverse `Span.mu -> Annotation.RWMutex` path was found. Calls under the annotation lock pass IAST-owned payloads, integers, or strings, not customer `fmt.Stringer` values.
- `RecordStackTrace` under the annotation lock resolves the root span and writes an internal structured stack value; the inspected implementation does not re-enter annotation acquisition. Atomic bridge callbacks execute outside IAST mutexes.
- No production `go` statement, channel operation, `sync.WaitGroup` wait, `runtime.SetFinalizer`, or `runtime.AddCleanup` call was found. IAST registers a dd-trace-go telemetry heartbeat callback but creates no worker, ticker, or channel consumer of its own.
- In the private copy, `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -race -count=1 -timeout=15m ./internal/spans ./internal/taint/request ./internal/taint/store ./internal/vulnerability/...` passed all six audited package groups.

## Not covered / open questions

- This review traced the local dd-trace-go APIs used by IAST, not arbitrary third-party tracer exporters or agent network workers outside IAST's ownership.
- The F1 reproducer is scheduling-sensitive but failed in 12.75 seconds on this run; it establishes the owner-generation crossover, not an end-to-end vulnerability event.

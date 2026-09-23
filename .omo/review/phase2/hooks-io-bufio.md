# hooks-io-bufio: io / bufio reader hooks and iobridge
Verdict: Host behavior is preserved exactly. Bytes, len, cap, errors, EOF handling, partial reads, panics and nil readers matched between woven and plain builds in every case tested. Provenance is wrong in two reachable ways, because a reader binding is keyed only on the wrapper object's address and is attached to the whole `io.ReadAll` result. First, a reset or reused wrapper keeps its original owner, which leaks taint across owners (High, reproduced). Second, a mixed `io.MultiReader` taints clean or foreign data as the request body (Medium, reproduced).

Scope covered: `iast/io/orchestrion.yml`, `iast/io/io.go`, `iast/io/io_test.go`, `iast/io/reader_limits_test.go`, `iast/bufio/{orchestrion.yml,bufio.go,bufio_test.go}`, `internal/taint/iobridge/bridge.go` and its tests, `internal/taint/request/reader.go`, `request/http.go:15-79` (`analysisForOwner`, `LookupObject` gate, body binding), `request/table.go` (`prepareBytes`), `store/binding.go` (whole file), `store/root.go:184-260` (`AdoptSourceBytes`, `AdoptBytes`), the `net/http.MaxBytesReader` and EagerHTTP aspects (`iast/net/http/orchestrion.yml:104-137`), and the Go 1.26.6 and 1.27.0 sources of `io.ReadAll` and `bufio.NewReaderSize`/`Reset`. I ran a new reproducer and parity test, woven and plain, plus the existing packages' woven tests under `-race`.

## Findings

### hooks-io-bufio-F1: A reset or reused reader wrapper keeps its original owner's binding, so taint leaks across owners
- Severity: High
- Category: cross-request
- Location: iast/bufio/orchestrion.yml:15-34; iast/io/orchestrion.yml:12-27; internal/taint/request/reader.go:27-39,67-88; internal/taint/store/binding.go:95-108,166-203
- Claim: `PropagateReader` binds the wrapper object's address (`*bufio.Reader` or `*io.LimitedReader`) to the owner exactly once, at construction. Nothing removes that binding when the wrapper's source changes. `bufio.Reader.Reset(r)` and assignment to the exported `LimitedReader.R` both change it, and neither is hooked. The binding stays live until the owner finishes. Every later `io.ReadAll(wrapper)` then adopts whatever the wrapper now yields as that owner's `http.request.body` source (reader.go:81-87). This causes two failures:
  1. Within one request, `br.Reset(strings.NewReader(constant))` makes a clean constant look like body data, which produces a false positive at a sink.
  2. The common pooling idiom (`br := pool.Get(); if br == nil { br = bufio.NewReader(r.Body) } else { br.Reset(r.Body) }`, the same shape as `net/http`'s `newBufioReader`) binds the reader to the request that created it. When another request reuses the reader while that owner is still active, its data is published as a source of the foreign owner. The data then reports through foreign-owner lookup even if the second request was sampled out or was never admitted.
- Evidence: `.omo/review/evidence/hooks-io-bufio/zz_review_repro_test.go` (`TestReviewStaleBindingAfterReset`, `TestReviewCrossOwnerViaResetReader`). Command: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -count=1 -v -run TestReview ./iast/io/`. Output is in `woven.out.txt`:
  - `case=bufio.Reset data="SELECT 1 FROM clean_constant" tainted=true ranges=[0,+28 origin=http.request.body value="SELECT 1 FROM clean_constant"]`
  - `case=LimitedReader.R data="SELECT 2 FROM clean_constant" tainted=true ...`
  - `case=cross-owner dataB="SELECT 3 FROM data_of_B" tainted=true ... ownerA.sources before=1 after=2 ownerB.sources=0`
- Fix: Hook `bufio.(*Reader).Reset` with a prepend that unbinds the receiver from every owner, then re-propagates from the new input. For the `LimitedReader` case, or as a general guard, record the bound input with the wrapper binding and have `ReadAllBytes`/`CloneReaderBytes` check that the wrapper still wraps it (for example, have `*io.LimitedReader.R` compare against the stored input), and drop on mismatch. At minimum, add an unbind API and a regression test for Reset.

### hooks-io-bufio-F2: A MultiReader with any bound input taints the whole ReadAll result, including clean and other-owner data
- Severity: Medium
- Category: false-positive
- Location: iast/io/orchestrion.yml:46-68; internal/taint/request/reader.go:67-88,119-126
- Claim: The MultiReader advice binds the result to every owner bound to any of the first 8 inputs. `ReadAllBytes` then adopts the complete result as one `http.request.body` source spanning `[0,len)`. Clean readers mixed into the MultiReader are therefore tainted, and the reported source value contains non-request bytes. If the bound reader contributes nothing (an empty chunked body, or a body drained earlier), a fully clean result is reported as body taint. A reader bound to a different owner beyond index 8 is merged into the included owner's source value too. The existing `TestMultiReaderInspectionBoundAndCleanup` (io_test.go:134-138) asserts exactly this: the source value is `"included-excluded"`. This is not a documented coarse transform, because the README lists no reader coverage.
- Evidence: `.omo/review/evidence/hooks-io-bufio/zz_review_repro_test.go` (`TestReviewMultiReaderCleanPrefixTainted`), same command. Output is in `woven.out.txt`:
  - `case=mixed ... ranges=[0,+35 origin=http.request.body value="SELECT * FROM t WHERE id = 1 OR 1=1"]`
  - `case=bound-empty data="SELECT * FROM t WHERE id = 1" tainted=true ranges=[0,+28 ...]`
- Fix: Propagate to a MultiReader result only when every input is bound to the same owner set and there are at most 8 inputs. Otherwise drop, which is a safe miss. Update the enshrining test accordingly.

### hooks-io-bufio-F3: Common body-reading idioms silently lose provenance
- Severity: Info
- Category: false-negative
- Location: iast/bufio/orchestrion.yml:15-34; iast/io/orchestrion.yml (no `NopCloser` or `bytes.NewReader` aspect)
- Claim: These are safe misses and not errors, but they are undocumented:
  - Pooled `bufio.Reader`s initialized through `Reset(r.Body)` are never bound, because only `NewReaderSize` is hooked.
  - `io.NopCloser(tracked)` returns a non-pointer value, so `dynamicPointer` rejects it (binding.go:205-215).
  - The "restore body" idiom `r.Body = io.NopCloser(bytes.NewReader(data))` loses taint for downstream `ReadAll` or JSON decoding.
  - `bufio.Reader.ReadString`, `ReadBytes`, `ReadLine`, and `bufio.Scanner` results are untainted. The parity test logged `rsTainted=false`. Untainted `Peek` is correct, because it aliases the internal buffer.
- Evidence: static reasoning, plus the `PARITY ... rsTainted=false` line in `woven.out.txt`.
- Fix: Document the reader coverage (the wrappers and `ReadAll` are supported; the idioms above are not) in the README propagation table. Consider a `Reset` hook, which is shared with the F1 fix.

### hooks-io-bufio-F4: Reader hooks run on every process-wide call while any analysis is active
- Severity: Info
- Category: perf
- Location: internal/taint/request/http.go:43-49; internal/taint/store/binding.go:121-164; iast/io/orchestrion.yml:61-68
- Claim: The only gate is `manager.used.Load()==0`. While any request is sampled, every `bufio.NewReaderSize`, `LimitReader`, `TeeReader`, `MultiReader` and `ReadAll` call in the process pays for a `reflect.ValueOf`, a 64-owner scan with `TryRLock`, and a probe of the binding hash. That includes `net/http`'s per-connection readers, `transfer.go` body `LimitReader`s, and client-side reads. A `MultiReader` pays this up to 8 times. The cost is bounded and small, but this is not the "cheap check first" pattern (for example, a process count of reader bindings).
- Evidence: static reasoning only.
- Fix: Keep an atomic count of live reader bindings in the store and return early when it is zero.

## Checked and found correct
- **Parity of wrapped calls.** `TestReviewParity` printed identical `len`, `cap`, sha256, `nil`-ness and `err` for 12 reader shapes in plain and woven builds (`plain.out.txt` vs `woven.out.txt`), each bound and unbound. The shapes were: `n>0` with a custom error, `n>0` with EOF, one-byte reads, a 100 KiB body, `LimitReader` with n = 70000, 0 and -5, an empty `MultiReader`, a `MultiReader` with a trailing error, `TeeReader`, a clamped `bufio` size of 1, and `NewReaderSize` returning its input. The reader panic value (`reader-panic`), the `io.ReadAll(nil)` panic, and the `Peek`/`ReadString` results matched as well.
- **The advice cannot alter results.** All five hooks are `defer func(){...}()` closures that only read the named results and never `recover()`. The callbacks cannot panic: `dynamicPointer` handles nil, typed-nil, non-pointer and zero-size values. `ReadAllBytes` returns early for `len < 2`, and the `ReadAll` panic path receives a nil result. `iobridge` imports only `sync/atomic`, so there is no import cycle into `io` or `bufio`.
- **ReadAll adoption invariant.** In Go 1.26.6 and 1.27.0, `io.ReadAll` returns either its own `make(..., 0, 512)` buffer or `append([]byte(nil), make(finalSize)...)`, so the result always starts at the allocation base and its `cap` is the full allocation, as `AdoptSourceBytes` requires. The size boundaries 0/1/2/64 KiB-1/64 KiB/64 KiB+1 are covered by `TestReadAllBodySizeBound` and pass.
- **Bounds.** At most 8 reader bindings per owner, 256 bindings in total, and 4 owners per lookup. `MultiReader` inspects at most 8 inputs. The `bufio` size limit of 4096 bytes is identical in the YAML and in `iast/bufio.Propagate`. When `NewReaderSize` returns its input, the rebind reuses the existing entry and does not consume a slot (binding.go:185-198).
- **Owner lifecycle.** `OwnerRef.Handle` revalidates generation and state, `BindObjectValue` goes through `beginWrite`, and finish resets the binding table. Both existing tests and a `-race` run pass (`woven-race-existing.out.txt`: `iast/io`, `iast/bufio`, `iobridge` and `request` all ok).
- **Escape analysis (static).** `ReadAll`'s `r` and `NewReaderSize`'s `rd` already escape through interface method calls or heap stores. The `MultiReader` range passes element values, not the variadic backing array.
- **Coverage and design.** `TeeReader` does not taint its side writer, which is intended. `MaxBytesReader` is propagated by the `net/http` aspect.

## Not covered / open questions
- I did not inspect the `-gcflags=-m` output of the woven `io` and `bufio` packages, so the escape claim above is static only.
- I did not measure whether `sourceMu.TryLock` contention during `ReadAll` adoption (reader.go:91) drops body taint under concurrency.
- The JSON-decoder use of `CloneReaderBytes` belongs to the JSON node. It is affected by F1 and F2 in the same way.

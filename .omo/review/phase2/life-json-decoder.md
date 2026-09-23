# life-json-decoder: JSON decoder slot lifecycle, reentrancy, panic cleanup and limits
Verdict: Not correct under concurrency. The admission slot table has an open-addressing insert bug. A nested `Bind` claims a freed earlier probe instead of the decoder's existing slot, so admitted `Decoder.Decode` calls lose their document mapping and request-body taint (a High false negative, reproduced, with a one-line fix validated). The pointer hash also clusters real `Decoder` addresses into 8 buckets, which halves the documented 64-slot capacity. Panic cleanup, stack-growth safety, >64 KiB documents, streaming, and Token/More paths behaved correctly on Go 1.26.6.
Scope covered: `internal/taint/jsonbridge/bridge.go` (all), `capacity_test.go`, `bridge_test.go` (names/structure), `iast/encoding/json/{orchestrion.yml,json.go}`, `internal/taint/propagation/json.go`, `internal/taint/request/reader.go:40-122` (`CloneReaderBytes`/`adoptBodyBytes`), `iast/integration/testapp/json_regression_test.go`, commit 7de00fb stat. I read the Go 1.26.6 `encoding/json` `Unmarshal`, `Decoder.Decode`, `value`, `valueQuoted`, the `object` destring path, `literalStore` and `init`. I checked the Go 1.27 JSON-v2 source selection. I ran woven (Orchestrion, `GOTOOLCHAIN=go1.26.6`) reproducers in `iast/integration/testapp`, a plain jsonbridge unit reproducer, and a `-gcflags=-m` escape check. Peak RSS of the woven test build was 375 MB.

## Findings
### life-json-decoder-F1: Nested Bind creates a duplicate slot and drops the Decoder document, so request-body taint is lost
- Severity: High
- Category: false-negative
- Location: internal/taint/jsonbridge/bridge.go:210-224 (with iast/encoding/json/orchestrion.yml:41 and :58)
- Claim: Every `Decoder.Decode` binds its state twice. The first bind is `Bind(dec.r, &dec.d)` at Decode entry. The second is `Bind(nil, d)` in `decodeState.unmarshal`, on the same pointer after `d.init` has published the cloned document. `addDecoderState` probes in order, and at each probe it checks `pointer == ours` and then `CompareAndSwap(0, 1)`. Suppose the Decode's first bind landed on probe k>0 and an earlier probe was freed in the meantime, for example because another request's decode finished while this one blocked in `r.Read`. The nested bind then claims that freed slot as a new entry (`depth=1`, `reader=nil`, `document=nil`) instead of incrementing the existing one. `Literal`'s `findDecoderState` returns that first match, sees no document, and publishes against the uncloned buffer, so the decoded string gets no taint. Both slots are released on unwind, so nothing leaks, but provenance is silently lost for an admitted decoder on the primary supported path (`json.NewDecoder(r.Body).Decode`). With the address clustering in F2, colliding probes are the norm, and this race needs only that a neighbor's decode finish during the body read. The README's "colliding concurrent decodes drop provenance" describes admission failure. This failure happens after successful admission, is caused by a logic error, and is not a bound.
- Evidence: Deterministic unit reproducer `.omo/review/evidence/life-json-decoder/zz_review_dup_slot_test.go` (uses the `zz_review_debug.go` probe). Command: `GOTOOLCHAIN=go1.26.6 go test -run TestReviewNestedBind -v ./internal/taint/jsonbridge/`. Output (`dup.out.txt`): `occupied=2 pointers=[0x798765b65880 0x798765b65880] depths=[1 1]`, `literal callback document is clone: false`, `BUG: nested Bind claimed a freed earlier probe ...`, `FAIL`. The woven end-to-end run uses 40 heap Decoders on one request-bound reader, all blocked in `Read` and then released one at a time (`zz_review_json_test.go`, `TestReviewConcurrentHeapDecodersHashCapacity`). Command: `REVIEW_SERIAL=1 REVIEW_COUNT=40 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -run TestReviewConcurrentHeapDecodersHashCapacity -v .`. It shows `occupiedWhileBlocked=32 taintedResults=8` (`more2.out.txt`), and bridge counters show `docStored=32 ... litMapped=8 ... noDoc=32` (`diag.out.txt`). The fully concurrent run with 16 decoders shows `occupiedWhileBlocked=16 taintedResults=10` (`capacity.out.txt`). With the fix below applied, the same runs give `taintedResults=32` and `taintedResults=16`, and the jsonbridge package passes (`fixed.out.txt`, `fix-and-diagnostics.diff`).
- Fix: In `addDecoderState`, look for an existing entry across all four probes first (`if slot := findDecoderState(pointer); slot != nil { slot.depth.Add(1); return slot }`) and only then claim a free probe. A given state pointer is only ever bound by one goroutine in nested order, so the two-pass lookup is race-free for it. Add the unit reproducer as a regression test.

### life-json-decoder-F2: The `(ptr>>3)%64` hash maps real Decoders to 8 buckets, so effective capacity is 32, not the documented 64
- Severity: Medium
- Category: memory-bound
- Location: internal/taint/jsonbridge/bridge.go:210, :232; README.md:64-66; internal/taint/jsonbridge/capacity_test.go:19-21
- Claim: `json.Decoder` is 304 bytes (size class 320) with `d` at offset 40. Spans are 8 KiB-aligned, so `(&dec.d>>3)%64 = (40k+5) mod 64` takes only 8 values (5, 13, ..., 61). With 4 disjoint probes each, at most 32 of the 64 slots can ever hold a Decoder, process-wide. `decodeState` heap objects from `Unmarshal` cluster the same way for their own size class. The capacity test uses consecutive `uint64` elements, which have an ideal distribution and hide this. Documentation and limits say "64 process slots with four-probe admission".
- Evidence: `.omo/review/evidence/life-json-decoder/capacity.out.txt` and `more.out.txt`: `sizeof(json.Decoder)=304 offset(d)=40`, `decoders=40 distinctStartBuckets=8 buckets=map[5:5 13:6 21:4 ...] occupiedWhileBlocked=32`.
- Fix: Mix the address before bucketing, for example `(pointer * 0x9E3779B97F4A7C15) >> 58`, and make the capacity test use real `json.Decoder`/`decodeState` allocations.

### life-json-decoder-F3: Slot admission is not gated on relevance, so every process-wide Decode/Unmarshal competes for the 32 usable slots
- Severity: Medium
- Category: false-negative
- Location: internal/taint/jsonbridge/bridge.go:60-72; iast/encoding/json/orchestrion.yml:41, :58
- Claim: `Bind` checks only `active()`, which is true while any owner in the process is active. It does not check whether the reader is request-bound or whether the document can contain taint. While one request is sampled, every `Decoder.Decode` and every `json.Unmarshal` in the process takes a slot and pays `reflect.ValueOf`, CAS work, and a `readerRef` allocation on a shared, contiguous atomic array. That includes unsampled requests, outbound HTTP client responses, and background jobs. Unrelated decodes can therefore occupy the (effectively 32, see F2) slots and deny admission to the sampled request's decoder. The README frames the limit as "excess ... concurrent decodes", which reads as tracked decodes, not all decodes.
- Evidence: static reasoning only. `Bind` has no reader or document gate (bridge.go:60-72). The unconditional `Bind(nil, d)` for Unmarshal (orchestrion.yml:58) is only needed for the `,string` quoted mapping. The capacity ceiling is measured in `more.out.txt`.
- Fix: For Decode, bind only when the reader has an owner binding, using a cheap `LookupObject`/`MayContain`-style gate. For Unmarshal, key the quoted state off `d.data` being in the store (`MayContain`), or bind lazily in `valueQuoted`.

### life-json-decoder-F4: Streaming Decoder sources include inter-document whitespace
- Severity: Low
- Category: provenance
- Location: internal/taint/jsonbridge/bridge.go:103-122 (data from Go `stream.go:69` `dec.buf[dec.scanp:dec.scanp+n]`)
- Claim: `readValue`'s `n` includes leading whitespace, so the second and later documents in a newline-delimited stream are published as body sources with a leading `\n`. In the reproducer, the source is 18 bytes for a 17-byte document. Ranges and redaction still work, but the reported source value differs from the document.
- Evidence: `.omo/review/evidence/life-json-decoder/more.out.txt`: `decode 0 (doc len 17): ... sourceLen=17` and `decode 2 (doc len 17): ... sourceLen=18`.
- Fix: Trim leading JSON whitespace before cloning in `Document`. Keep the offset math relative to the untrimmed slice, or trim in the callback and adjust the mapping.

### life-json-decoder-F5: Address-keyed slots rely on `decodeState`/`Decoder` escaping to the heap
- Severity: Info
- Category: test-gap
- Location: internal/taint/jsonbridge/bridge.go:193-199, :206-240
- Claim: Slots store `uintptr` addresses. If a `decodeState` or `Decoder` were ever stack-allocated, a stack copy during decode (growth, or shrink at GC) would pass the runtime-adjusted pointer to `Unbind` and `Literal` while the slot still held the old address. The slot would then leak permanently, because depth stays at 1 and pointer is never cleared, and could later match a reused address. Today both escape: stdlib `decodeState` methods leak `d`, and `NewDecoder`'s result escapes. The protection is incidental, though, and no test pins it.
- Evidence: `escape.out.txt`: `decode.go:106: moved to heap: d` and `&json.Decoder{...} escapes to heap`. `leak.out.txt` shows 400 completed decodes each for Decode and Unmarshal with 5,000-deep nesting forcing stack growth: `occupied slots before=0 after ...=0`, with taint intact.
- Fix: Add a woven regression test that asserts zero occupied slots after deep-recursion decodes on fresh goroutines, or anchor the state (for example `runtime.KeepAlive` plus an explicit escape) in the advice.

## Checked and found correct
- Panic inside a custom `UnmarshalJSON`. In `Unmarshal` (my `TestReviewUnmarshalPanicCleanup`), the panic value propagates unchanged (`recovered=review panic`), `occupiedAfterPanic=0`, and the next decode works. `literalSlow`'s `shield` does not swallow the outer panic because it is not the panic-invoked deferred frame. The existing `TestJSONDecoderPanicThenCleanReader` covers Decode.
- No slot leak after deep-nesting decodes on fresh goroutines, for both Decode and Unmarshal (`leak.out.txt`).
- Documents over 64 KiB. `CloneReaderBytes` returns nil, so no mapping is stored and the value stays untainted. The following document in the same streaming Decoder is still tainted, and slots are 0 afterwards (`more.out.txt`).
- Streaming Decoder with multiple `Decode` calls. Each value's source is its own document, not the whole buffer. Token/`More` element streaming propagates per element (`more.out.txt`).
- `*string` destinations propagate, because the deferred Literal closure reads `v` after `literalStore` reassigns `v = pv`. `any` destinations stay untainted, which is documented.
- `Quoted` is consumed by the next `Literal` (Swap nil) on the same slot. Null and invalid `,string` tokens are rejected (bridge.go:137), and the existing `TestJSONStringTagLeavesUnchangedValuesUntainted` covers this.
- Concurrent decoders on one shared reader. With the F1 fix, all 16/16 and 32/32 admitted decoders are tainted with per-document sources (`fixed.out.txt`).
- Unbind state reset at final depth clears quoted, document and reader before releasing the pointer. `addDecoderState` reinitializes a claimed slot behind the `1` sentinel.

## Not covered / open questions
- The Go 1.27 JSON-v2 compile break (`dec.r`/`dec.d` undefined) is already reported as base-test-127-F1 / sink-json-sources-F1. The same break applies statically to Go 1.26.6 with `GOEXPERIMENT=jsonv2`, which I did not build.
- I did not run the reproducers under `-race`. The slot fields are atomics, and the remaining races need concurrent use of one Decoder, which is already a customer data race.
- Reentrant use of the same Decoder from inside `UnmarshalJSON` is documented as lossy and was not exercised.
- The other decodes in the woven harness JSON (tracer/telemetry) show how many non-request decodes reach `Literal` (`enter=487`, `diag.out.txt`). That supports F3, but I did not measure it under realistic load.

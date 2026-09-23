# fx-perf-hotpath-F2: verification of perf-hotpath-F2

## Verdict per finding

| id | verdict | original | adjusted |
| --- | --- | --- | --- |
| perf-hotpath-F2 | CONFIRMED | High | High |

The mechanism is real and the finding understates it. The gate that decides whether a writer wrapper does bookkeeping is process-wide: it only asks whether some request anywhere in the process is being analysed. It never checks whether the written value could be tainted or whether any writer state exists. While one sampled request is in flight, every `strings.Builder`/`bytes.Buffer` operation in every goroutine runs the full bookkeeping path. That includes `WriteByte`/`WriteRune`/`Grow`/`Reset`/`String`, not only `WriteString`.

In a woven build of ordinary customer code, the overhead is about 50x the unwoven cost. A gate that returns early when the input cannot be tainted and no writer state exists is 9-22x cheaper and keeps provenance.

## Reproduction

All runs were in the private copy at HEAD 2e23b46. The evidence is in `.omo/review/evidence/fx-perf-hotpath-F2/`. I did not reuse the finder's harness.

1. **Woven, customer-shaped (most realistic).** `f2_render.go` (non-test file, so it is woven) builds a clean 8-field template with a Builder and a Buffer: 32 writes and 2 `String` calls. `f2_woven_test.go` runs it with no owner and then with one clean owner acquired via `request.Begin` (config: enabled, sampling 100, max-concurrent 2). The same benchmark was run unwoven (`go test`) and woven (`go tool orchestrion go test`), both with `GOTOOLCHAIN=go1.26.6 -benchtime=300ms -count=3 -cpu=1,4 -benchmem`.
   - Woven header: `F2: woven=true instrumentedPropagation=125`; unwoven header: `woven=false instrumentedPropagation=0`.
   - Unwoven, active-clean-owner: `284.3 / 322.3 / 328.6 ns/op`
   - **Woven, active-clean-owner: `16123 / 16367 / 16720 ns/op`**, which is about 50x (roughly 470 ns added per writer op).
   - Woven, no-owner: `376-669 ns/op`, 440 B / 9 allocs against 360 B / 7 allocs unwoven. The +2 allocs are the documented, accepted writer-anchor escape and are not part of this finding.
   - Woven, active-clean-owner-parallel-4: `4052-4636 ns/op` aggregate. This is the same per-core cost, which points to pure CPU work rather than lock contention.
   - Woven build peak RSS was 368 MB (`/usr/bin/time -l`), well under the 4 GB threshold.
   - Files: `bench-woven.txt`, `bench-control-unwoven.txt`. An earlier attempt placed the fixture in a `_test.go` file, which Orchestrion does not weave (identical numbers), so it was discarded and rerun.
2. **Internal API, with a "necessary cost" baseline.** `f2_review_test.go` compares native calls, the real wrappers (`hooks.BuilderWriteString`/`BuilderString`, `BufferReset`/`BufferWriteString`/`BufferString`), and a *gated* variant. The gated variant returns natively when `!s.HasWriterStates()` and the input key is not `s.MayContain`, and otherwise calls the real wrapper.
   - Go 1.27.0, quiet machine (`bench-internal-go1.27.0.txt`):
     - active-clean-1 builder: native `83-87`, hook **`1023-1030`**, gated `115-120 ns/op` (hook is about 9x gated).
     - active-clean-1 buffer: native `32-33`, hook **`1430-1518`**, gated `65-66 ns/op` (about 22x).
     - no-owner builder: hook `103`, native `80`, so the no-owner path is fine.
   - Go 1.26.6, load average about 50 (`bench-internal-go1.26.6.txt`, noisy): the same ordering in every scenario. Examples: active-clean-1 buffer hook `6708-12008` against gated `276-378`; active-unrelated-taint-1 (the owner holds a tainted parameter) buffer hook `3761-6050` against gated `261-325`; active-clean-2 (the default max of 2 concurrent requests) buffer hook `6566-10347` against gated `96-388`.
   - `active-tracked-writer-elsewhere`: once any writer anywhere holds taint, `HasWriterStates()` is true and the gated variant falls back to the slow path (`13938-28192 ns/op`). The process-wide counter is therefore only a first-level fix.
   - `TestF2GatedPreservesProvenance` passes (`gated path kept taint on "SELECT attacker"`), so the proposed gate does not lose provenance for a clean prefix followed by a tainted write.
3. **Attribution.** CPU profile `pprof-active-clean.txt`: `store.LookupWriterValue` accounts for 46% cumulative; `updateWriter` has 20% flat, which is mostly stack zeroing; `writerPresent` 11%. `sizes.txt` gives `Snapshot=6312` bytes and `owner=187440` bytes with `MaxOwners=64`. So every clean write zeroes a 6.3 KB stack struct. It also walks 64 owner records spaced 187 KB apart, about 12 MB of address space and 64 distinct pages per call, and for each active owner it runs `writerPresent` (8 slots × 3 atomics, up to 3 attempts).

## Reachability

This is reachable under the default configuration. The defaults are `DD_IAST_ENABLED=true`, sampling 30% and max concurrent requests 2 (`internal/config/config.go:72-74`). `request.ActiveStore()` (`internal/taint/request/lookup.go:73-79`) returns non-nil whenever *any* sampled request is in flight. Under steady traffic that is almost always true, and all goroutines pay, including background jobs and unsampled requests. Builder/Buffer use is ubiquitous in customer code and in libraries the customer compiles woven (logging, templating, encoders).

The only documented writer trade-off is one extra allocation for the strong receiver anchor (`_docs/plans/taint-tracking-net-http-sqli-cmdi-phase-5.md:18,82`; README "Tracking a stateful writer..."). Nothing documents or accepts a per-operation scan on clean writes, so this is not a documented limitation. It violates product rule 2 (expensive work must sit behind a cheap check). The behavior is the same on Go 1.26.6 and 1.27.0.

## Adjusted severity

**High (unchanged).** This is a hot-path regression several times larger than necessary: 9-22x the gated cost per op in isolation, and about 50x end-to-end in woven customer code. It is reachable by default for every goroutine while any request is sampled. It is not Critical because there is no crash, no wrong result and no unbounded memory.

## Root cause (file:line, HEAD 2e23b46)

- `iast/propagation/writer.go:20,31,42,53,64,75,85,94,108,122,136,152,166,178,195`: every wrapper gates only on `internal.WriterActive()`.
- `internal/taint/propagation/writer.go:23-25`: `WriterActive()` is `request.ActiveStore() != nil`, meaning "some owner exists". It does not use `writerbridge.Active()` / `Store.HasWriterStates()` (`internal/taint/store/writer.go:354`), which already exist.
- `internal/taint/propagation/writer.go:96-102`: `updateWriter` zeroes `var input store.Snapshot` (6,312 B) and calls `store.LookupWriterValue` unconditionally, even for `UpdateUntaintedWriter` (WriteByte/WriteRune/Grow). The result is discarded because `UpdateWriter` returns early at `internal/taint/store/writer.go:190` when `index < 0 && writtenSet.Len() == 0`.
- `internal/taint/store/writer.go:76-113`: `LookupWriterValue` walks all 64 owner records, which are spaced 187 KB apart, and calls `writerPresent` (`:412-433`) per active owner. Buffer writes run this twice: once in `PrepareBufferWriter` (`internal/taint/propagation/writer.go:41-53`) and once in `updateWriter`. `ResetWriter` (`:161-173`) and `publishWriterString` (`:215-219`) run it again for `Reset` and `String`.

## Minimal fix

1. Add a cheap second-level gate in `internal/taint/propagation` and use it in each wrapper before any view is built:
   - For string/byte input writes: `s := request.ActiveStore(); needed := s != nil && (s.HasWriterStates() || (keyOK && s.MayContain(key)))`.
   - For `WriteByte`/`WriteRune`/`Grow`/`Reset`/`Truncate`/`String`: only `s.HasWriterStates()`.
   - When `needed` is false, call the native method.
   - This is safe: without any writer state and with clean input, `UpdateWriter` is a no-op (`store/writer.go:190-191`), `PrepareBufferWriter` has nothing to adopt, and `writerbridge.Expect` already returns false. `TestF2GatedPreservesProvenance` checks the tainted-after-clean sequence.
2. Second level, for the case where any writer is tracked in the process: in `LookupWriterValue`, check a per-owner `writerCount`/atomic "has writers" flag before `writerPresent`. Move the `Snapshot` declaration and zeroing behind `keyOK && s.MayContain(key)` (for example, split it into a `//go:noinline` slow path).
3. Keep invalidation (`writerbridge.Invalidate`) unchanged, since it is already gated on `activeStates`.

# fx-life-json-decoder-F1: falsification of life-json-decoder-F1

## Verdict per finding
- **life-json-decoder-F1: CONFIRMED.** Adjusted severity: **High**, unchanged. I independently reproduced it at HEAD 2e23b46 with Go 1.26.6 through a woven build. Two real concurrent HTTP requests each run `json.NewDecoder(r.Body).Decode(&v)`. When request B's Decoder shares request A's start bucket and A finishes while B is still waiting for body bytes, B's decoded string loses its request-body taint in **0/20 tainted** runs. The non-colliding control is 20/20 tainted. With the proposed fix, the colliding case goes to 20/20 tainted.

## Reproduction
My reproducer: `.omo/review/evidence/fx-life-json-decoder-F1/zz_fx_f1_test.go`, placed in `iast/integration/testapp/`. It does not use the finder's debug probe (`zz_review_debug.go`), and the jsonbridge package was pristine HEAD code for the woven run.
- Surface: `httptest` server with two POST requests. Their bodies are `io.Pipe`s, so the server-side `r.Body.Read` really blocks. Each handler starts a span and uses `json.NewDecoder(reader).Decode`. `reader` wraps `r.Body` (bound with `taintrequest.PropagateReader`, as in the repo's own `TestJSONDecoderMoreThanEightDocuments`) and only signals the first `Read`, so the test knows each Decode has passed its entry `Bind`.
- Ordering: A binds its slot and blocks. B allocates Decoders until it finds one whose `(&dec.d>>3)%64` equals A's bucket (or differs from it, for the control), then binds (probe 1) and blocks. A's body is written and A's request completes, which frees probe 0. B's body is then written.
- Command (in `iast/integration/testapp`): `GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 /usr/bin/time -l go tool orchestrion go test -count=1 -run TestFxF1NestedBindConcurrentRequests -v .`
- HEAD output (`head-go1.26.6.out.txt`):
  ```
  collide=false: request-B Decoder results tainted 20/20
  collide=true sample: B bucket=29 B value tainted=false
  collide=true: request-B Decoder results tainted 0/20
  BUG: request-B lost body taint in 20/20 colliding runs (A finished while B blocked in Read)
  354074624  maximum resident set size
  ```
- With the fix (`fix.diff`, `fixed-go1.26.6.out.txt`):
  ```
  zz_fx_f1_test.go:139: collide=false sample: B bucket=45 B value tainted=true
  zz_fx_f1_test.go:142: collide=false: request-B Decoder results tainted 20/20
  zz_fx_f1_test.go:139: collide=true sample: B bucket=45 B value tainted=true
  zz_fx_f1_test.go:142: collide=true: request-B Decoder results tainted 20/20
  --- PASS: TestFxF1NestedBindConcurrentRequests (0.11s)
  375570432  maximum resident set size
  ```
- The finder's unit reproducer (`zz_review_dup_slot_test.go`, run in my copy with `GOTOOLCHAIN=go1.26.6 go test -run TestReviewNestedBind -v ./internal/taint/jsonbridge/`) also fails at HEAD: `occupied=2 pointers=[0x4e203cfd400 0x4e203cfd400] depths=[1 1]`, `literal callback document is clone: false`, `FAIL`. Output: `finder-unit.out.txt`.

## Reachability
- **Default configuration, supported toolchain (Go 1.26.6): yes.** The only preconditions are ordinary server behavior:
  1. Two Decoders that are live at the same time share a start bucket. Per life-json-decoder-F2, real `json.Decoder`s (size class 320, `d` at offset 40) only ever map to 8 buckets, so any two concurrent decodes collide about 1/8 of the time. Many more concurrent decodes make a collision near-certain.
  2. The earlier-probe decode finishes while the later one is still between its `Decode` entry and `decodeState.unmarshal`, that is, while it waits in `r.Body.Read` or `readValue`. Slow or streaming clients, larger bodies, and multiple TCP reads make that window common.
- The earlier decode does not have to be request-bound or sampled. `Bind` gates only on process-wide `active()` (bridge.go:60-62), so outbound-response decodes, background jobs, and unsampled requests all occupy the probes.
- The outcome is a silent false negative on a supported path. The README's JSON row lists `json.Decoder.Decode` string values as supported, so SQLi or CMDi from a JSON request body goes unreported.
- **Go 1.27.0:** not separately reachable today. The woven `encoding/json` hooks do not compile on 1.27 (`dec.r`/`dec.d` undefined under JSON v2), which is already reported as base-test-127-F1 / sink-json-sources-F1. The slot logic is toolchain-independent, so the bug returns once that break is fixed.
- **Documented?** Only partly, and in my view it does not cover this. README.md:64-66 says "excess or colliding concurrent decodes drop provenance". That describes *admission failure*: all four probes are busy and `Bind` returns false. Here the decode *was admitted* (`Bind` returned true, and only one other slot was ever occupied), and a bookkeeping bug loses it after the colliding decode has *ended*. Even if one reads "colliding" broadly, this violates product rule 4 (no lost taint on supported paths) with free capacity, and a one-line fix exists at no cost.

## Adjusted severity
**High.** This is a false-negative vulnerability on a supported path (`Decoder.Decode` of a request body) at ordinary concurrency under default config, and my woven reproducer shows it deterministically. It is not Critical: there is no crash, no leak (both slots return to 0 after the two `Unbind`s), and no cross-request false taint.

## Root cause (file:line)
- `internal/taint/jsonbridge/bridge.go:210-224` `addDecoderState`: a single probe loop that, at each probe, checks `pointer == ours` and then `CompareAndSwap(0, 1)`. If our entry lives at probe k>0 and an earlier probe j<k has been freed, the nested bind claims j as a fresh entry (`depth=1`, `reader=nil`, `document=nil`) instead of incrementing k.
- Trigger: every `Decoder.Decode` binds `&dec.d` twice. The first bind is `iast/encoding/json/orchestrion.yml:41` (`Bind(dec.r, &dec.d)` at Decode entry). The second is `:58` (`Bind(nil, d)` at `decodeState.unmarshal`), which runs after `d.init` has published the cloned document on slot k (bridge.go:102-122).
- Effect: `findDecoderState` (bridge.go:229-240) returns the first match, j. `Literal` (bridge.go:158-167) therefore finds no document and passes the uncloned `dec.buf` bytes to the callback, which have no taint in the store, so the value is not tainted. `Unbind` still balances: the first call releases j, the second releases k.

## Minimal fix
In `addDecoderState`, look up an existing entry across all four probes before claiming a free one:
```go
if slot := findDecoderState(pointer); slot != nil {
	slot.depth.Add(1)
	return slot
}
// then the CAS(0,1) claim loop, without the per-probe pointer check
```
A given state pointer is only bound by the goroutine that owns it, in nested order, so a concurrent insert of the same pointer cannot race with this two-pass lookup. I validated the fix with my woven reproducer (`fix.diff`). Add the woven two-request test, or the finder's unit test, as a regression test.

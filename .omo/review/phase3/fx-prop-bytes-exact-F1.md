# fx-prop-bytes-exact-F1: independent verification

## Verdict per finding
- **prop-bytes-exact-F1**: **CONFIRMED**. The severity stays **High**.
  - `bytesAlias` bounds the result's end by `len(input)`, not `cap(input)`, so `ByteWindow` silently drops any valid slice that extends past the input's current length.
  - This holds even when the slice stays inside the input's capacity and its managed root.
  - I reproduced it on my own through the internal API (Go 1.26.6 and 1.27.0) and through a woven build on Go 1.26.6 with a real `io.ReadAll` request-body source.

## Reproduction
I wrote my own reproducers; the finder's were not reused. Each case uses a fresh root, because the store matches exact `(pointer,len)` keys and an earlier identical key hides the bug. My first draft was confounded exactly this way: a control `root[1:6]` made `short[1:6]` look tainted.

**1. Internal API.** Source: `evidence/fx-prop-bytes-exact-F1/zz_fx_reslice_test.go`. Output: `internal-repro-go1.26.6.txt` and `internal-repro-go1.27.0.txt`. Both exit 1.
```
cd /tmp/ddiast-review/wt/fx-prop-bytes-exact-F1 && GOMAXPROCS=4 GOTOOLCHAIN=go1.26.6 go test -p=4 -count=1 -timeout=3m -run '^TestFx' -v ./internal/taint/propagation
```
Setup: root `"SELECT-x"` with range `{Start:1,Len:6,Src:9,Marks:4}`, then `short := root[:3:8]`.
```
control short[1:3]  out="EL"    len=2 cap=7 byteRanges=[{0 2 9 4}] stringRanges=[{0 2 9 4}]
short[:5]           out="SELEC" len=5 cap=8 byteRanges=[] stringRanges=[]
short[1:6]          out="ELECT" len=5 cap=7 byteRanges=[] stringRanges=[]
short[1:6:7]        out="ELECT" len=5 cap=6 byteRanges=[] stringRanges=[]
short[:8]           out="SELECT-x" ... byteRanges=[{1 6 9 4}]   <- only because it equals the root's own key
token start "SE" ranges=[{0 2 10 0}]
grown token "SELECT" ranges=[]
FX-REPRO: 4 reslice(s) within capacity lost all provenance
```
The loss also drops taint on bytes that sit inside `short`'s visible prefix: `short[1:3]` is tainted, but `short[1:6]` is not.

**2. Woven build with a realistic customer pattern.** Source: `zz_fx_reslice_woven_test.go`, placed in `iast/io`. Output: `woven-repro-go1.26.6.txt`, exit 1. Peak RSS was 338 MB.

The test binds a reader to the request, reads the body with `io.ReadAll` (len 24, cap 512), and runs an ordinary lexer that grows the token with `tok = tok[:len(tok)+1]`. It then does an assigned conversion `name := string(tok)` and a SQL-style concatenation.
```
GOFLAGS=-p=4 GOMAXPROCS=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -p=4 -count=1 -timeout=5m -run '^TestFx' -v ./iast/io
body="name=alice'--OR-1=1 tail" len=24 cap=512 tainted=true
control value="alice'--OR-1=" bytes=true name=true query=true
lexed tok="alice'--OR-1=1" len=14 cap=507 bytes=false name=false query=false
Messages: FX-REPRO: grown token lost provenance
```
My earlier woven draft also carried two confounds, which I removed:
- A control with the same key as the token made the token's bytes look tainted.
- `string(tok)` written directly inside `+` is a documented unwrapped conversion context (README:47-49). The final test assigns the conversion first.

**3. Fix check.** Applying `fix.patch` (the bound changed from `len` to `cap`) makes reproducer 1 pass with exact ranges: `short[:5]` gives `[{1 4 9 4}]` and the grown token gives `[{0 6 10 0}]`. The existing `./internal/taint/propagation` and `./internal/taint/store` suites still pass on Go 1.26.6 (`fix-check-go1.26.6.txt`).

## Reachability
- **Reachable under the default configuration** on Go 1.26.6 and 1.27.0. No mutation, saturation, contention, or unsupported operation is involved.
- **Trigger:** any ordinary two-index or three-index `[]byte` reslice whose high bound exceeds the operand's current length but stays within its capacity. Examples:
  - lexers or scanners that grow a token (`tok = tok[:len(tok)+1]`);
  - re-extending a truncated view (`b = b[:n]` followed later by `b[:m]` with m > n);
  - `x[:cap(x)]`.
- **Sources hit it naturally:** `io.ReadAll` results carry spare capacity (cap 512 for 24 bytes), and so do sub-slices returned by `Cut`, `Trim*` and `Split*`.
- **Timing:** `ByteWindow` rejects the output at `propagation.go:482`, before any lookup that could recover the window. With no key derived, `BytesToString` misses at `conversion.go:23-29`, and so does every downstream sink lookup.
- **Not a documented limitation:**
  - README:33 lists "Two- and three-index `[]byte` slicing" as supported.
  - README:44-45 says "Supported byte-slice windows share the parent managed root".
  - The Phase-6 plan, section 10, enables "all two-index ... byte slice forms and valid three-index byte slices".
  - Neither the README nor 01-design-intent excludes beyond-length reslicing.
- The finding therefore violates product rule 4 (no lost taint on supported paths).
- A side observation: provenance for these slices depends on whether an identical key happened to be derived earlier. The `short[:8]` case hit the root's own key. Results are therefore inconsistent as well as lossy.

## Adjusted severity
**High, unchanged.** It is a false negative on an advertised, supported propagation path, reachable from ordinary customer code with no load or mutation precondition. A missed SQLi or CMDi report follows directly. It is not Critical: no crash, no behavior change, no false positive.

## Root cause (file:line)
- `internal/taint/propagation/propagation.go:53-60`, in `bytesAlias`: `end <= base+uintptr(len(input))`. The string variant at lines 42-50 is correct as written, because strings have no capacity.
- `bytesAlias` gates `ByteWindow` at `propagation.go:482` and the operator wrappers at `iast/propagation/operators.go:256-303`. The same gate is used by `ByteWindows` (line 530), `copyBytesHit` (line 450), `repeatBytesHit` (line 565), and `coarseBytesAlias` (line 620).
- The store is not the problem: `putWindow` validates against the root's full span `[base, base+cap(root))` at `store/value.go:126` through `inWindow` (value.go:35-48). The store would accept these windows; propagation never offers them.

## Minimal fix
- **Change:** in `bytesAlias`, bound the result by the input's capacity, which is the addressable region shared with the input: `end <= base+uintptr(cap(input))`. Keep `len(input)==0`/`len(result)==0` → false.
- **Why it is safe:**
  - `putWindow` still rejects anything outside the live root span or generation.
  - Ranges stay root-relative and clipped by the store.
  - For the copy, repeat and coarse callers, the change makes within-capacity results derive a window rather than be adopted as a new root. That is also the safer behavior, because the interior-slice adoption contract forbids treating an interior slice as a new root.
- **Tested:** the one-line patch is `evidence/fx-prop-bytes-exact-F1/fix.patch`. The existing suites stay green with it applied.
- **Trade-off to note:** bytes between `len(input)` and `cap(input)` may have been overwritten through an unobserved `append` on the shorter alias, and those bytes would then carry stale root ranges. README:45-46 already documents this as the mutable-alias limitation, and the current `len` bound gives no protection for in-length index writes either. It does not justify dropping in-prefix provenance.
- **Follow-ups:**
  - Add a regression case for beyond-length and within-capacity reslices, including the grown-token loop.
  - Widen the sequence oracle in `sequence_operations_test.go:51-74`, whose byte-window bounds stop at `len`.
  - Zero-length intermediates (`b[:0][:n]`) stay lost because `BytesKey` rejects empty values. That needs a separate root association, as the finder noted, and is outside this one-line fix.

## Duplicates
There is only one finding under test, so there is nothing to merge.

# fx-store-identity-gc-F1: unanchored `strings.Builder` backing can revive stale provenance

Verdict: **CONFIRMED.** `store-identity-gc-F1` and `life-cross-request-F2` are duplicate reports of one High-severity provenance bug. I independently reproduced the cross-request consequence through woven HTTP source, direct supported Builder hooks, and the SQL sink on Go 1.26.6.

Scope covered: `iast/propagation/writer.go`, `iast/propagation/orchestrion.yml`, `internal/taint/store/writer.go`, `internal/taint/propagation/writer.go`, README/design-intent, both phase-2 reports, finder-derived wrapper reproduction, and an independent woven test.

## Verdict per finding

### store-identity-gc-F1

- Verdict: **CONFIRMED**
- The claimed mechanism is real. `builderView` returns only pointer/length/capacity (`iast/propagation/writer.go:201-205`), while `WriterView.Anchor` is intentionally absent for builders (`internal/taint/store/writer.go:20-34`). A writer record retains the `*strings.Builder`, not the dropped backing. After an un-woven reset or zero assignment, GC can release that backing. If a clean allocation has equal pointer/length/capacity, `LookupWriterValue` and `SnapshotWriter` accept the old view (`internal/taint/store/writer.go:76-111,234-263`), and `publishWriterString` adopts stale ranges into the clean `String()` result (`internal/taint/propagation/writer.go:190-237`).

### life-cross-request-F2

- Verdict: **CONFIRMED**
- This is the same root cause, demonstrated at the request/span boundary. Request B's constant `SELECT id FROM customers` inherited request A's query-parameter source and generated one SQL finding on B's span while A remained live.

## Reproduction

Finder-derived direct wrapper check, Go 1.26.6:

```sh
env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 \
  go test -count=1 -timeout 5m \
  -run TestFinderBuilderStaleViewAfterAddressReuse -v ./iast/propagation/
```

Key output: both zero assignment and method-value `Reset` reused the former 16-byte backing and returned `"cleanvalue" tainted=true`. Captured output: `.omo/review/evidence/fx-store-identity-gc-F1/finder-derived-go1.26.6.out.txt`.

Independent woven reproduction, Go 1.26.6:

```sh
cd iast/integration/testapp
/usr/bin/time -l env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 \
  go tool orchestrion go test -count=1 -timeout 15m \
  -run TestIndependentPooledBuilderBleedsAcrossWovenRequests -v .
```

The independent test source is `.omo/review/evidence/fx-store-identity-gc-F1/zz_independent_builder_woven_test.go`, with woven call sites in `zz_independent_builder_helper.go`. It failed as intended:

```text
B query="SELECT id FROM customers" tainted=true attempts=0 findings=1
sources=[{http.request.parameter q x' OR '1'='1' --comment! ...}]
```

Captured output: `.omo/review/evidence/fx-store-identity-gc-F1/independent-woven-go1.26.6.out.txt`. Peak RSS was 366 MB. I also attempted Go 1.27.0; the woven build fails before this test because the pinned JSON instrumentation references removed `encoding/json.Decoder` fields (`dec.r`, `dec.d`), captured in `independent-woven-go1.27.0.out.txt`.

## Reachability

Reachable by ordinary customer code under default configuration: **yes**. The normal supported path is direct `strings.Builder.WriteString`/`String`; the trigger is an allowed un-woven mutation, such as a method-value `Reset`, a dependency/pool helper, or `*builder = strings.Builder{}`, followed by an un-woven `fmt.Fprintf`/`io.WriteString` clean rewrite. Direct Builder methods are woven, while `Fprintf` has no propagation aspect and Builder has no native invalidation hook (`iast/propagation/orchestrion.yml:1057-1247,1473-1495`; only `bytes.Buffer` has native invalidation aspects at :1593-1679).

Method-value calls not propagating are documented, but stale taint and cross-request source attribution are not a documented accepted limitation. Default sampling (30%) and the default two concurrent analyses make the concurrent case probabilistic, not unreachable. It violates the product rule requiring accurate provenance and no cross-request bleed.

## Adjusted severity

**High** for both findings. A clean SQL query can receive an SQL-injection finding carrying another request's raw source on a supported source/writer/sink path. The equal-view and GC-reuse requirements constrain frequency, but do not make the behavior an unsupported-path safe miss.

## Root cause

`iast/propagation/writer.go:201-205` constructs Builder views without a GC root. `internal/taint/store/writer.go:20-34,76-111,234-263` stores and compares those unanchored identities; `internal/taint/propagation/writer.go:190-237` publishes the stale ranges. Both reports therefore have the same root cause.

## Minimal fix

Anchor non-empty Builder backing in `builderView`, as `bufferView` already does:

```go
value := builder.String()
view := writerView(stringPointer(value), builder.Len(), builder.Cap())
if len(value) != 0 {
    view.Anchor = unsafe.StringData(value)
    view.Backing = uintptr(unsafe.Pointer(view.Anchor))
}
return view
```

This keeps a tracked Builder backing live until its bounded writer record is released at owner finish, so a fresh clean allocation cannot match the stale view. The existing capacity charge and eight-writer owner bound remain unchanged.

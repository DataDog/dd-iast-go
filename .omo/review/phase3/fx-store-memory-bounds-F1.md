# fx-store-memory-bounds-F1: verification of store-memory-bounds-F1

Verdict: CONFIRMED as a real mechanism, but re-rated Critical → Medium: the
retained bytes are caller-owned, count-bounded, request-lifetime-bounded and
verified to be released synchronously at finish; the unbounded-charge retention
is an explicitly documented README trade-off, and nothing leaks or accumulates.

Scope covered: `internal/taint/store/binding.go`, `internal/taint/store/writer.go`,
`internal/taint/store/limits.go`, `internal/taint/request/reader.go`,
`internal/taint/request/http.go` (EagerHTTP), `iast/propagation/writer.go`
(BufferWriteString), `iast/propagation/orchestrion.yml` (writer join points),
`iast/io/orchestrion.yml` (LimitReader join point), `internal/taint/iobridge`,
README "Propagation coverage", phase-1 architecture/design-intent docs; plain
and woven reproductions under go1.26.6.

## Verdict per finding

### store-memory-bounds-F1: Strong reader and writer anchors retain arbitrarily large uncharged allocations

- Verdict: CONFIRMED (mechanism), severity adjusted Critical → Medium.
- The finder's factual claims are all accurate: reader bindings and tracked
  buffer views anchor arbitrarily large caller allocations outside the byte
  budget (charge 0 / 64 for a 96 MiB payload), untracked controls retain
  nothing, and finish releases exactly the retained payload. The one implied
  characterization we reject is "unbounded memory growth": nothing grows or
  leaks; retention is transient and bounded by the request lifetime and the
  hard anchor-count limits.

## Reproduction (commands + key output lines)

All runs in the private copy `/tmp/ddiast-review/wt/fx-store-memory-bounds-F1`
(removed after the run; see `evidence/fx-store-memory-bounds-F1/README.md` for
reconstruction). Reproducer: `zz_fx_anchor_repro_test.go` (written from scratch
for this node).

1. Internal/advice-body surface, plain build:
   `env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 DD_IAST_MAX_RANGE_COUNT=64 timeout 900 go test -count=1 -timeout 10m -v -run '^TestFxAnchorRetention$' ./internal/taint/store`
   - `reader control: ... drift=0` (build-and-drop without binding retains nothing)
   - `reader bound: retained=115843072 delta=114925568 incrementalCharge=0`
   - `reader finish: ... released=100663296`
   - `buffer tracked: retained=115875840 delta=100663296 incrementalCharge=64`
   - `buffer finish: ... released=100663296`
   PASS (evidence `fx-anchor-plain.txt`).
2. Woven customer surface (`go tool orchestrion go test`):
   `env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 DD_IAST_MAX_RANGE_COUNT=64 timeout 1500 /usr/bin/time -l go tool orchestrion go test -count=1 -timeout 20m -v -run '^TestFxAnchorWovenSurface$' ./internal/taint/store`
   - `woven surface: bodyBound=true limitedReaderBound=1 retained=117399552 incrementalCharge=0`
   - `woven finish: ... released=100663296 charge=0`
   - peak woven-build RSS `351338496` bytes (351 MB, under the 4 GB note threshold).
   PASS (evidence `fx-woven-build.txt`); plain non-woven build shows
   `limitedReaderBound=0` (`fx-woven-surface-plain.txt`), proving the join point
   is what binds the `io.LimitedReader` wrapper.
3. Finder's reproducer re-run in this node's private copy
   (`TestBoundsRetainedAnchors`): identical numbers (reader/buffer × 32/96 MiB:
   retained exactly payload size, charge 0/64, finish releases all) —
   `fx-anchor-finder.txt`.

## Reachability

Reachable under default configuration on the supported toolchain
(go1.26.6 verified, plain and woven). `EagerHTTP` — the woven request-entry
advice — calls `store.BindObjectValue(owner, bodyObject, store.BindingReader)`
and binds the URL object for **every sampled request** (default sampling 30%,
default 2 concurrent requests; `request/http.go:75-76`). Any request whose body
reader wraps a large in-memory payload (middleware pattern
`r.Body = io.NopCloser(bytes.NewReader(fullBody))`, client requests with
`bytes.Reader` bodies, `io.LimitReader`/`bufio`/JSON-decoder reader chains
propagated by the stdlib-body advices) retains the complete payload graph
uncharged until scope finish. The interior-view buffer case (64-byte-capacity
view over a large allocation, charged 64) is legal but less common customer
code.

Documented limitation: yes — README "Propagation coverage", `README.md:70-77`:
"The byte budget does not bound all memory retained through these anchors. A
buffer can refer to a short slice of a larger allocation, and a bound reader can
retain other readers and their data. The number of these references is bounded,
and they are released when the tracking owner ends. Their full retained size is
not known. This is an accepted trade-off to preserve useful taint propagation."

Product-rule assessment (rule 3: "NEVER leak memory. All storage has a hard
maximum footprint, and data is dropped when saturated"):
- No leak: both reproducer paths released exactly the retained payload at
  `scope.Finish()` and charge returned to baseline. No accumulation across
  requests is possible (bindings live in the per-owner table, reset at finish).
- IAST-owned storage remains hard-bounded (256 bindings, 8 readers, 8 writers
  per owner, fixed tables). What lacks a byte bound is the *transitively
  retained caller memory* behind those bounded-count anchors — the README
  explicitly accepts this, and the alternative (dropping propagation for
  unownable allocations) would trade against rule 4.
- The only rule-3 aspect genuinely broken is the strict "hard maximum footprint"
  reading applied to retained (not owned) heap: 64 owners × (8 reader graphs +
  8 writer backings) × arbitrary per-object size has no constant byte maximum,
  and the 64-byte charge understates retention by an unbounded factor.

## Adjusted severity

Medium. The mechanism is real and reachable by ordinary code, but it is a
deliberate, explicitly documented trade-off; the retained bytes are allocations
the customer application itself made; the anchor count is hard-bounded; release
at finish is synchronous and verified; and there is no growth, leak, or
cross-request effect. It rises to High only under a product decision that rule
3's "hard maximum footprint" covers transitively retained caller memory (the
byte charge is exceeded by an unbounded factor: 96 MiB retained vs 64 charged);
it is not Critical: no panic, no unbounded growth, no leak, no behavior change,
no cross-request bleed. Single finding, no duplicates (F1's reader and buffer
aspects share one root cause: strong uncharged anchors in `binding.go` and
`writer.go`).

## Root cause (file:line, HEAD 2e23b46)

- `internal/taint/store/binding.go:29-35` — `binding{object any}` is a strong
  typed anchor; the code comment itself admits "reader graphs can retain
  uncharged payload data". `bind()` (binding.go:166-203) enforces count limits
  only (`MaxBindings=256`, `MaxReaderBindings=8`); no byte charge exists on the
  binding path.
- `internal/taint/store/writer.go:23-31` — `WriterView.Anchor *byte` strongly
  pins the backing allocation and `writerRecord.object any` retains the
  `*bytes.Buffer` (whose `buf` slice references the full backing);
  `resizeWriterChargeLocked` (writer.go:474-495) charges only
  `sizeClass(view.Capacity)` — the visible window, never the retained backing.
- Production entry points: `internal/taint/request/http.go:75-76` (EagerHTTP
  binds URL + body reader per sampled request), `internal/taint/request/reader.go:18-25`
  (BindReader), `iast/propagation/writer.go:107-118` (BufferWriteString, the
  advice injected at `bytes.Buffer.WriteString` call sites,
  `iast/propagation/orchestrion.yml:1281-1307`).

## Minimal fix

Re-establish a per-anchor byte bound while keeping the count bounds:
1. On reader binding, charge a conservative payload estimate against the shared
   request/process budgets using the same `reserveInt64` path as roots/writers,
   from sizes knowable for the concrete supported types (`bytes.Reader.Len`,
   `bytes.Buffer.Cap`, `strings.Reader.Len`), and refuse to bind (safe miss,
   counting telemetry) when the knowable payload exceeds `MaxRootBytes` (64 KiB)
   or the budget is exhausted — matching the existing `ReadAllBytes`/`adoptBodyBytes`
   behavior, which already caps adopted bodies at 64 KiB.
2. For `bytes.Buffer` views, track only views whose `Backing` is the buffer's
   own allocation start (charge full capacity); for interior views whose
   allocation base is unknowable, either drop provenance (documented safe miss)
   or retain a bounded clone of the visible window instead of `Anchor`.
3. Update README:70-77 to describe the new charged/capped behavior.
This converts "unknown retained size" into `count-limit × per-object charge ≤
budget`, restoring the hard maximum footprint at a small, documented
propagation cost.

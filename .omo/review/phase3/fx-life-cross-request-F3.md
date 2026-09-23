# fx-life-cross-request-F3: verification of life-cross-request-F3 (bytes.Buffer view match across receivers)

## Verdict per finding

**life-cross-request-F3 — CONFIRMED** (independently reproduced end to end on a woven build, Go 1.26.6, HEAD 2e23b46).

The claimed mechanism is real and I re-derived it from the code before running anything:

- A writes tainted input into `bytes.NewBuffer(pooled[:0])` via a woven `WriteString`. `UpdateWriter`
  (`internal/taint/store/writer.go:233-263`) stores a `writerRecord` in A's owner whose
  `view = (Pointer=dataPtr, Length=L, Capacity=cap, Backing=addr, Anchor=sliceData)`
  (`iast/propagation/writer.go:202-210`, `bufferView`). A returns `pooled[:0]` to a pool while still in flight.
- B takes the slice, refills it with clean bytes using `append` and reads it via `bytes.NewBuffer(b).String()`.
  Neither `append` nor `bytes.NewBuffer` is hooked (verified against `iast/propagation/orchestrion.yml:1249-1596`:
  only Write/WriteString/WriteByte/WriteRune/Reset/Truncate/String/Grow and the native invalidate hooks exist),
  so nothing invalidates A's record. B's new Buffer yields the *identical* view (same data pointer, same length,
  same cap, same anchor value).
- `publishWriterString` (`internal/taint/propagation/writer.go:215-237`) → `LookupWriterValue`
  (`internal/taint/store/writer.go:76-113`) reaches A's owner via the overlap check in `writerPresent`, and
  `writerViewIndexLocked` (`internal/taint/store/writer.go:448-462`, the view-equality loop at 453-459) matches
  B's receiver against A's record even though the receiver object pointer differs.
- `SnapshotWriter` returns A's ranges and `AdoptString` publishes B's clean string **into A's owner**. At B's SQL
  sink, `selectTaintedAnnotation` (`internal/vulnerability/tainted.go:110-127`) picks B's span from B's context and
  resolves A's source table: B's trace gets an SQL_INJECTION whose source is A's raw attacker input.

Deterministic: no GC, no timing, no address-reuse luck — only an equal-length refill and A still active. The
finder's reproducer and my own both fail 3/3 in the concurrent case and the sequential control (A finished) passes.

## Reproduction

My own reproducer (written from scratch, no shared code with the finder's harness):
`.omo/review/evidence/fx-life-cross-request-F3/zz_f3repro_test.go` + `zz_f3repro.go` (woven helpers live in the
root package so every hook-relevant call is a supported direct call site).

Command (private copy, woven, pinned toolchain):
```
cd iast/integration/testapp && GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test \
  -count=3 -timeout 15m -run TestF3PooledNewBufferCrossRequest -v .
```
Key output (fails 3/3 for `concurrent-bleed`, `sequential-control` passes 3/3; full logs
`run1-both-reproducers-go1.26.6.log`, `run2-count3-go1.26.6.log`):
```
B: query="SELECT status FROM users" tainted=true
span f3.b: {"sources":[{"origin":"http.request.parameter","name":"uid","value":"1' OR '1'='1' --xxxxxxxx"}],
 "vulnerabilities":[{"type":"SQL_INJECTION",...,"evidence":{"valueParts":[{"value":"SELECT status FROM users","source":0}]}...
CROSS-REQUEST BLEED: request B executed the constant query "SELECT status FROM users" but its span reports
 1 vulnerabilities with sources [http.request.parameter:uid="1' OR '1'='1' --xxxxxxxx"]
```
The finder's own reproducer (`TestReviewPooledSliceNewBufferViewAcrossRequests`, copied from
`.omo/review/evidence/life-cross-request/`) was also re-run and fails identically (same log file). Peak RSS of the
woven build: 371 MB (no build-memory issue).

Go 1.27.0 attempt (`run3-go1.27.0-build-fails.log`): the woven build itself fails in `encoding/json`
(`dec.r`/`dec.d` undefined) — the pre-existing orchestrion/Go 1.27 incompatibility recorded in
`base-test-127`, unrelated to this finding. Verification stands on Go 1.26.6, the go.mod toolchain.

## Reachability

- Ordinary customer code triggers it: pooling/recycling a `[]byte` and wrapping it with `bytes.NewBuffer` is a
  common pattern (serialization scratch buffers, protocol framing), and `append` refills and `NewBuffer` are
  un-woven by design. Under default configuration (`DD_IAST_ENABLED` defaults to true, 30% request sampling,
  `MaxConcurrentRequests` default 2 — both A-in-flight and B fit), it is reachable whenever both requests are
  sampled and B's fill length equals A's recorded view length (common for fixed-width IDs/tokens/records).
  The testapp's own `init()` overrides sampling to 100% only for test determinism; nothing about the mechanism
  depends on that override.
- Not a documented limitation. README "Propagation coverage" and `01-design-intent.md` document view matching
  for **`bytes.Buffer` value copies** within a request and stale ranges from un-hooked aliases *within one owner*
  ("append, copy … do not create tracked mutable roots", "Divergent or historical views can lose provenance").
  Neither document states that a different request's brand-new Buffer over recycled memory can inherit the
  originating request's provenance and emit that request's raw source value into another user's trace. This
  directly violates product rule 4 ("no cross-request taint bleed") and, since A's raw attacker input is emitted
  verbatim under the default redaction patterns (it matches neither name nor value pattern), also degrades the
  redaction guarantee for cross-user data.

## Adjusted severity

**High (unchanged).** Wrong provenance on a supported path with cross-request, cross-user attribution:
deterministic given the equal-length precondition, no GC or race required, and it both fabricates a
false-positive SQL injection on a clean query and leaks request A's input into request B's trace. Not Critical:
no crash, no unbounded memory (writer records stay within the 8-per-owner / 64 KiB-charge bounds), and it needs
the equal-length + concurrent-A + both-sampled preconditions.

## Root cause

`internal/taint/store/writer.go:448-462` (`writerViewIndexLocked`, view-equality loop 453-459): view-only matching
keys solely on `(Pointer, Length, Capacity, Backing, Anchor)` with no content validation and no restriction tying
the matching receiver to the request that created the record; combined with `internal/taint/propagation/writer.go:215-237`
(`publishWriterString`), which adopts the result into the *record's* owner (A) while a foreign active owner is
accepted by design at the sink (`internal/vulnerability/tainted.go:110-127`).

## Minimal fix

Store a bounded content fingerprint of the visible bytes in `writerRecord` (the backing is anchored and at most
64 KiB; maintain an incremental FNV-1a updated only over each written span in `UpdateWriter`/`TruncateWriter`,
and reset it in `AdoptBufferWriter`), and verify it in `SnapshotWriter` before returning ranges on a
cross-receiver view match (`record.writers[index].object`'s pointer ≠ the querying receiver's pointer). On a
mismatch, drop the record (the slice was refilled outside tracking). This preserves the legitimate same-request
value-copy feature (identical content) and closes the recycled-slice bleed. Alternatively/additionally, restrict
view-only matches to receivers first seen through a hooked copy by the same owner, and document that pooled
backings must be refilled through tracked writes.

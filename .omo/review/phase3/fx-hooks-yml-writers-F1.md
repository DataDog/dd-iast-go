# fx-hooks-yml-writers-F1: Buffer writer anchors retain unbounded caller allocations

Verdict: CONFIRMED — reproduced independently at the woven call-site surface (Go 1.26.6) and at the store internal API (Go 1.26.6 and 1.27.0): 128 bytes charged, 128 MiB retained across GC with all customer references dropped, released by owner finish.

Scope covered: `iast/propagation/writer.go` (bufferView, Buffer wrappers), `internal/taint/store/writer.go` (WriterView, writerRecord, UpdateWriter, resizeWriterChargeLocked, releaseWritersForFinishLocked), `internal/taint/store/limits.go`, `internal/taint/propagation/writer.go`, `iast/internal/propagationtest/writer.go`, phase-2 report and its evidence, `.omo/review/phase1/01-design-intent.md`.

## Verdict per finding

### hooks-yml-writers-F1: Buffer writer anchors retain unbounded caller allocations
- Verdict: CONFIRMED (mechanism real at HEAD 2e23b46 and reproduced independently; finder's claim accurate, including the 128-byte charge and request-bounded release).
- Original severity: High. Adjusted severity: High.
- Same root cause; single finding, no duplicates.

## Reproduction

Private copy: `/tmp/ddiast-review/wt/fx-hooks-yml-writers-F1` (removed after verification). Reproducers are mine, written for this phase (not the finder's files).

1. Woven surface (most realistic; ordinary `bytes.Buffer` usage in the customer-call-site fixture package):
   - `iast/internal/propagationtest/fx_retention.go`: `bytes.NewBuffer(scratch[:0:16])` over a 16 MiB `scratch`, woven `buffer.WriteString(taintedInput)`, all customer references dropped on return (evidence: `propagationtest-fx_retention.go`).
   - `iast/propagation/fx_retention_test.go`: `TestFxBufferInteriorViewRetainsCallerAllocation` (evidence: `woven-fx_retention_test.go`).
   - Command: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -count=1 -timeout=15m ./iast/propagation -run TestFxBufferInteriorViewRetainsCallerAllocation -v` (GOFLAGS=-p=4; peak RSS 354 MB).
   - Key output (`woven-retention-go1.26.6.txt`):
     `retained while owner active: 112 MiB (caller scratch allocations, all customer references dropped)` — exceeds the documented 24 MiB whole-feature envelope ~4.7x;
     `released by owner finish: 128 MiB` — proves the writer anchors are the retainers and release is request-bounded.
2. Store internal API, charging vs retention made explicit (`store-fx_retention_test.go`):
   - `GOTOOLCHAIN=go1.26.6|go1.27.0 go test -count=1 -timeout=10m ./internal/taint/store -run TestFxInteriorViewAnchorRetainsBacking -v`
   - Key output (`store-retention-go1.26.6.txt`, `store-retention-go1.27.0.txt`): `store charged=128 bytes for 8 writer records`, `retained while owner active: 128 MiB`, `released by owner finish: 140 MiB`. Identical on both toolchains.
3. Go 1.27.0 woven build: fails for an unrelated orchestrion/toolchain reason (`never-build-twice ... # encoding/json`, `woven-go1.27.0-build-incompatibility.txt`); the GC-liveness mechanism was confirmed on 1.27.0 via the store-level run above.

## Reachability

Reachable under default configuration on the supported toolchain: any woven customer application that seeds a `bytes.Buffer` with a small full-slice view of a larger allocation (`bytes.NewBuffer(big[:0:small])`, e.g. a pooled scratch/arena buffer) and writes tainted HTTP-derived data into it creates an anchor into the whole allocation for the life of the request. No special configuration. Two honest mitigating facts: (a) buffers whose visible capacity exceeds 64 KiB are not tracked at all (`validWriterView`), so amplification requires the interior-view pattern, not merely large buffers; (b) retention ends at owner finish — it is delayed reclamation, not unbounded growth.

Documented limitation: yes. `01-design-intent.md` ("Strong request-bounded receiver anchors are intentional; their full allocation retention is not charged exactly, but the number of anchors is bounded and release occurs with owner finish") and the `WriterView` doc comment (`internal/taint/store/writer.go:26`). The finding nonetheless stands as a legitimate challenge to a documented trade-off because it breaks product rule 3 ("all storage must guarantee a maximum memory footprint"): the design's stated safety argument — bounded anchor counts bound retention — is unsound, and the design's own verification checklist requires "the final retained heap stays within the documented 24 MiB envelope under saturation", which this pattern violates by an arbitrary factor.

## Adjusted severity

High (unchanged). Justification: the brief's High band is "a bound that can be exceeded by a large factor" — the advertised 24 MiB retained-heap envelope is exceeded ~5x by a 3-line customer pattern and by an arbitrary factor as caller allocations grow (16 bytes charged per 16 MiB retained). It is not Critical: no panic/behavior change, release is synchronous at owner finish, and the retained memory is caller-owned and usually still live, so real-world impact is delayed reclamation rather than new allocation.

## Root cause

- `iast/propagation/writer.go:212-216` — `bufferView` stores a typed `Anchor = unsafe.SliceData(buffer.Bytes())`; a pointer into an interior view pins the entire caller allocation.
- `internal/taint/store/writer.go:28-34` — `WriterView.Anchor *byte` is retained in the persistent `writerRecord`; `:37` — `writerRecord.object any` retains the `*bytes.Buffer` receiver, whose `buf` slice independently pins the same allocation.
- `internal/taint/store/writer.go:220` with `resizeWriterChargeLocked` (writer.go:486-502) — the store charges `sizeClass(view.Capacity)` only, i.e. the visible capacity (`writerView` also clamps visible capacity to 64 KiB, `iast/propagation/writer.go:227-231`), never the retained allocation.

## Minimal fix

Do not retain strong references whose retained size cannot be bounded. Concretely: only set `view.Anchor`/`Backing` (and admit the writer record) when the hook observed the full backing allocation — e.g. backing grown through the instrumented `BufferGrow` path or otherwise known to be bounded by the charged capacity; for caller-seeded interior views, leave `Anchor` nil and drop writer provenance (consistent with the design's drop-rather-than-retain rule). This must also stop retaining the receiver `*bytes.Buffer` for unbounded backings, since the `buf` slice alone pins the allocation; replace with numeric-pointer identity plus the existing `writerDirty`/`InvalidateBuffer` overlap invalidation and per-hook view revalidation (accepting the conservative stale-address-reuse trade-off already accepted elsewhere in the design).

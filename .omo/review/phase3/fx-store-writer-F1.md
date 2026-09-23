# fx-store-writer-F1: verification of store-writer-F1 (cross-request writer wipe)

## Verdict per finding

### store-writer-F1 — CONFIRMED
- Original severity: High (cross-request, false negative on a supported path).
- Adjusted severity: **High** (unchanged). Justification: silent loss of all Builder/Buffer taint of a request whenever *unrelated* writer activity in another request overlaps its writer critical section; wrong provenance on a path the README explicitly supports, with zero-loss controls at every surface.
- The mechanism, the loss rate (399/400 finder; 400/400 my rerun; 220/300 woven), and the reachability are all real. The finder's line citations check out exactly (`writerPresent` writer.go:412-433, "conservative possible match" return at 432; dirty stores at 89/94 in `LookupWriterValue` (writer.go:76) and 376/381 in `InvalidateBuffer` (writer.go:366)).

## Reproduction (all in the private copy; GOTOOLCHAIN=go1.26.6)

1. **Finder's reproducer** (rerun independently, evidence `fx-finder-repro.out.txt`):
   `go test -count=1 -run TestReviewCrossRequest -v ./iast/propagation/`
   → `B builder checks=400 lost-taint=400; A clean buffer writes=12635` — FAIL (finder reported 399/400; I got 400/400).
2. **My store-level deterministic reproducer** (`zz_fx_f1_store_test.go`, evidence `fx-store.out.txt`):
   `go test -count=1 -run 'TestFxF1' -v ./internal/taint/store/`
   - `TestFxF1UnrelatedLookupDirtiesCriticalSectionOwner`: while owner B holds `writersMu` with `writerVersion` odd (the exact state of every wrapped Builder/Buffer write), a single `LookupWriterValue` for a *unrelated* receiver (different pointer, no backing overlap) leaves `B.writerDirty=true`; after B leaves the section, `SnapshotWriter=false, charged=0, writerCount=0` — B's entire writer state wiped. Deterministic, no race required.
   - `TestFxF1ConcurrentUnrelatedLookupWipeRate` (no artificial locks, real ops only): `ops=20000 B-update-losses=7500` (37.5%).
3. **My public-wrapper reproducer** (`zz_fx_f1_crossreq_test.go`, evidence `fx-public.out.txt`):
   `go test -run TestFxF1CrossRequestBuilderTaintWipedByUnrelatedBuffer -v ./iast/propagation/`
   → 225/300, 3/300, 175/300 lost across runs; control (`FX_F1_NO_A=1`) → 0/300, PASS.
4. **My woven reproducer** (`zz_fx_f1_woven_test.go`, evidence `fx-woven.out.txt` / `fx-woven-control.out.txt`) — the most realistic surface, plain stdlib customer code (`strings.Builder`, `bytes.Buffer`, no IAST imports) under `go tool orchestrion go test`:
   → `ops=300 lost-taint=220 A-unrelated-buffer-writes=4754` — FAIL; control → 0/300 PASS. Warm woven-build peak RSS 346 MB (cold build not separately timed; no >4 GB signal observed).

## Reachability

- **Default configuration, supported toolchain (go1.26.6): yes.** The woven run uses only ordinary customer code shapes (request-scoped taint source, `strings.Builder` accumulation, concurrent `bytes.Buffer` logging-style writes in another request). Default `MaxConcurrentRequests` is 2, i.e. two overlapping requests — the minimum needed to trigger this — are admitted by default whenever IAST is enabled and sampled. Any request that touches a Builder/Buffer while any other active request performs any writer operation can be wiped; the loss is silent (no error, and the uncounted dirty paths of F6 hide it from `drops.contention`).
- **Documented limitation: no.** README "Propagation coverage" lists direct `strings.Builder`/`bytes.Buffer` writes as supported; the documented drops concern overlapping views, >64 KiB decoder documents, and decoder-slot collisions — nothing authorizes wiping an *unrelated* owner's state. This breaks product rule 4 ("no lost taint on supported paths") and is not the intended conservative drop of the receiver's own state under contention.

## Adjusted severity

**High** (unchanged from the finder). Lost provenance on a supported path, cross-request blast radius (an owner loses *all* its writer entries, not one), silently, under default concurrency. Not Critical: no crash/deadlock/race on host state, memory stays bounded, and the drop is a false negative, not a false positive or data leak.

## Root cause (file:line)

- `internal/taint/store/writer.go:412-433` — `writerPresent` does 3 back-to-back version reads with no wait; whenever `writerVersion` is odd (owner inside any writer critical section) it returns `true` ("conservative possible match") *even when no pointer or backing interval matches*.
- `internal/taint/store/writer.go:87-96` (`LookupWriterValue`) and `373-386` (`InvalidateBuffer`) — on the resulting `TryRLock`/`TryLock` failure they set `writerDirty` on the whole owner; `clearDirtyWritersLocked` (writer.go:495-501) then drops *every* writer entry of that owner at its next writer operation.
- Callers: every wrapped writer op in `internal/taint/propagation/writer.go` calls `LookupWriterValue` scanning all 64 owners, and every native `bytes.Buffer` mutation in the process calls `InvalidateBuffer` (`writerbridge` → `propagation/writer.go:26-32`), so request A's activity repeatedly scans request B's owner.

No duplicate set: this JSON contains one finding; it is the single root cause. (Phase-2 F6 — dirtying not counted in `drops.contention` at writer.go:94 and 381 — is a secondary quality aspect of the same code paths, reported separately there; my deterministic repro confirms it: `drops` stays 0 while the wipe happens.)

## Minimal fix

Do not treat "version odd" as a match: in `writerPresent`, spin a small bounded number of loads (e.g. up to 64, no sleeping) until the version is even, and return the stable snapshot result; if still inconclusive after the bound, return a match only for slots whose pointer or overlapping backing interval actually matches (per-slot answer, not a whole-owner `true`). Callers should then dirty only the affected slots (or skip the owner when nothing matches), never the entire owner on an inconclusive read. Additionally increment `drops.contention` on every dirtying path (also fixes F6).

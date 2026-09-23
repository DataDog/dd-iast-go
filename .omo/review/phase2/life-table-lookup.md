# life-table-lookup: request source index and provenance lookup
Verdict: Source attribution, capacity, and owner-generation checks are sound in the paths reviewed, but a controllable hash-boundary collision defeats the randomized probe distribution and materially increases request hot-path work.
Scope covered: `internal/taint/request/{table,lookup,owner,source,reader,http,lazy}.go`, `internal/taint/store/{lookup,owner,root,limits}.go`, request table/admission/owner/lookup-related tests, and the phase-1 architecture/design/research checks.

## Findings

### life-table-lookup-F1: Embedded NULs force a full source-index probe chain
- Severity: High
- Category: perf
- Location: internal/taint/request/table.go:130-151,208-220
- Claim: `hashValue` hashes `origin || name || NUL || value` without framing the name. A NUL already in the name or value is indistinguishable from the separator, so 256 distinct `(name,value)` tuples obtained by moving the separator within one NUL-containing byte sequence have identical hashes for **every** per-table random seed. Full-tuple equality keeps source IDs correct, but linear probing needs 256 probes for the last insertion and 32,896 probes for the 256 insertions, rather than the intended low-load behavior. `url.ParseQuery` accepts these percent-encoded NUL-bearing tuples and a live `Analysis.ManageString` admits all 256. This is bounded, not a provenance error, but it makes attacker-controlled source admission roughly two orders of magnitude more probing than intended while holding `sourceMu`.
- Evidence: `.omo/review/evidence/life-table-lookup/zz_review_collision_test.go` and `.omo/review/evidence/life-table-lookup/collision-race.out.txt`. In the private copy run `GOTOOLCHAIN=go1.26.6 go test -race -count=1 -run ^TestReview -v -timeout=5m ./internal/taint/request`. Captured output: `final insertion probes=256; total insertion probes=32896`, `adversarial source tuple needs 256 probes (target <=64)`, and `live request admitted all 256 colliding sources`. The first test deliberately fails on the excessive probe count; the second passes.
- Fix: Frame the name unambiguously before hashing the value, for example hash its fixed-width length between the origin and name (or use a separate keyed field hash). Preserve the same framing for string and byte-valued sources, then retain the full equality check.

### life-table-lookup-F2: Oversized sources are fully hashed before the root limit is checked
- Severity: Medium
- Category: perf
- Location: internal/taint/request/owner.go:146,180,213
- Claim: `Analysis.TaintString`, `ManageString`, and `TaintBytes` call `prepareString`/`prepareBytes`, which hashes the complete value at `table.go:130-131,208-220`, before the store rejects a value or name over 64 KiB (`store/root.go:71,153`). A huge HTTP path/header/lazy parameter or direct taint input therefore consumes linear hashing work despite guaranteed admission failure; repeated attempts pay the cost again, including when the 256-source table is already full.
- Evidence: static reasoning only (NEEDS-REPRO). The relevant input guards occur in `store/root.go:67-72,149-154`, after the hash and probe. No throughput figure is asserted.
- Fix: Apply the store's cheap length/capacity eligibility guard before attempting source-table preparation on these live-analysis paths, while retaining unchanged caller values on rejection.

## Checked and found correct
- `Table` has 256 source records and 512 index slots, uses full tuple comparisons rather than trusting the hash, preserves existing IDs when full, and clears retained strings and the index on `Reset`; existing table property/boundary tests and the collision reproducer confirm identity survives collisions.
- New live sources commit a table ID only after a managed root publishes successfully; the request admission tests cover rejection, duplicate reuse, and capacity without phantom source entries.
- `VisitString`/`VisitBytes` gate on the active manager and store index, copy bounded owner snapshots, then `copySources` checks owner index, ID, generation, directory pointer and active state under `sourceMu` before copying complete source records. It never calls a visitor while holding the source lock.
- `Finish` clears the directory, locks and resets the table before freeing the permit; a stale analysis handle cannot finish a reused permit slot. Store lookup validates owner/root generations before resolving a range. The existing request package passed `GOTOOLCHAIN=go1.26.6 go test -race -shuffle=on -count=1 -skip ^TestReviewHashDelimiterCollision$ -timeout=15m ./internal/taint/request` in the private copy.
- An observed lookup can legitimately drop provenance when `TryLock` fails, as documented. No unbounded probe, table eviction, or source metadata crossover on slot reuse was found.

## Not covered / open questions
- No instrumented HTTP end-to-end run or wall-clock throughput measurement was made for the collision case; the reproducer verifies URL-query representability and the actual live source admission/probe sequence without weaving.
- Did not run concurrent GC/address-reuse stress for the store's separate numeric-address index; review here is limited to the request source table and its lookup boundary.

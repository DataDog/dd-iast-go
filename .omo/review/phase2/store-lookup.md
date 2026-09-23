# store-lookup: bounded value-index lookup, mutation, and overflow review
Verdict: One High provenance defect: stale matching index slots can exhaust the four-entry candidate buffer and hide a live owner's taint snapshot.
Scope covered: `internal/taint/store/{lookup,mutation,store,limits,overflow}.go`; related `value.go`, `root.go`, `owner.go`; store bounds, churn, contention, mutation, saturation, memory, and race tests; root `README.md`; `internal/config/config.go`.

## Findings
### store-lookup-F1: Stale matches consume the live-owner snapshot budget
- Severity: High
- Category: false-negative
- Location: `internal/taint/store/lookup.go:125-129`
- Claim: `Lookup` admits only `MaxSnapshotOwners` matching slots into `windows` before it validates the slot's owner generation, state, and root generation. Four completed owners can therefore leave stale matching slots in the fixed shard; a fifth, live owner with the same key is skipped at the candidate-cap branch. The later validation discards all four stale candidates and returns an empty snapshot, losing taint on a live, supported owner rather than using the available snapshot capacity. This contradicts the owner-separated cross-owner lookup contract and yields a false-negative sink result until another insertion happens to reclaim the stale slots.
- Evidence: `.omo/review/evidence/store-lookup/stale_fanout_repro_test.go` and `.omo/review/evidence/store-lookup/stale_fanout_repro.out`; `cd /tmp/ddiast-review/wt/store-lookup && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -timeout 15m ./internal/taint/store -run '^TestReproLookupSkipsLiveOwnerAfterFourStaleMatches$' -count=1 -v`; captured output shows `expected: 1`, `actual : 0`.
- Fix: Retain and validate every matching candidate in the bounded `ProbeLimit` search window before applying the `MaxSnapshotOwners` output cap (a fixed `[ProbeLimit]lookupWindow` is sufficient). Count a fanout drop only after four complete live entries have been accepted; continue to perform the existing locked validation before publishing an entry.

## Checked and found correct
- Keys are bounded, non-owning numeric comparisons: invalid, empty, and tombstone keys are rejected; lookup never reconstructs a pointer.
- Mutation claims the next root generation before publication and removes prior-generation value accounting, so a failed publication leaves the old byte provenance invalid rather than stale.
- Root, request, and process limits are fixed and aligned with the documented envelope: 64 owners, 16,384 process values, 4,096 request values, 8 MiB process root charge, 2 MiB request root charge, 512 roots/owner, 256 values/root, 64 ranges, 256 overflow blocks, 256 shards, 128 slots/shard, and 64 probes.
- README runtime configuration agrees with `internal/config/config.go` for `DD_IAST_MAX_RANGE_COUNT` (1--64, default 10); no configuration claim controls the fixed store ceilings.
- Overflow allocation is fixed-pool and contention-safe: mutation keeps the guaranteed inline prefix when overflow allocation fails, releases a prepared block on root-lock failure, replaces and frees the prior block atomically with the root record, and finish returns all blocks.
- Targeted race verification passed under Go 1.26.6: lookup lock contention, collision probe cap, overflow replacement/contention, concurrent lookup/mutation/finish, and root/value process/request limits all passed with `go test -race`.

## Not covered / open questions
- This node did not perform an end-to-end woven SQL or command-sink scenario. The reproducer exercises the store API directly, which is sufficient to show the dropped live snapshot but does not measure application-level frequency.
- `MayContain` can still report stale index candidates until a write lazily reclaims them; that is a documented slow-path-cost question, not a separate correctness finding from this review.

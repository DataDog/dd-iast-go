# fx-store-lookup-F1: verification of store-lookup-F1 (stale matches consume the live-owner snapshot budget)

## Verdict per finding

### store-lookup-F1 — **CONFIRMED** (mechanism), severity adjusted **High → Medium**
- **Claim re-checked at HEAD 2e23b46:** real. `Store.Lookup` (`internal/taint/store/lookup.go:104-129`) fills a fixed `[MaxSnapshotOwners]lookupWindow` candidate buffer with the *first four* matching index slots before any owner/root liveness validation; the fifth matching slot hits the `windowCount >= len(windows)` branch (lookup.go:125-129), increments `drops.fanout`, and is skipped. Validation (lookup.go:133-198) then rejects all four stale windows (dead owner state, lookup.go:140-143) and returns an empty snapshot, so `MayContain` stays hot while `Lookup` yields nothing. `Finish` never touches the shard index (`store/owner.go:155-215`), so finished owners leave exactly such stale slots.
- **Independently reproduced on three surfaces** (see Reproduction). The finder's claim about the *mechanism* is fully accurate, including the "returns an empty snapshot" consequence.
- **However, the claimed production impact does not hold:** the 4-stale+1-live arrangement requires **five owners holding index slots on the same address key simultaneously**, and no woven (customer-reachable) path can construct that state (see Reachability). The finding is therefore an internal-contract violation, not a customer-reachable false negative.

## Reproduction (commands + key output)

All runs in the private copy `/tmp/ddiast-review/wt/fx-store-lookup-F1`, `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -timeout 15m -count=1 -v`. Test files are preserved under `.omo/review/evidence/fx-store-lookup-F1/`.

1. **Finder's reproducer, rerun verbatim by me** (`fx_finder_repro_test.go`, store API):
   `go test ./internal/taint/store -run '^TestReproLookupSkipsLiveOwnerAfterFourStaleMatches$'`
   → `expected: 1 / actual : 0` (`repro_store_lookup.out`).
2. **My own reproducer, propagation surface** (`fx_stale_fanout_repro_test.go`): the exact path a woven build executes for a stdlib copy (`MayContain` gate → `Store.Lookup` → `publishStringCopy`). Five live owners adopt one shared allocation, four finish, then `propagation.CopyString(shared, strings.Clone(shared))` publishes the copy **untainted**:
   → `TestFxReproCopyStringLosesLiveOwnerBehindFourStaleSlots: expected: 1 / actual : 0` (`repro_propagation.out`).
   Controls: `TestFxControlOneStaleOneLiveIsPreserved` PASS (contract holds below the cap, matching the authors' `TestPublishHelpersDropStaleAndPreserveLiveOwner`); `TestFxControlSequentialChurnReclaimsStaleSlots` PASS — four owners that all finish plus a *new* owner adopting the same address get their dead slots reclaimed by `putWindow` (`value.go:167-175`), so the new live owner's taint survives. Sequential churn cannot construct the failing state.
3. **Request body-adoption surface** (`fx_stale_fanout_request_test.go`, from an earlier run of this node, executed and captured by me): five concurrent analyses adopting one shared `ReadAllBytes`-style result, four finished → `snapshot entries for the live owner's key: 0`, `expected: 1 / actual : 0`; controls (four adopters; default concurrency 2; fresh per-request buffers) all PASS (`request_level_repro.out`).

## Reachability

**Not reachable from ordinary customer code under default configuration.** The failing state needs five concurrent same-key slot holders because `putWindow` reclaims every dead-owner slot it probes during a same-key insert (control 2 proves this empirically); slots preceding a live insert must therefore have had live owners at insert time.

- Default `DD_IAST_MAX_CONCURRENT_REQUESTS = 2` (`internal/config/config.go:81`) caps concurrent analyses/owners at 2 — five concurrent owners already impossible by default.
- Even with concurrency raised to 64 (supported range), every woven adoption site structurally caps same-address adoptions at `MaxSnapshotOwners = 4`: source taints clone into single-owner roots (`root.go:26-67`); propagation fanout publishes iterate `snapshot.Len() ≤ 4` (`propagation.go:184-196`, `string_exact.go:104`, `bytes_exact.go`, `json.go:56`, `conversion.go:38`); writer publishes use `LookupWriterValue` with a `[MaxSnapshotOwners]` refs array (`propagation/writer.go:181`; `store/writer.go:76-118`); reader body adoption (`request/reader.go:48,71`) uses `LookupObject` over a `[MaxSnapshotOwners]` refs array (`store/binding.go:126-163`). A fifth same-key owner is dropped at the refs cap before it could ever hold a slot. The phase-1 design intent (01-design-intent.md:71) documents this same "at most four owners per snapshot/publication" bound.
- `AdoptSourceBytes`/`AdoptString`/`AdoptBytes` adopt the caller's allocation directly without cloning (`root.go:181-268`), which is how the multi-owner state is constructed in tests — but no woven join point passes a *shared, already-adopted* allocation for a fifth owner.
- **Documented limitation?** No. README/design-intent document the four-owner fanout *bound*, not "stale entries may hide a live owner"; the authors' own test asserts the opposite. So this is an unintended contract break — but of an internal contract, in a state only reachable through `internal/` APIs.

## Adjusted severity

**Medium** (original High). The false-negative mechanism is real and violates the store's asserted stale/live separation (product rule 4), but the triggering state cannot be constructed through any customer-reachable woven path under default (or even maximum) configuration; impact is limited to the internal API contract and to future call sites that might adopt a shared allocation for a fifth owner.

## Root cause (file:line)

`internal/taint/store/lookup.go:117-129` — the `MaxSnapshotOwners` candidate cap is applied to *unvalidated* matching slots during the probe scan, before owner generation/state and root-generation validation (which happens in the second loop, lookup.go:133-198). Single root cause; the phase-2 input list contained only this one finding, so there is no duplicate cluster to adjudicate.

## Minimal fix

In the probe loop, only let a matching slot consume a window slot when its owner *plausibly* live: before admitting into `windows`, read `s.owners[slot.ownerIdx].generation.Load()` and `state.Load()` (atomics, no lock) and skip candidates whose generation differs from `slot.ownerGen` or whose state is not `stateActive`. Stale candidates then no longer consume the budget; the existing locked validation in the second loop remains authoritative and unchanged (it already re-checks everything and caps `out.count` at `MaxSnapshotOwners`, lookup.go:182). Alternative, slightly costlier fix: size the candidate buffer `[ProbeLimit]lookupWindow` (64 entries ≈ 1.8 KB stack) and keep the existing publish cap; the fanout drop counter should then count only drops of *plausibly live* owners.

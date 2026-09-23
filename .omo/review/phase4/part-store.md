# Part report: taint store (`internal/taint/store`)

HEAD 2e23b46. **After dedup: Critical 0, High 9, Medium 13.** Every High entry cites its phase-3 `fx-*` verdict. The phase-3 adjusted severity is used for all High and Critical inputs. Both original Criticals (store-memory-bounds-F1 and -F2) were downgraded in phase 3. Evidence paths are relative to `.omo/review/`. Entries H7 and H8 were found by the store node, but their code lives in `internal/spans` and `internal/taint/redaction`. They are listed here so nothing is lost, and the final consolidation should dedup them with the spans and sink parts.

## 1. Part verdict

The store is **crash-safe and data-race-free, but not provenance-safe under concurrency or memory reuse.** Nodes found no panic, no Go-memory-model race, and no deadlock: a 15-minute model fuzz run, 69.7M ops over 39 `-race` stress seeds, and `-race -count=50` all came back clean. The lock graph is acyclic, and fixed quotas and accounting are exact in single-threaded models.

The defects are logical ones:
- A finished request's handle can publish into the next request that reuses its owner slot (H1).
- Writer state is matched by numeric view identity. An unanchored Builder backing (H2) or a recycled Buffer backing seen by another receiver (H3) gives clean data another request's source, and these produced real false SQL_INJECTION reports in woven apps.
- One request's writer activity wipes another request's writer provenance (H4).
- A fully occupied index shard wedges for the process lifetime (H5).

On memory, the fixed arrays and charges fit the roughly 21.6 MiB envelope, but strong reader/buffer anchors and evidence strings retain uncharged caller memory well past 24 MiB until request or span finish (H6, H7). The retained memory is request-bounded, not a leak. The part is **not customer-ready** until H1 through H5 are fixed.

## 2. Findings by root cause

### H1. Stale owner handle passes `beginWrite` during slot reuse and publishes into the successor request
- Severity: **High**. Status: **CONFIRMED** (`phase3/fx-store-concurrency-F1.{md,json}`, `phase3/fx-store-stress-F1.{md,json}`).
- Location: `internal/taint/store/owner.go:53-59` (Acquire), `owner.go:127-149` (`alive`/`beginWrite`), `binding.go:77-108,168-207`, `writer.go:117-335`.
- Contributing ids: store-concurrency-F1, store-stress-F1, crash-deadlock-F1.
- Mechanism: `Acquire` recycles a Dead slot by running `generation.Add(1)` and then `state.Store(stateActive)` without taking `lifecycleMu`. `alive()` loads generation and state as two separate atomics. A stale handle can therefore read the new generation's `stateActive` and pass. After that, `BindObject*`, `UpdateWriter`, `AdoptBufferWriter`, `TruncateWriter`, `ResetWriter` and `claimMutation` never re-check. The old request's objects and owner-local source IDs land in the successor, whose source table then resolves them to the wrong source, which can produce a false positive. Production callers hold raw `*Owner` handles at `request/reader.go:23-38`, `request/http.go:74` and `propagation/writer.go:110-132`, and reuse of slot 0 is the common case at default concurrency 2.
- Reproduction: the deterministic seam repro is `evidence/fx-store-concurrency-F1/fx-seam-deterministic.txt` (`go test -run 'TestFxSeam|TestFxControl' ./internal/taint/store/`). Natural scheduling on unmodified code failed in 47s (cross_generation_bindings=1) with `evidence/store-concurrency/stale-bind-natural.txt`. `evidence/fx-store-stress-F1/fx-min-store-level.out.txt` reproduced it in 46s. Caveat from fx-store-stress-F1: 2x300s of realistic woven-surface runs did not hit it, which bounds reachability but does not refute it.
- Minimal fix: in `Acquire`, take `lifecycleMu.Lock()` around the generation bump and the state store. Alternatively, pack generation and state into one atomic word and re-validate under the `lifecycleMu` read lock inside every writer entry point.

### H2. `strings.Builder` writer views are unanchored, so reuse of a freed address revives stale or cross-request taint
- Severity: **High**. Status: **CONFIRMED** (`phase3/fx-store-identity-gc-F1.{md,json}`, `phase3/fx-crash-diff-bytes-F1.{md,json}`).
- Location: `iast/propagation/writer.go:202-205` (`builderView`, no Anchor). The match happens at `internal/taint/store/writer.go:23-34,76-111,234-263,448-451`.
- Contributing ids: store-identity-gc-F1, store-writer-F2, crash-diff-bytes-F1, life-cross-request-F2.
- Mechanism: the writer record retains only the `*strings.Builder` receiver, and the view is the numeric tuple `{ptr,len,cap}`. Some resets and rewrites are not woven: zero assignment, a method-value `Reset`, `fmt.Fprintf`, and `io.WriteString`. After one of these, GC can free the old backing. A clean rewrite at the same address with the same len and cap then matches, and `publishWriterString` adopts the clean `String()` with the old ranges. If the builder is pooled across requests, B's constant query is reported as SQLi sourced from A.
- Reproduction: woven HTTP to builder to `database/sql`, run with `go tool orchestrion go test -run TestIndependentPooledBuilderBleedsAcrossWovenRequests .` in `iast/integration/testapp`. Output is in `evidence/fx-store-identity-gc-F1/independent-woven-go1.26.6.out.txt` and `evidence/fx-crash-diff-bytes-F1/repro-woven-http-sql-go1.26.6.txt` (88/88 false reports when the address is reused, 0 without reuse).
- Minimal fix: anchor the builder backing the same way `bytes.Buffer` does (`Anchor = unsafe.StringData(b.String())` or equivalent). A fix diff was validated at `evidence/store-identity-gc/builder-anchor-fix.diff`.

### H3. A `bytes.Buffer` view is matched across receivers, so a recycled slice gives A's ranges to B's new Buffer
- Severity: **High**. Status: **CONFIRMED** (`phase3/fx-life-cross-request-F3.{md,json}`). Cross-part: this was found by the life part, but the code is in the store.
- Location: `internal/taint/store/writer.go:448-462` (`writerViewIndexLocked`), `writer.go:233-263`, and `internal/taint/propagation/writer.go:202-237`.
- Contributing ids: life-cross-request-F3.
- Mechanism: when no entry exists for the receiver pointer, `writerViewIndexLocked` accepts *any* entry whose `(pointer,len,cap,backing,anchor)` equals the view. Suppose A wrote tainted input into `bytes.NewBuffer(pooled[:0])`, and B refills the pooled slice with `append` and calls `bytes.NewBuffer(b).String()`. B's view then matches A's entry, and the result is adopted with A's source. The trigger is deterministic and needs no GC or special timing.
- Reproduction: `evidence/fx-life-cross-request-F3/zz_f3repro_test.go`, run with `go tool orchestrion go test -run TestF3PooledNewBufferCrossRequest .` in the integration testapp. It fails 3/3, and the sequential control is clean.
- Minimal fix: restrict the view-equality fallback to the value-copy transfer case (`AdoptBufferWriter` inside the same owner), and never use it for a publish on a different receiver. Alternatively, require the receiver pointer to match.

### H4. Writer activity in another request wipes an owner's entire writer state
- Severity: **High**. Status: **CONFIRMED** (`phase3/fx-store-writer-F1.{md,json}`).
- Location: `internal/taint/store/writer.go:85-96` (`LookupWriterValue`), `writer.go:372-386` (`InvalidateBuffer`), `writer.go:412-433` (`writerPresent`).
- Contributing ids: store-writer-F1. Related Lows: store-writer-F4, store-writer-F6.
- Mechanism: `writerPresent` answers "possibly present" whenever `writerVersion` is odd, which means the owner is inside a writer critical section. When the following `TryRLock` fails, the caller sets `writerDirty=true`, and `clearDirtyWritersLocked` then erases every Builder and Buffer entry of that owner. Any unrelated Buffer or Builder hook in another request can trigger this. The losses were 220/300 woven with a 0/300 control, and 400/400 in the finder's repro.
- Reproduction: the `evidence/fx-store-writer-F1/` files `fx-woven.out.txt`, `fx-store.out.txt` and `fx-public.out.txt`. Command: `go tool orchestrion go test -run TestFxF1WovenBuilderTaintWipedByUnrelatedBuffer ./iast/propagation/`.
- Minimal fix: on a failed `TryLock` against a *possible* match, drop only the current operation and count it in `drops.contention`. Never dirty a foreign owner unless the entry is confirmed under its lock.

### H5. A fully occupied value shard stays wedged after its owners finish
- Severity: **High**. Status: **CONFIRMED** (`phase3/fx-store-stress-F2.{md,json}`).
- Location: `internal/taint/store/value.go:147-193` (`putWindow`) and `value.go:225-227` (compaction only after a successful insert).
- Contributing ids: store-stress-F2, store-value-F1 (Medium, same mechanism). Related: store-value-F3 (Low).
- Mechanism: `putWindow` turns stale slots into tombstones, but it inserts into `firstTombstone` only once it reaches an empty slot (case 0). A 64-probe window made entirely of live slots and tombstones returns `drops.full`, even when the tombstones were reclaimed in that same scan. Compaction runs only after a successful insert, so the shard can never recover, and about 1/256 of all values are dropped until the process restarts. store-value-F1 notes that the comment at `value.go:190-191`, which claims a duplicate-slot risk, is wrong: every insertion path places keys within ProbeLimit.
- Reproduction: `evidence/fx-store-stress-F2/independent-go1.26.6.out.txt`, run with `go test -run '^TestIndependentShardWedge$' ./internal/taint/store` (test file `wedge_independent_test.go`). Also `evidence/store-value/tombstone_window.out.txt`. Organic default-config stress reached 116/128 slots.
- Minimal fix: when the probe window is exhausted, insert into `firstTombstone` if one exists, or trigger `compact` on a full-window failure.

### H6. Strong reader and writer anchors retain arbitrarily large uncharged caller allocations (severity DISPUTED between falsifiers)
- Severity: **High**, disputed. `phase3/fx-hooks-yml-writers-F1.json` confirms the Buffer anchor path as High: the documented trade-off rests on an unsound argument, since counting anchors does not bound retained bytes, and the design's own 24 MiB verification checklist is violated. `phase3/fx-store-memory-bounds-F1.json` confirms the same mechanism, including reader anchors, but rates it Medium: README.md:70-77 documents the trade-off, and the memory is released at Finish.
- Location: `internal/taint/store/binding.go:29-35,166-203`, `writer.go:17-42,217-229`, and `iast/propagation/writer.go:213-216`.
- Contributing ids: store-memory-bounds-F1 (reported Critical, adjusted Medium), hooks-yml-writers-F1 (High).
- Mechanism: a bound body reader (charge 0) or an interior-slice Buffer view (charge `sizeClass(visible cap)`) pins the whole caller allocation. Measurements: 96 MiB retained with charge 0 or 64, and 128 MiB retained with charge 128. EagerHTTP binds the body reader on every sampled request. The memory is released synchronously at owner Finish, so it cannot accumulate across requests.
- Reproduction: `evidence/fx-hooks-yml-writers-F1/woven-retention-go1.26.6.txt` (`go tool orchestrion go test -run TestFxBufferInteriorViewRetainsCallerAllocation ./iast/propagation`) and `evidence/fx-store-memory-bounds-F1/01-independent-reproduction.txt`.
- Minimal fix: charge `cap` of the anchored allocation base rather than the visible view, or refuse to track views whose base allocation exceeds the per-root limit. For readers, bind a weak reference or stop anchoring past a byte budget. This needs a product decision on the README trade-off.

### H7. Short evidence parts pin full sink snapshots outside the event byte budget (outside the store package)
- Severity: **High**. Status: **CONFIRMED** (`phase3/fx-store-memory-bounds-F3.{md,json}`).
- Location: `internal/taint/redaction/source.go:187-207`, `internal/spans/tainted.go:114-162,274-294`, `internal/taint/evidence/evidence.go:293-300`.
- Contributing ids: store-memory-bounds-F3.
- Mechanism: untruncated short value parts are substrings that keep the whole snapshot backing alive, while event admission charges only new source-identity bytes. At maximum supported config the extra HeapInuse was 137.9 MB, 5.48x the 24 MiB ceiling, released at span finish.
- Reproduction: `evidence/fx-store-memory-bounds-F3/01-independent-sql-retention.txt`, run with `go test -run '^TestIndependentF3SQLSnapshotRetention$' ./internal/taint/store` and the env from the fx JSON.
- Minimal fix: `strings.Clone` evidence and value parts when they enter the event, and charge the cloned bytes against the event budget.

### H8. Non-atomic span-annotation admission lets the map exceed its capacity (outside the store package)
- Severity: **High** (reported Critical). Status: **CONFIRMED** (`phase3/fx-store-memory-bounds-F2.{md,json}`).
- Location: `internal/spans/annotation.go:131-143,198-205,227-236`.
- Contributing ids: store-memory-bounds-F2.
- Mechanism: the `trimStore()` size check is a TOCTOU against the `LoadOrCompute` insert. Without any patch, a synchronized burst gave 11 entries against cap 2 and 70 against 64. A scheduling barrier reached 2048 against 64, so no code-imposed bound exists. The excess is removed when the span finishes.
- Reproduction: `evidence/fx-store-memory-bounds-F2/01-noPatch-admission.txt`, run with `go test -run '^TestFxF2AdmissionNoPatch$' ./internal/spans`.
- Minimal fix: reserve capacity with an atomic counter (CAS increment before insert, decrement on remove or failure).

### H9. Every `bytes.Buffer` mutation in the process scans active writer owners (hot-path cost)
- Severity: **High** (perf). Status: **CONFIRMED** (`phase3/fx-crash-stress-app-F2.{md,json}`). Cross-part.
- Location: `internal/taint/store/writer.go:366-432` (`InvalidateBuffer`/`writerPresent` scan), `internal/taint/writerbridge/bridge.go:75-96`, `iast/propagation/orchestrion.yml:1553-1595`.
- Contributing ids: crash-stress-app-F2.
- Mechanism: the woven Buffer advice is gated only on a process-wide `activeStates>0`. Once any request holds writer state, every Buffer write anywhere in the process runs 4 CAS probes and a 64-owner `writerPresent` scan. That includes dependencies, the tracer, and goroutines with no request. Measured medians: 6 to 475 ns/op with one tracked owner, and 5 to 1838 ns/op with 64 owners. H4 amplifies the correctness impact of this path.
- Reproduction: `evidence/fx-crash-stress-app-F2/default.out` (`fxwriter` harness, command in the fx JSON).
- Minimal fix: key a small process-wide bloom or set of tracked backings and check it before the owner scan. Alternatively, gate on the receiver being known to the writerbridge table.

### M1. Stale same-key slots use up Lookup's four-owner window before validation
- Severity: **Medium** (reported High). Status: **CONFIRMED**, downgraded (`phase3/fx-store-lookup-F1.{md,json}`: needs five simultaneous same-key owners, which the default MaxConcurrentRequests=2 and the `MaxSnapshotOwners=4` caps at adoption sites make unreachable by default).
- Location: `internal/taint/store/lookup.go:117-139`.
- Contributing ids: store-lookup-F1, store-fuzz-F1 (Low), store-value-F5 (Info).
- Mechanism: candidates are capped at 4 before owner and root liveness checks, so four stale slots hide a live fifth owner.
- Reproduction: `evidence/fx-store-lookup-F1/repro_propagation.out`.
- Minimal fix: validate the generation and state (or skip stale slots) before counting a candidate against the window.

### M2. A contended `rollbackRoot` leaks its root slot and charge until Finish
- Severity: **Medium** (reviewer-reported). Contributing ids: store-root-F1 (Medium), store-stress-F4 (Low).
- Location: `internal/taint/store/root.go:370-375`.
- Mechanism: when `rootsMu.TryLock` fails, the rootID, rootCount, up to 192 KiB of charge and any anchor stay held. The contention correlates with the original failure, so leaks accumulate until the 512-root or 2 MiB budget is exhausted, and the rest of the request loses taint.
- Reproduction: `evidence/store-root/zz_review_root_test.go` (`go test -run TestReview ./internal/taint/store/`) and `evidence/store-stress/campaign/per-run-stats.txt`.
- Minimal fix: use a blocking `Lock` in rollback, which is safe per the lock order, or queue the rollback for the next `beginWrite`.

### M3. Stale `Finish` can finish the owner that reused the slot
- Severity: **Medium** (reviewer-reported). **Nodes disagree**: store-stress-F3 rates it Medium, store-concurrency-F5 rates it Info because production finishes each `*Owner` once via `Swap(nil)`.
- Location: `internal/taint/store/owner.go:157-163`. Same root cause as H1.
- Reproduction: `evidence/store-stress/stale-handle.out.txt` (`TestReviewStaleFinishKillsReusedSlot`).
- Minimal fix: fixed by the H1 fix (a single atomic generation-and-state word used in a CAS).

### M4. `Owner.Finish` holds the global `overflowMu` across the 512-root scan
- Severity: **Medium** (reviewer-reported). Contributing ids: perf-contention-F3 (Medium), store-concurrency-F6 (Info), store-root-F6 (Info, first-come overflow pool).
- Location: `internal/taint/store/owner.go:181-203`, `overflow.go:8-24`, `root.go:354-361`.
- Mechanism: other requests' `allocateOverflow` TryLocks fail during the scan, so 10-14% of multi-range publishes are silently truncated to 10 ranges when `DD_IAST_MAX_RANGE_COUNT>10`. This also goes against the drop-rather-than-block policy.
- Evidence: `evidence/perf-contention/store.mutex.top.txt`.
- Minimal fix: collect the owner's overflow blocks under `rootsMu` and free them in one short `overflowMu` section, or keep a per-owner list of blocks in use.

### M5. `Store.Acquire` drops sampled requests on `ownerMu.TryLock` contention despite free capacity
- Severity: **Medium**, reviewer-reported, and **DISPUTED**. life-weak-gc-F5 reports up to about 30% drops (Medium). crash-race-hunt-F2 reports 39-80% under a 16-loop stress (Low). life-soak-F2 and sink-e2e-truepos-F6 corroborate the effect. perf-contention-F1 was **REFUTED** as a correctness defect in `phase3/fx-perf-contention-F1.json` (adjusted Info): the mechanism reproduced (2384/29805 sampled requests rejected at defaults), but the design explicitly allows contention drops.
- Location: `internal/taint/store/owner.go:24-27`.
- Evidence: `evidence/fx-perf-contention-F1/woven-go126.txt`, `evidence/life-weak-gc/review_gc_internal_test.go`.
- Minimal fix: use a blocking `ownerMu.Lock` (the section is short and bounded), or retry once, and count the drop in telemetry.

### M6. Foreign or unsampled traffic consumes a live owner's budgets
- Severity: **Medium** (reviewer-reported, cross-part). Contributing ids: prop-owner-isolation-F2.
- Location: `internal/taint/store/writer.go:209-217`, `internal/taint/propagation/writer.go:123-133`.
- Mechanism: propagating owner A's value from other goroutines publishes state charged to A. Eight foreign builders exhaust A's `MaxWriters`, and A's own supported propagation is then dropped.
- Evidence: `evidence/prop-owner-isolation/budget.out.txt`.
- Minimal fix: publish writer state only when the caller's own scope is that owner, or give foreign publishes a separate quota.

### M7. Repeated `String()` on an unchanged tracked writer burns the request's root budget
- Severity: **Medium** (reviewer-reported). Contributing ids: store-writer-F3.
- Location: `internal/taint/propagation/writer.go:215-237`.
- Mechanism: each call publishes a new root, so after 511 calls later provenance in the request is dropped.
- Evidence: `evidence/store-writer/zz_review_builder_budget_test.go` (`go test -run TestReviewRepeatedBuilderString ./iast/propagation/`).
- Minimal fix: cache the last published root per writer entry and reuse it while the view is unchanged.

### M8. The address-reuse regression test usually skips
- Severity: **Medium** (reviewer-reported). Contributing ids: store-tests-F1 (Medium, 7/20 skips), store-identity-gc-F2 (Low, 4/5 skips), light-test-determinism-F1 (Low).
- Location: `internal/taint/store/identity_test.go:30-65`. Evidence: `evidence/store-tests/race-stress.txt`.
- Fix: test identity deterministically through the key API (a synthetic slot with the same pointer), and add Builder and Buffer backing-reuse tests covering H2 and H3.

### M9. The Finish-blocking assertion can pass before Finish runs
- Severity: **Medium** (reviewer-reported, NEEDS-REPRO). Contributing ids: store-tests-F2.
- Location: `internal/taint/store/lifecycle_test.go:14-35`.
- Fix: signal from inside Finish (via a test seam) before asserting that it is blocked.

### M10. Binding-kind replacement and reader-budget transitions are untested
- Severity: **Medium** (reviewer-reported). Contributing ids: store-tests-F3.
- Location: `binding.go:166-202`. Evidence: `evidence/store-tests/coverage.txt`.
- Fix: add tests for URL-to-reader at capacity and reader-to-URL release.

### M11. No test covers two concurrently active requests sharing recycled memory
- Severity: **Medium** (reviewer-reported, cross-part). Contributing ids: life-cross-request-F4.
- This is exactly the regime behind H2, H3 and the cross-reference X2.
- Fix: add woven two-request tests based on the fx reproducers.

### M12. JoinString alias scan runs before the active-store gate
- Severity: **Medium** (reviewer-reported, NEEDS-REPRO). Contributing ids: store-api-misuse-F1.
- Location: `internal/taint/propagation/string_exact.go:24-44`.
- Mechanism: the clean path does unbounded work despite the bound of 16 inspected inputs.
- Fix: check `store.Active()` (or the equivalent) first.

### M13. JSON reports publication after every store adoption failed
- Severity: **Medium** (reviewer-reported, NEEDS-REPRO). Contributing ids: store-api-misuse-F2.
- Location: `internal/taint/propagation/json.go:42-69`.
- Mechanism: the result is `published=true` even when no `AdoptString` succeeded, so the JSON callback replaces the value with an untracked clone.
- Fix: return `published` only when at least one adoption succeeded.

### Cross-references (High, owned by other parts, share store code)
- **X1, hooks-io-bufio-F1 (High, CONFIRMED, `phase3/fx-hooks-io-bufio-F1.json`)**: reader bindings are keyed by wrapper address only and live until owner finish (`binding.go:95-108,166-203`). Because `bufio.Reader.Reset` is unhooked, this produces cross-owner attribution. The primary fix belongs to the hooks part. It shares the address-only binding key with store-binding-F1 below.
- **X2, life-cross-request-F1 (High, CONFIRMED, `phase3/fx-life-cross-request-F1.json`)**: an application-owned `io.ReadAll` slice is adopted under `(ptr,len)`, and `Lookup` (`lookup.go:120-196`) accepts a foreign active owner without a content check. The primary fix belongs to the request and life part. life-cross-request-F5 (Info) generalizes this: foreign-owner reporting turns every stale-identity miss into cross-user attribution.
- life-admission-F1 (DISPUTED, `phase3/fx-life-admission-F1.json`) concerns net/http admission slots, not the store, and is not counted here.

## 3. Low / Info and code-quality notes
- **store-binding-F1**, reported High, adjusted **Low**, CONFIRMED (`phase3/fx-store-binding-F1.json`): a reader bound at the address of an embedded first-field URL replaces the URL binding (`binding.go:186-198`). It needs a hand-built `*http.Request`, and real servers always use separate allocations. Evidence: `evidence/fx-store-binding-F1/woven-alias-go1.26.6.out.txt`.
- store-binding-F2 (Low): stale owner handle accessors (`owner.go:72-75,94-124`) read the successor's ID and charge its drop counter because they have no generation check.
- store-concurrency-F2 and prop-owner-isolation-F3 (Low, same root as H1): a torn `Lookup` builds a hybrid-generation Entry. Current consumers reject it. Evidence: `evidence/prop-owner-isolation/lookup-torn.out.txt`.
- store-concurrency-F3 and store-value-F2 (Low): a rebind racing `claimMutation` undercounts values and can close the `!=0` gates. This is latent because `PublishBytesMutation` has no production caller. Evidence: `evidence/store-concurrency/rebind-drift-seam.txt`.
- store-concurrency-F4 (Low, CI): no `+checklocks:` field annotations exist, so `checklocks` verifies nothing in the store and the `+checklocksforce` comments are inert.
- store-fuzz-F2 (Low): `Lookup` returns zero-range entries, and propagation publishes empty-provenance roots that consume budget.
- store-root-F2 (Low): the `sizeClasses` table (`limits.go:38-39`) diverges from the Go runtime at 1088 and 5392 and undercharges up to 752 B.
- store-root-F3 (Low, doc): the `TaintBytes` clone zero-fills `[len:cap]` and breaks aliasing, and the public doc does not mention it.
- store-root-F4 and perf-contention-F4 (Low): Adopt pre-check rejections and shard/owner TryLock drops are missing from telemetry, and `Counters()`/`AcquireDrops()` have no production caller.
- store-value-F3 (Low): an aborted compaction is retried on every later successful insert into that shard.
- store-value-F4 (Low): the `forceCollision` test seam is loaded on every production `keyHash`.
- store-writer-F4, F5 and F6 (Low): the 4-owners-per-receiver limit is soft, and exceeding it wipes an owner. A dirty owner keeps its entries and the process fast gate until it next writes. Dirtying on lock failure is not counted.
- perf-contention-F5 (Low): the `Lookup` slow path costs about 16x `MayContain` because of ranges.Set copies. perf-bench-quality-F4 (Low): `BenchmarkFinishWithActiveWriter` times setup inside the loop.
- Info notes:
  - store-root-F5: root generations never advance in production, so mutation invalidation is test-only.
  - store-value-F6: generation comparisons are not wrap-aware (unreachable).
  - store-fuzz-F3: the probe-exhaustion drop is unreachable at design load.
  - crash-panic-static-F3: manual unlocks would leak locks if a critical section ever panicked (latent).
  - hooks-io-bufio-F4: reader hooks run process-wide while any analysis is active.
  - store-stress-F5: an adoptable randomized stress harness, validated by three killed mutants, is at `evidence/store-stress/stress_review_test.go`.

## 4. Verified correct
- No Go-memory-model data race: every plain field is guarded by its mutex, and `writerActive` is published via `atomic.Pointer`. The store suite passed `-race -count=50` (store-concurrency). No race and no panic appeared in 39 `-race` seeds covering 69.7M ops, 17.7M model-checked lookups and 1,734 quiescent invariant checks (store-stress).
- The lock order `lifecycleMu → writersMu → rootsMu → overflowMu → bindings.mu` is acyclic, nested acquisitions are `Try*`, no callbacks run under locks, and every Try/unlock pair is balanced (store-concurrency, store-root, store-writer).
- Single-threaded correctness: a 15-minute model fuzz run (145,718 execs) found no crasher. Admission limits are exact, accounting drains to zero, and every overflow block returns (store-fuzz).
- The identity key `(uintptr,len,kind)` never becomes a pointer again, and live slots are confined to anchored roots. GC reuse after Finish reads clean even while another request is active, and the 64-bit `ownerGen` prevents ABA (store-identity-gc, store-value).
- Root constructors roll back on every failure path, and the charges match the documented worst case (3 x 64 KiB) (store-root).
- The fixed footprint matches the envelope (13.39 MB store plus 0.86 MB manager, about 21.59 MiB with maximal charge), and the limits match the README and config (store-memory-bounds, store-lookup, perf-memory-F5).
- Writer entries never outlive their owner. `MaxWriters` and the 64 KiB cap are enforced, `AdoptBufferWriter` copy transfer is correct, and Buffer anchors prevent Buffer ABA (store-writer).
- `OwnerRef.Handle` rejects old generations. A panicking handler's deferred Finish releases bindings, charge and permit (store-binding).
- Production store callers check `ok`, use fresh snapshots, and adopt only allocation bases (store-api-misuse).
- Store statement coverage is 91.5%, and no store test uses `time.Sleep` (store-tests).

## 5. Coverage gaps
- The store nodes ran no woven end-to-end run for H1, H4, H5, M1 or M2. Phase-3 woven reproductions exist only for H2, H3, H4, H6, H9 and X1/X2. Phase-3 woven attempts on H1 (2x300s) did not hit, so its production frequency is unmeasured.
- Go 1.27.0 was not exercised woven: the JSON advice compile failure blocks it, per fx-perf-contention-F1 and fx-life-cross-request-F1. Most store evidence was collected on go1.26.6 only.
- The fuzz model is single-threaded. `bytes.Buffer` writers, `AdoptBufferWriter` value-copy transfers and the `forceWriterLockFail` seam were not randomized under concurrency.
- The mirrored check-then-CAS pattern in `request.Analysis.Finish`/`Active` (`request/owner.go:125-129,258-273`) was reviewed only statically.
- No node checked whether every `AdoptString`/`AdoptBytes` caller passes an allocation base. An interior adoption would undercharge without bound, and the store cannot enforce this (deferred to the propagation part).
- Retained heap under full saturation combining H6 and H7 was measured separately, never together. The production tracer's export queue and build-time RSS were out of scope.
- Wrap-around of root generations was not exercised, and 32-bit targets were vet-only.

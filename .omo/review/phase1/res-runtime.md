# res-runtime: Design lessons from the Orchestrion research runtime taint registry (orchestrion#858)
Verdict: The research registry is internally consistent and race-clean for its own scope. It buys exact provenance by pinning every tainted array (unbounded memory), latching process-wide over-taint on eviction, and scanning linearly under a global lock. A reproduced stale-capacity pitfall shows that bytes metadata in `[len, cap)` can come back after an uninstrumented reset. All findings concern research code (Info). The lessons are distilled into 17 dd-iast-go checks in `phase1/research/runtime.md`.
Scope covered: orchestrion `eliottness/iast-testing:runtime/taint/` README.md, registry.go, lifecycle.go, range.go, string.go, bytes.go, buffer.go, builder.go, reader.go, runes.go, scalar.go, scalar_transfer.go, sink.go, sql.go, transforms.go, constructors.go; registry_test.go, lifecycle_test.go, concurrency_test.go; e2e case_103/104; the `ReleaseByte`/`ReleaseRune` advice in instrument/orchestrion.yml. I ran the research unit tests under `-race` on a `git archive` copy, a new stale-capacity reproducer, and a Go runtime aliasing probe on go1.26.6 and go1.27.0. For dd-iast-go I skimmed store/limits.go, store.go, value.go, lookup.go, owner.go, and root.go (span/charge) only to aim the checks. No dd-iast-go verdicts are made here.

## Findings
### res-runtime-F1: Stale taint in buffer spare capacity resurfaces on clean data (research)
- Severity: Info
- Category: provenance
- Location: orchestrion eliottness/iast-testing runtime/taint/buffer.go:143-157 (with range.go:43-87)
- Claim: A clean overwrite erases ranges only over the written `[start, start+len)`. Ranges on bytes in `[len, cap)` stay. `bytes.Buffer.Read` on an empty buffer calls `Reset()` internally, outside instrumentation. After a shorter clean write, `BufferReadFrom` with an arbitrary reader re-reads `postRanges := RangesBytes(buffer.Bytes())` over the grown length and republishes the old source's range on clean bytes, which is a false positive. The dd-iast-go counterpart is check 5 in runtime.md, since byte roots span `cap`.
- Evidence: .omo/review/evidence/res-runtime/zz_review_stale_test.go; `GOFLAGS=-mod=mod go test -count=1 -run Test_ReviewStaleCapacityTaint -v ./runtime/taint/` (setup in evidence README.md). Output: `clean data reported tainted: "cleancleanxy" ranges=[]taint.Range{taint.Range{Start:10, End:12, SourceID:0x1}}` (stale_capacity.out.txt)
- Fix: On any length decrease observed at a hook, including one detected by comparing the recorded length, clear metadata over the whole `[off, cap)` window. Do not merge `postRanges` from an untracked reader.

### res-runtime-F2: Exact provenance bought by pinning every tainted backing array (unbounded memory)
- Severity: Info
- Category: memory-bound
- Location: orchestrion runtime/taint/registry.go:121,127,145,167; README.md:76-86
- Claim: `stringOwners/byteOwners/runeOwners` hold strong references keyed by start address. Arrays are never collected, so addresses are never reused and stale taint cannot occur. Memory grows with the number of distinct tainted values until `StartRequest` evicts a generation. The README documents this, and case_104 confirms it with a weak pointer that survives 10 GCs. This design would violate dd-iast-go rule 3. The lesson: releasing anchors requires invalidating index entries first (runtime.md check 3).
- Evidence: static reasoning; documented in README and pinned by case_104
- Fix: n/a (research). dd-iast-go uses bounded, owner-scoped anchors instead.

### res-runtime-F3: Generation eviction latches permanent "unknown" reports on every clean sink
- Severity: Info
- Category: false-positive
- Location: orchestrion runtime/taint/lifecycle.go:30-40,73; sink.go:60-69
- Claim: The second `StartRequest` sets `historyDiscarded` for good. From then on, `reportOpenPath` emits `State: unknown` for every range-free path, including literals. The same happens when a builder or reader table saturates (`stateSaturated`). The design chooses a false-positive flood over false negatives, and `Test_StartRequestOverTaintsCleanSinks_when_GenerationHistoryIsDiscarded` pins it. dd-iast-go must do the opposite (runtime.md check 7).
- Evidence: static reasoning; the behaviour is asserted by research lifecycle_test.go:131-179
- Fix: n/a (research).

### res-runtime-F4: Every propagation scans all stored ranges under a blocking global lock, with no cheap gate
- Severity: Info
- Category: perf
- Location: orchestrion runtime/taint/range.go:23-41,60-86; lifecycle.go:64-97; registry.go:101-109
- Claim: `RangesString`/`RangesBytes` snapshot the generations, then iterate and allocate over every interval, even for clean values. A registration that overlaps existing ranges rebuilds and re-sorts the full slice under a write `Mutex`. Cost is O(N) per lookup and O(N log N) per such write, all serialized. Contrast with dd-iast-go's sharded, fixed-probe `MayContain` with TryLock (runtime.md check 10).
- Evidence: static reasoning only
- Fix: n/a (research).

### res-runtime-F5: Request boundary is process-global; concurrent requests evict each other's metadata
- Severity: Info
- Category: cross-request
- Location: orchestrion runtime/taint/lifecycle.go:15-40
- Claim: `StartRequest` rotates one global registry list with a single retired slot. With concurrent requests, two starts from other requests drop a live request's generation, and taint is never attributed to an owner or request. The README scopes the prototype to one logical request generation. This is a lesson for dd-iast-go's per-owner design (checks 4, 6, 17), not a defect.
- Evidence: static reasoning only
- Fix: n/a (research).

## Checked and found correct
- The research unit tests pass under `-race` (`evidence/res-runtime/research_race.out.txt`, exit 0).
- `isolatedString`'s `len+1` sentinel copy defeats the runtime's 1-byte string interning. The probe shows `string(b[i:i+1])` results sharing an address (`true`), while isolated results do not (`false`) on go1.26.6 and go1.27.0 (`evidence/res-runtime/alias_probe.out.txt`). The probe also confirms that `""+s` returns `s` for a heap operand and that `TrimPrefix` returns an interior view. Both hazards feed dd-iast-go checks 1, 2 and 13.
- Interval-overlap lookup (range.go:23-41) makes substring and subslice views correct without registration. `BufferBytes`/`BufferNext` rely on this correctly.
- Conservative transforms keep one range per distinct source ID and do not collapse sources (range.go:143-166).
- The builder detects an out-of-band `Reset` by recorded-length regression (builder.go:44-46).
- The default reporter redacts values unless `ORCHESTRION_TAINT_INCLUDE_VALUE=1` (sink.go:78-84).

## Not covered / open questions
- The patched-Go shadow-label prototype (compiler and runtime patches) was not read beyond the case names. Its GC-sweep and stack-reuse clearing is the alternative answer to address reuse.
- `instrument/orchestrion.yml` (1,322 lines) was read only for the scalar `Release` advice. Join-point soundness is outside this node.
- The dd-iast-go checks in runtime.md are questions only. No dd-iast-go code was verified against them here.

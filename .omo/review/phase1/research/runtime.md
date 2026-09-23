# Research lessons: Orchestrion runtime taint registry (orchestrion#858, `runtime/taint`)

Source: `git -C ../orchestrion show eliottness/iast-testing:runtime/taint/<file>`. The package is RESEARCH code (source `os.Getenv`, sink `os.Open`). It is not the product. Line numbers below are for that branch. Evidence is under `.omo/review/evidence/res-runtime/`.

## 1. How values are identified and stored

- **Identity is the data address, not the value.** A string or `[]byte` is looked up by `unsafe.StringData`/`unsafe.SliceData` plus its length (registry.go:171-183). Taint is stored as absolute address intervals `addressRange{start,end,sourceID}` in one sorted slice per kind: `stringRanges`, `byteRanges`, `runeRanges` (registry.go:21-39, range.go:17-21).
- **Lookups use interval overlap.** `relativeRanges` intersects every stored interval with `[ptr, ptr+len)` (range.go:23-41). As a result, any view (a substring, subslice, `bytes.Buffer.Bytes()`, `Next`, or `strings.Cut` result) sees the ranges of the bytes it covers without being registered. `SliceString`/`SliceBytes` re-register purely for form (string.go:30-34, bytes.go:42-46). `BufferBytes`/`BufferNext` rely on this aliasing outright (buffer.go:82-101).
- **Registering replaces the ranges.** `replaceAddressRanges` erases every interval inside `[start, start+len)` and inserts the new ones (range.go:43-87). Registering with `nil` is therefore a *clean overwrite*. `ClearBytes`, `SetByte`, `CopyBytes` and `BufferReset` depend on it (bytes.go:92-130, buffer.go:159-172). A fast path appends without rewriting when `start > maxEnd` (range.go:48-58).
- **Fresh allocation at every source and conversion.** `isolatedString` copies into `make([]byte, len+1)` and returns `s[:len]` (registry.go:185-193). The +1 sentinel forces an allocation of at least 2 bytes. That sidesteps two Go runtime behaviours that would make address identity unsound:
  - `string(b[i:i+1])` returns a pointer into the runtime's shared `staticuint64s` table. Every tainted and clean 1-byte string with the same value shares one address.
  - `"" + s` returns `s` itself when `s` is on the heap.

  Both were reproduced on go1.26.6 and go1.27.0 (`evidence/res-runtime/alias_probe.out.txt`).
- **Multi-source provenance is kept per source ID.** Conservative transforms (`ToUpper`, `Sprintf`, `QueryEscape`, `json.Marshal`) emit one full-length range per distinct source ID (range.go:143-166, constructors.go:17-47). `normalizeRanges` merges only ranges that overlap and share a source ID (range.go:89-114).
- **Stateful objects get keyed side tables.** `strings.Builder` and readers are tracked in `map[*T]state` with an offset and length (builder.go:32-55, reader.go:15-86). When the builder's recorded length exceeds its current length, the builder was reset outside instrumentation and its state is dropped (builder.go:44-46).
- **Scalars (`byte`/`rune` locals) are keyed by variable address** in `map[unsafe.Pointer]struct{}` with a deferred `ReleaseByte(&x)` (scalar.go, orchestrion.yml `defer taint.ReleaseByte`). Taking the address forces the local to escape to the heap. Values sent through maps and channels carry an embedded `tainted bool` packet (scalar_transfer.go). dd-iast-go does not track scalars, so this is only background.

## 2. Lifetime and GC handling

- **Every tainted backing array is pinned.** Each registration also stores the value in `stringOwners/byteOwners/runeOwners map[uintptr]…` as a strong reference (registry.go:121,127,145,167). The GC therefore cannot free the array, and **its address can never be reused**. That is how the prototype avoids stale taint on recycled memory. The README states the cost (README:76-86), and case_104 checks it with a weak pointer that survives 10 forced GCs.
- **The price is unbounded memory.** Owners grow with the number of distinct tainted values. `maxTrackedOccurrences = 1<<16` bounds only the builder and reader tables. Registry tests deliberately exceed 65,536 string owners (registry_test.go:13-49).
- **Reclamation happens by generations, not by GC.** `StartRequest()` retires the current registry and keeps one prior generation. On the second rollover the oldest generation is dropped and a process-wide latch `historyDiscarded` is set (lifecycle.go:22-40). From then on, every sink value that has no ranges reports `State: unknown` (lifecycle.go:73, sink.go:60-69). The prototype over-taints clean sinks for the rest of the process, and `Test_StartRequestOverTaintsCleanSinks_when_GenerationHistoryIsDiscarded` pins that behaviour on purpose.
- **The patched-toolchain prototype (not this package) went the other way.** It used one-byte shadow labels that are cleared on GC sweep and stack reuse (case_103/104 names). Address reuse is either prevented (pinning) or explicitly cleaned (shadow clearing). No approach can ignore it.

## 3. Concurrency

- There is one `sync.RWMutex` per generation and one on the lifecycle (registry.go:21-22, lifecycle.go:15-20). Every propagation takes the write lock and blocks. Nothing uses TryLock.
- Lookups snapshot the generation list under the lifecycle lock, then read-lock each registry in turn (lifecycle.go:54-77). A value is written to whichever generation already tracks it (`registryTracking`, lifecycle.go:122-132).
- A read-modify-write (`RangesX` followed by `registerX`) is **not atomic**. Two goroutines that write the same buffer can interleave and lose each other's ranges. In practice the application's own data race on the same buffer comes first.
- The research tests pass under `-race` (`evidence/res-runtime/research_race.out.txt`). The only concurrency test uses *distinct* values per goroutine (concurrency_test.go:14-37).

## 4. Bounds

| Structure | Bound |
|---|---|
| string/byte/rune range slices + owner maps | **none** (grow per tainted value, pinned) |
| builder / string-reader / bufio-reader maps | 65,536 each, then `stateSaturated` -> `unknown` reports |
| scalar maps | none (released by deferred Release) |
| generations | current + 1 retired |
| per-value ranges | none |

Cost per op: every `RangesString` scans **all** stored intervals linearly and allocates (range.go:23-41). A non-append registration re-sorts the whole slice (range.go:60-86). Nothing gates the work cheaply first, so clean values pay the full scan.

## 5. Pitfalls the research hit (and that dd-iast-go must defend against)

1. **Address reuse / stale taint.** Solved by pinning (leak) or by shadow clearing (runtime patch). Any design that releases the anchor must invalidate the index entry before the memory can be reused.
2. **Runtime-shared storage.** Single-byte conversions (`staticuint64s`), string literals in rodata, and operands returned by concatenation with `""` all share storage. Keying taint on such an address taints every other user of that address. The research fix is to always copy into a fresh allocation of at least 2 bytes (`isolatedString`).
3. **Aliasing views.** Subslices and substrings share the backing array. The research handles this naturally with interval overlap. An exact-key index must resolve interior pointers through a containing-window lookup, or views become false negatives.
4. **Mutable bytes written outside instrumentation.** `bytes.Buffer` internals (`Read` on an empty buffer calls `Reset`, and `grow` slides data with `copy`), `io.ReadFull`, and pooled buffers all change bytes without clearing their metadata. **Reproduced here:** stale taint left in the spare capacity of a buffer resurfaces on clean data. The sequence is: tainted write, `Next`, `Read` (internal `Reset`), a shorter clean write, then `ReadFrom(strings.NewReader("xy"))`. The result reports `"cleancleanxy"` with range `[10,12)` from the old source (buffer.go:151-155; `evidence/res-runtime/stale_capacity.out.txt`). Metadata for bytes in `[len, cap)` is live state that can come back.
5. **Saturation semantics.** When the research exhausts a bound or drops history, it latches a conservative "unknown" state for the whole process: a permanent false-positive flood. dd-iast-go's rule is the opposite (drop data, never block, stay accurate).
6. **Global request boundary.** `StartRequest` is process-global. Concurrent requests share generations, so two back-to-back `StartRequest` calls from unrelated requests evict a live request's metadata. Taint is never attributed to one request.
7. **Unmodelled writers go stale.** Builder and reader state keyed by object pointer must detect resets and truncations done outside the hooks (length decrease). The builder does this; readers do it only through offset and length bookkeeping.

## 6. CHECKS to apply to dd-iast-go

Each check is a question a reviewer can answer from dd-iast-go code (HEAD 2e23b46). The pointers are starting places, not verdicts.

1. **Runtime-shared addresses.** Can any `AdoptString`/`AdoptBytes` caller, or any operatorbridge or propagation result, register a string whose data may live in `staticuint64s` (1-byte conversions), rodata (constants), or an operand returned unchanged by `""+s` / `s+""` / `strings.Clone("")` / `strings.Repeat(s,1)`? (store.go:9-10 says adoption is only for results "known to begin at their complete allocation base". Verify each call site against the probe in `evidence/res-runtime/alias_probe.go`.)
2. **Interior views.** Do `s[i:j]`, `strings.Cut/TrimPrefix/Split/Fields`, `bytes.Buffer.Bytes()/Next`, and `json` sub-slices of a tainted root resolve to ranges through the root window (`inWindow`, store/value.go:35-49) even when no value slot was put for that exact key? Or does the exact-key `MayContain` probe (store/lookup.go:81-102) short-circuit them to clean?
3. **Invalidate before release.** When an owner finishes, are all value slots and windows made unmatchable (owner or root generation bump, tombstone) *before* the strong `stringAnchor`/`bytesAnchor` is cleared (store/root.go:384 area)? Can a concurrent `Lookup` observe a slot whose anchor is already gone and match a new allocation at the same address?
4. **Owner slot ABA.** After owner slot reuse, can a goroutine from a finished request, holding an old `Entry` or `Owner`, publish into the new owner? Is `Entry.Handle` (store/lookup.go:35-44) enforced on every publish path, not only in lookups? Can the generation wrap?
5. **Spare capacity (research pitfall 4).** Byte roots span `cap` (store/root.go:115-128, 247). After a clean overwrite, truncate, or reset that happens *outside* the hooks (the internal `Reset` in `bytes.Buffer.Read`, the slide in `grow`), can ranges over `[len, cap)` reappear when the length grows through uninstrumented appends or `ReadFrom`? Port `zz_review_stale_test.go` to dd-iast-go's `bytes.Buffer` writer bridge and its operator `append` hooks.
6. **Caller-owned mutable bytes.** Does dd-iast-go ever keep taint on a `[]byte` it did not allocate (adopt instead of clone), such as request body buffers, `bufio` buffers, or `sync.Pool` slices? If uninstrumented code later refills that array with another request's clean data, is the old taint reported on it (false positive, or bleed across requests while the first owner is alive)?
7. **Saturation direction.** When a bound is hit (MaxOwners, MaxRootsPerOwner, MaxValuesPerRoot, MaxRanges, byte budgets, TryLock contention), does every path *drop* (possible false negative) and never latch a process-wide conservative state like the research's `historyDiscarded`? Grep for sticky booleans and "unknown" states.
8. **Failed clears.** On contention (`TryLock`/`TryRLock` fails), a skipped *add* is a safe miss. Is a skipped *clean overwrite or clear* also safe, or does it leave stale ranges visible (false positive)? Check every mutation path in store/mutation.go and store/writer.go.
9. **Hard footprint.** Are all tables fixed arrays with the capacities in store/limits.go? Is the retained anchor memory charged against the actual allocation (`sizeClass(cap)`, including sub-slices that pin a larger parent array)? Can retained anchors exceed `ProcessRootBytes` when roots are adopted from large parent arrays?
10. **Cheap gate first.** Does every orchestrion hook check `len==0`, the absence of an owner, or `MayContain` before any allocation, reflection, lock, or range-set construction? The research's per-op full scan and allocation is the counter-example.
11. **Exact window span.** Given tiny-allocator packing (the probe shows two 3-byte allocations 4 bytes apart), is the window exactly `[base, base+len)` for strings and `[base, base+cap)` for bytes? It must never be the size-class-rounded `charge` value, or it would cover a neighbouring object.
12. **Conservative transforms keep sources.** For transforms without exact positions (case mapping, `fmt`, `url` escaping, `strconv.Quote`), is provenance kept per source (as in research range.go:143-166), and are the documented range limits applied deterministically instead of silently merging different sources?
13. **Empty and aliasing results.** When a hook's result *is* one of its inputs (`""+s`, `strings.TrimSpace` with nothing to trim, `bytes.TrimSpace`, `append(x)` with no growth), does the hook avoid re-registering shifted or narrowed ranges over the input's existing root? Would doing so corrupt the input's taint?
14. **Concurrency tests on the same value.** Are there `-race` tests that propagate the *same* tainted value from several goroutines while the owner finishes and another request acquires the slot? The research tested only distinct values.
15. **Redaction on every exit.** The research passes raw values to custom reporters and has an env var that disables redaction. Does dd-iast-go have any debug or env path that emits unredacted evidence or source values, including drop or telemetry logs?
16. **Writer reset detection.** For `strings.Builder` and `bytes.Buffer` writer state (MaxWriters=8 per owner), is a reset, truncate, or re-slice done outside hooks detected (length or pointer mismatch), so that the state is dropped rather than applied to new content? (Compare research builder.go:44-46.)
17. **Owner lifetime.** Anchors stay strongly held until the owner finishes. Is finish guaranteed on panic, hijacked connections, streaming handlers, and goroutines that outlive the handler? Otherwise each missed finish permanently takes one of 64 owner slots, and IAST disables itself after 64 leaks.

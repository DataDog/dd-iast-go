# Part "prop": ranges and propagation engine (internal/taint/ranges, internal/taint/propagation)

**Counts after dedup: Critical 1, High 10, Medium 12.** Every Critical and High entry cites a phase-3 `fx-*` verdict. Phase-3 adjusted severity is authoritative. Findings rated Medium or lower that phase 3 did not check are marked "reviewer-reported". Evidence paths are relative to `.omo/review/evidence/`. `life-admission-F1` (DISPUTED) is not in this part's scope.

## 1. Part verdict

The range algebra (`internal/taint/ranges`) is correct. 60.9M fuzz execs and 1.1M oracle cases (prop-ranges-fuzz), 13.2M Unicode differential cases on Go 1.26.6 and 1.27.0 (prop-unicode), and 24.7M exact-op execs (prop-engine-fuzz) found no range mismatch, overflow, out-of-bounds range, value change, or panic. Crash-safety of the engine is good: no panic was found anywhere in this part. The one Critical is a data race on the analysis permit slot. It only fails under `-race`, because the racing write stores the same value. The engine's defects are about provenance. There are 7 confirmed High wrong-provenance bugs on supported paths:
- fmt coarse propagation taints by argument identity, not by what fmt printed (3 roots)
- `strings.Map` stays tainted after every tainted rune is deleted
- Split window budget counts empty outputs
- byte reslicing within capacity loses taint
- the writer owner-fanout bound can be exceeded (the one High that is a memory bound)

There are also 3 confirmed High host-cost regressions: woven conversions and concats allocate even when IAST is inactive, and the writer gate scans on every Builder/Buffer op in the process. Memory is bounded by the global store caps. The local bounds leak in two places: the per-receiver four-owner limit (H7), and foreign-owner budget charging (M6). Cross-owner isolation held in 817k owner cycles and 167.9M ops (plus 137k cycles under `-race`) with 0 mismatches (prop-owner-isolation).

## 2. Findings by root cause

### C1. Data race on `analysisSlot.index` (Manager.Acquire vs analysisForOwner)
- Severity: **Critical**. Status: CONFIRMED (`phase3/fx-prop-owner-isolation-F1.json`, reachable_default=true).
- Location: `internal/taint/request/owner.go:82` (`slot.index = uint8(index)`), read at `internal/taint/request/http.go:33`. This is request-layer code found by the prop review; cross-reference the life part.
- Contributing: prop-owner-isolation-F1.
- Mechanism: every permit Acquire does a plain store of `slot.index`. A detached goroutine calling `URL.Query()` (through `ManageURLQuery`), `io.ReadAll`, or `CloneReaderBytes` does a plain read after its request finishes and a new request reuses the permit. The value never changes, so non-race builds behave correctly, but customer `-race` runs of woven code report a DATA RACE. The ReadAll/CloneReaderBytes paths are mostly masked by the `sourceMu` happens-before edge (fx note).
- Repro: `fx-prop-owner-isolation-F1/woven-detached-query-race-go1.26.6.out.txt`. `cp fx-prop-owner-isolation-F1/zzfxrepro_repro_test.go zzfxrepro/repro_test.go && GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -race -run '^TestFxWovenDetachedQuery$' ./zzfxrepro`. Internal variant: `prop-owner-isolation/slotindex-race.out.txt`.
- Fix: initialize `slot.index` once in `NewManager` and never rewrite it in Acquire (the falsifier verified this fix).

### H1. fmt coarse propagation keys on the receiver's backing, not on what the String/Error/Format/GoString method printed
- Severity: **High**. Status: CONFIRMED (`phase3/fx-prop-string-coarse-F1.json` for both prop-string-coarse-F1 and hooks-yml-fmt-strconv-url-F1; `phase3/fx-crash-diff-strings-F1.json`).
- Location: `internal/taint/propagation/string_coarse.go:206-220` (`formatArgumentKey`: `reflect.String` → `StringKey(value.String())`, `[]byte` kind → `BytesKey`).
- Contributing: prop-string-coarse-F1, hooks-yml-fmt-strconv-url-F1 (cross-part dup), crash-diff-strings-F1 (also covers H2).
- Mechanism: a named string or `[]byte` type with a `String()`/`Error()`/`Format` method is keyed by its underlying bytes. When fmt prints the method's constant output instead (for example an allowlisting Stringer that maps `' OR '1'='1` to `AUDIT_OK`), the output still gets a full `[0,len)` source range. The SQL sink then commits a real SQL_INJECTION span event. Default redaction, dedup, and quotas do not prevent it.
- Repro: `fx-prop-string-coarse-F1/woven-go126.txt`. Build `./cmd/fx-coarse` in `iast/integration/testapp` with `go tool orchestrion go build`, then run it with the `stringer` or `formatter` argument (full command in the fx json). Also `fx-crash-diff-strings-F1/woven-go1.26.6.log` and `prop-string-coarse/repro-output.txt`.
- Fix: in `formatArgumentKey`, skip arguments whose dynamic type implements `fmt.Formatter`, `fmt.Stringer`, `error`, or `fmt.GoStringer`, unless the type is exactly `string`/`[]byte`.

### H2. fmt coarse propagation taints output for verbs that emit none of the operand's bytes (`%.0s`, `%T`, `%p`, skipped `%[n]`)
- Severity: **High**. Status: CONFIRMED for prop-semantics-parity-F2 (`phase3/fx-prop-semantics-parity-F2.json`). The other contributors are reviewer-reported at Medium or Low. The phase-3 High supersedes them.
- Location: `internal/taint/propagation/string_coarse.go:115-146,175-197`.
- Contributing: prop-semantics-parity-F2, prop-string-coarse-F2 (Medium), sink-e2e-truepos-F2 (Medium, `%T`), hooks-yml-fmt-strconv-url-F4 (Low), crash-diff-strings-F1 (`type=string` output).
- Mechanism: every inspected string/byte argument contributes to the coarse range regardless of the consuming verb. An HTTP query run through `Sprintf("SELECT 40 + 2 /* %.0s */", q)` gives clean SQL that is still tainted and reported.
- Repro: `fx-prop-semantics-parity-F2/woven_http_sql_go1.26.6.out.txt`. `cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -run '^TestHTTPQuery_SprintfZeroPrecision_reportsCleanSQL$' .`
- Fix: contribute an argument only if its bytes appear in the output. A cheap option is a verb pre-scan that honors precision, `%T`/`%p`, and explicit indexes. A stricter option is to contribute only when `strings.Contains(result, arg)`.

### H3. fmt false negative: tainted data inside structs, Stringer fields, slices, pointers, or errors is not propagated
- Severity: **High**. Status: CONFIRMED (`phase3/fx-prop-semantics-parity-F1.json`). The doc contributors are reviewer-reported Medium.
- Location: `internal/taint/propagation/string_coarse.go:115-145,203-219`; `README.md:31-32`.
- Contributing: prop-semantics-parity-F1, prop-string-coarse-F3 (doc), hooks-yml-fmt-strconv-url-F2 (doc).
- Mechanism: only top-level `string`/`[]byte` arguments are inspected. `Sprintf("%v", struct{F tainted})`, `errors.New(tainted)`, and `[]string` print tainted bytes, but the SQL sink sees no taint (StatusNone). The README advertises `fmt.Sprint*` without this restriction.
- Repro: `fx-prop-semantics-parity-F1/review_f1_test.go`. `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -run '^TestReviewF1_' ./iast/propagation`.
- Fix: at minimum, document "direct string/[]byte operands only" in the README. Better: bounded reflection over the first N fields and elements of aggregate arguments, which H1's method check must gate.

### H4. `strings.Map` keeps whole-value taint after deleting every tainted rune
- Severity: **High**. Status: CONFIRMED (`phase3/fx-prop-semantics-parity-F3.json`, documented_limitation=**true**, still High because it breaks rule 4).
- Location: `iast/propagation/coarse.go:36-38`; `internal/taint/propagation/propagation.go:326-425`.
- Contributing: prop-semantics-parity-F3.
- Mechanism: coarse transforms taint the whole result if any input byte is tainted. After a header is run through `strings.Map` and all its tainted runes are dropped, the result is the constant `SELECT 42`, and one SQL_INJECTION report is attributed to the deleted header.
- Repro: `fx-prop-semantics-parity-F3/woven-go1.26.6.out.txt`. `DD_IAST_REQUEST_SAMPLING=100 GOTOOLCHAIN=go1.26.6 go tool orchestrion go run ./cmd/f3verify`.
- Fix: give `Map` an exact per-rune segment mapper, like `mapValidUTF8Segments`, or re-run the mapping function over only the tainted input intervals and drop the taint when their output is empty.

### H5. Split/Fields window budget counts empty outputs, not the 32 published windows
- Severity: **High**. Status: CONFIRMED (`phase3/fx-prop-engine-core-F1.json` covers both ids).
- Location: `internal/taint/propagation/propagation.go:239-246` (`if outputIndex >= maxWindows { break }` runs before the `len(output)==0` skip); the byte twin is at `:515-537`.
- Contributing: prop-engine-core-F1, prop-string-exact-F1 (string-only dup), prop-engine-core-F3 (Low: 33 empty windows increment the drop counter).
- Mechanism: 32 empty fields (for example `",,,,…,attack"`) use up the index budget, so `parts[32]` is clean in both the string and byte variants. That is still below the documented 32-published-window cap.
- Repro: `fx-prop-engine-core-F1/go1.26.6-woven.out.txt`. `go tool orchestrion go test ./iast/propagation -run '^TestReviewFxSplitKeepsFirstNonEmptyAfterEmptyPrefix$'`. Also `prop-engine-core/window-budget.out.txt`.
- Fix: delete the `outputIndex >= maxWindows` break and keep the `published >= maxWindows` bound. Cap the scanned output count separately (for example 4×maxWindows) if the scan cost matters. Call `recordDropped` only when a non-empty alias is skipped.

### H6. `bytesAlias` bounds the result by `len(input)` instead of `cap(input)`
- Severity: **High**. Status: CONFIRMED (`phase3/fx-prop-bytes-exact-F1.json`).
- Location: `internal/taint/propagation/propagation.go:53-60` (`end <= base+uintptr(len(input))`).
- Contributing: prop-bytes-exact-F1.
- Mechanism: a valid reslice beyond the length but within capacity (`short[1:6]` or `short[1:6:7]` from `root[:3:7]`, or a lexer growing a token with `tok = tok[:len(tok)+1]`) is rejected as an alias. `ByteWindow` drops all exact ranges, so the byte slice, its string conversion, and the SQL query are untainted. The README advertises this path as supported (README:33,44-45).
- Repro: `fx-prop-bytes-exact-F1/woven-repro-go1.26.6.txt`. `go tool orchestrion go test -run '^TestFx' ./iast/io` with `zz_fx_reslice_woven_test.go`. Internal variant on 1.26.6 and 1.27.0: `prop-bytes-exact/repro-go1.26.6.txt`.
- Fix: bound by `cap(input)`. The falsifier verified this one-line fix, and existing suites stay green. The store root/window revalidation still clips ranges to the managed root. JSON literal alias checks (`json.go:31-33`) rely on `document[:len]`, so keep a len-bounded variant for that caller.

### H7. One Builder/Buffer can carry up to 60 owner writer records despite the four-owner-per-receiver limit
- Severity: **High**. Status: CONFIRMED (`phase3/fx-prop-writer-F1.json`, **reachable_default=false**: needs more than 4 concurrently active owners, while the default `DD_IAST_MAX_CONCURRENT_REQUESTS` is 2).
- Location: `internal/taint/propagation/writer.go:123-133` (the second loop admits every input owner not yet `seen`); `internal/taint/store/writer.go:104-107`.
- Contributing: prop-writer-F1, store-writer-F4 (Low: the soft limit also dirties and wipes the fifth owner's writers).
- Mechanism: after the four receiver owners are updated, each extra input-snapshot owner still calls `UpdateWriter`. With 60 configured owners, one Builder holds 60 charged records, 15x the documented local bound. The global store bound still holds.
- Repro: `fx-prop-writer-F1/go1.26.6.out.txt`. `go tool orchestrion go test -run '^TestFXPropWriterF1ConfiguredOwnerFanout$' ./iast/propagation`. Also `prop-writer/owner-fanout.out.txt`.
- Fix: in the second loop, stop once `seenCount + added >= MaxSnapshotOwners`, and record a drop.

### H8. Woven `[]byte`→`string` conversion heap-allocates even when IAST is disabled or sampled out
- Severity: **High**. Status: CONFIRMED (`phase3/fx-perf-escape-F1.json`, `phase3/fx-hooks-yml-operators-F4.json`). prop-concat-conv-json-F1 was rated Medium by its reviewer, so the phase-2 and phase-3 severities contradict each other. Phase 3 wins.
- Location: `iast/propagation/operators.go:198-204` (generic wrapper, inline cost 131 against a budget of 80); `internal/taint/propagation/conversion.go:15,42` (the result leaks through `AdoptString`).
- Contributing: prop-concat-conv-json-F1, perf-escape-F1, hooks-yml-operators-F4 (conversion half), hooks-fidelity-strings-F3 (Info).
- Mechanism: small non-escaping conversions lose their stack allocation in every root package: 1 alloc/op woven against 0 plain, with `DD_IAST_ENABLED=false`. The README's "allocation-preserving" claim is false.
- Repro: `fx-hooks-yml-operators-F4/woven-go1266.txt`, `fx-perf-escape-F1/`, `prop-concat-conv-json/woven_allocs.out`.
- Fix: put an inlinable pre-gate in the wrapper (`if !operatorbridge.HasValues() { return string(b) }`), and move the adopt path into a `//go:noinline` slow function so the fast path's result does not escape. The prop-concat-conv-json reviewer could not make the wrapper inlinable in a quick trial, so this fix is unverified.

### H9. Woven concat forces its operands to escape (`copy` into the local inputs array)
- Severity: **High**. Status: CONFIRMED through `phase3/fx-hooks-yml-operators-F4.json`, which measured concat-in-len and concat-in-comparison at 1 alloc/op woven against 0 plain. The direct contributors were rated Medium and never phase-3 checked.
- Location: `internal/taint/propagation/string_exact.go:56` and `bytes_exact.go:43` (`copy(inputs[:inputCount], elements[:inputCount])`); `operator_concat.go:9-79`.
- Contributing: prop-concat-conv-json-F2, perf-escape-F3, hooks-compile-matrix-F4 (real code: the x/exp/slog `TestTextHandlerAlloc` fails with 11 allocations per Handle against 0), hooks-yml-operators-F4 (concat half).
- Mechanism: escape analysis reports `leaking param content: elements`. Every `+` operand is heap-allocated, which defeats the zero-copy `"lit"+string(b)`. Customer `AllocsPerRun` tests fail under weaving.
- Repro: `prop-concat-conv-json/woven_allocs.out`; `hooks-compile-matrix/logs/x-exp.slogalloc-woven.log`; prototype patch at `perf-escape/prototype-fix-v3.patch`.
- Fix: replace `copy` with an explicit index loop. Both prop-concat-conv-json and perf-escape verified this in reviewer trials.

### H10. Writer wrappers gate only on "any active request", so every Builder/Buffer op in the process pays a 6 KB snapshot zero and a 64-owner walk
- Severity: **High**. Status: CONFIRMED (`phase3/fx-perf-hotpath-F2.json`).
- Location: `internal/taint/propagation/writer.go:23-25` (`WriterActive` returns `request.ActiveStore() != nil`) and `updateWriter` (`:98-102`); callers at `iast/propagation/writer.go:29-35,104-129`.
- Contributing: perf-hotpath-F2 (cross-part). Related: crash-stress-app-F2 (High, the Buffer invalidation hook scans the owner table; writerbridge/store scope).
- Mechanism: while any sampled request is live, a clean write with no writer state in any goroutine runs `LookupWriterValue`. Measured about 16.3 µs/op woven against 0.31 µs/op plain (about 50x).
- Repro: `fx-perf-hotpath-F2/bench-woven.txt` (command in the fx json).
- Fix: gate on `HasWriterStates() || MayContain(inputKey)` before building the snapshot. The falsifier notes this gate preserves provenance.

### M1. Coarse and duplicate-body adoption stamp `ranges.DefaultLimit` (10) into the Set, overriding `DD_IAST_MAX_RANGE_COUNT`
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/propagation.go:415,692`, `internal/taint/request/reader.go:110`. Later exact operations inherit the limit (`string_exact.go:72`, `bytes_exact.go:58`).
- Contributing: prop-ranges-fuzz-F1, prop-string-coarse-F6 (Info).
- Mechanism: after one coarse step, a limit of 64 truncates to 10 ranges (16 sources become 10), and a limit of 2 keeps 6. The 64 hard cap holds.
- Repro: `prop-ranges-fuzz/range-limit-repro.log` (`TestReviewCoarseResetsConfiguredRangeLimit`).
- Fix: pass `config.MaxRangeCount` (or the input entry's limit) instead of `DefaultLimit`.

### M2. Configured-range truncation is invisible to drop telemetry
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/string_exact.go:82-94`; other callers also ignore `Outcome.Truncated`. Contributing: prop-ranges-algebra-F1.
- Repro: `prop-ranges-algebra/range-drop.out.txt`. Fix: when `Truncated` is set, call `recordDropped` and increment the owner's range-drop counter.

### M3. Non-ASCII case conversion collapses the whole value to the first source
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/string_coarse.go:49-67`, `bytes_exact.go:382-399`. Contributing: prop-unicode-F1.
- Mechanism: any non-ASCII byte gives one `[0,len)` range, attributing clean template bytes to user input and dropping later sources, even though Unicode case mapping is rune-for-rune and exactly mappable.
- Repro: `prop-unicode/directed-go1.26.6.txt`. Fix: map ranges per rune with `utf8.DecodeRune` on input and output.

### M4. Coarse output keeps only the first contributor's source and marks the whole template as user input (not in README)
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/propagation.go:721-736`; `string_coarse.go:113-203`; `README.md:32`.
- Contributing: hooks-yml-fmt-strconv-url-F3, prop-string-coarse-F4 (Low: the source is chosen ignoring marks, latent because nothing sets marks today), sink-e2e-truepos-F5 (Info).
- Evidence: `hooks-yml-fmt-strconv-url/run_woven_go1.26.6.out.txt`. The design is documented in the plans (phase1/01-design-intent.md) but not in the README. Fix: document it in the README. Separately, prefer a contributor that lacks the surviving marks.

### M5. Zero-range snapshot entries are treated as taint hits
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/propagation.go:382-422`; `internal/taint/store/lookup.go:182-195`; `string_coarse.go:159-170`.
- Contributing: prop-engine-core-F2 (clean derived input clones its result), store-fuzz-F2 (a zero-provenance root is adopted, spending root, byte, and value budget), prop-string-coarse-F5 (a clean entry takes one of the 4 coarse owner slots and can crowd out a contributing owner).
- Repro: `prop-engine-core/clean-window-clone.out.txt`, `store-fuzz/reviews.out`.
- Fix: skip entries with `Ranges.Len()==0` in Lookup, or gate on the total range count.

### M6. Foreign or unsampled traffic that propagates owner A's value consumes A's bounded budgets
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/writer.go:123-133`, `store/writer.go:209-217`, `propagation.go:177-193,403-419`. Contributing: prop-owner-isolation-F2.
- Mechanism: 8 foreign builders exhaust A's MaxWriters, after which A's own Builder propagation is dropped. The foreign objects stay anchored until A finishes.
- Repro: `prop-owner-isolation/budget.out.txt`. Fix: only publish into an owner from its own scope, or keep a separate small budget for foreign contributions.

### M7. `JSONString` reports success and telemetry when every owner adoption failed
- Severity: Medium (highest contributor), reviewer-reported, static only. Location: `internal/taint/propagation/json.go:42-69`. Contributing: store-api-misuse-F2 (Medium), prop-concat-conv-json-F3 (Low).
- Fix: return `published=false` unless at least one `AdoptString` succeeds.

### M8. `JoinString` scans every element for an alias before the active-store gate
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/string_exact.go:21-48`. Contributing: store-api-misuse-F1, perf-hotpath-F3.
- Mechanism: unbounded O(n) clean-path work despite the 16-input bound. Evidence: `perf-hotpath/bench.txt`. Fix: check `request.ActiveStore()` first and cap the scan.

### M9. Tainted Repeat clones before checking bounds or budget
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/propagation.go:262-297`, `:546-575`. Contributing: perf-memory-F3, prop-engine-fuzz-F4 (Info: RepeatBytes looks up before `withinByteBounds`).
- Mechanism: in the saturated worst case, 4.92 MB/request of clones are made after the 2 MiB root budget is full. Evidence: `perf-memory/prof/sat-worst-clone-peek.txt`. Fix: check bounds and budget before `Lookup` and `strings.Clone`.

### M10. Each `Builder.String()` on a tracked writer clones and publishes a new root, even when unchanged
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/writer.go:190-237`. Contributing: store-writer-F3 (511 calls exhaust the 512-root budget and later provenance is dropped), hooks-fidelity-bytes-F2 (Low: O(n²) copying in loops).
- Evidence: `store-writer/builder-string-budget.out.txt`. Fix: cache the last published clone per writer generation.

### M11. Repository fuzzers never reach the exact→coarse, drop, writer, or JSON paths
- Severity: Medium, reviewer-reported. Location: `internal/taint/propagation/sequence_operations_test.go:16-33,131,138`; `ranges/fuzz_test.go:14-90`.
- Contributing: crash-fuzz-engine-F1 (coarse, case, window, Concat, JSON, writer, and recordDropped paths at 0% coverage), prop-engine-fuzz-F2, prop-ranges-fuzz-F2 (FuzzSliceAndCopy has no oracle; Compose, Coarse, Shift, and Marks are never checked by an oracle), crash-fuzz-engine-F2 (lifecycle fixed and single-threaded).
- Evidence: `crash-fuzz-engine/fuzz-corpus-coverage.func.txt`. Fix: upstream the review oracles (`prop-engine-fuzz/zz_review_exact_ops_fuzz_test.go`, `prop-ranges-fuzz/oracle_review_test.go`).

### M12. No engine microbenchmarks, and the operator benchmarks run unwoven
- Severity: Medium, reviewer-reported. Contributing: perf-bench-quality-F2 (no `Benchmark*` in internal/taint/propagation), perf-bench-quality-F3, prop-concat-conv-json-F5 (also: Concat tests do not pin offsets).
- Evidence: `perf-bench-quality/concat4-unwoven-no-signal.out.txt`. Fix: add tainted-hit engine benchmarks, and skip operator benchmarks unless `built.WithOrchestrion`. These benchmarks would have caught H8 and H9.

## 3. Low / Info and code quality

- Low, reviewer-reported: a single-element `Join` with a non-empty separator clones and double-charges the root instead of aliasing (prop-engine-fuzz-F1, crash-diff-strings-F2, hooks-fidelity-strings-F2). `string_exact.go:24-47`, evidence `prop-engine-fuzz/join_single.out.txt`.
- Low: a Join with more than 16 elements falls back to coarse, taints clean parts, and ignores the tail. README:34 does not mention it (crash-diff-bytes-F2). The gate inspects 16 elements, but the fallback reads only 15 (prop-engine-fuzz-F3, Info). Evidence `crash-diff-bytes/woven-deterministic-run1-go1.26.6.txt`.
- Low: the JSON literal intersection window includes the quotes, so taint that touches only a quote taints the whole value (prop-concat-conv-json-F4, `json.go:33,49`, `prop-concat-conv-json/unit_reproducers.out`).
- Low: `strings.ToValidUTF8` is coarse while the bytes variant is exact (prop-unicode-F2). `To*Special` and `Title` are not woven (prop-unicode-F3, `orchestrion.yml:661-686,1012-1037`).
- Low: tainted concat repeats lookups for each owner, up to 16+4×17 (prop-concat-conv-json-F6, static).
- Low: `ranges.Canonicalize` is exported, has no production caller, and uses a 29 KiB stack frame (prop-ranges-fuzz-F3).
- Low: drop counters are inflated by empty windows (prop-engine-core-F3) and by fmt calls with more than 15 or 16 arguments before any lookup (hooks-yml-fmt-strconv-url-F5).
- Low: a torn Lookup can build a hybrid Entry that mixes the stale OwnerGen with the successor's state. All consumers reject it through the (index, gen, ID) check, so there is no current impact. This is the same root cause as store-stress-F1 (prop-owner-isolation-F3, `prop-owner-isolation/lookup-torn.out.txt`).
- Info: context-less sinks attribute foreign-owner taint to the foreign span and bypass the sampled-out guard (prop-owner-isolation-F4). `Analysis.Finish` uses check-then-CAS but is unreachable (prop-owner-isolation-F5). Window drops under sustained per-root load are consistent with MaxValuesPerRoot (crash-diff-strings-F3).
- Cross-part Highs that touch `internal/taint/propagation/writer.go` or `conversion.go` but whose root causes live in store, request, or iast code (see those parts): Builder view ABA after GC address reuse (store-identity-gc-F1, store-writer-F2, crash-diff-bytes-F1, life-cross-request-F2); Buffer view matching across receivers (life-cross-request-F3); unrelated writer activity wipes an owner's writers (store-writer-F1); a pooled `io.ReadAll` slice attributes A's body to B (life-cross-request-F1); stale owner handles publish into the successor (store-stress-F1, store-concurrency-F1); stale candidates fill the Lookup fanout (store-lookup-F1, adjusted to Medium).

## 4. Verified correct

- Range algebra: Canonicalize precedence, merging, and truncation; the `2n-1` fragment bound; uint32 overflow rejection; dst aliasing; input immutability; bounded Repeat (prop-ranges-fuzz, prop-ranges-algebra). Evidence `prop-ranges-fuzz/oracle-100k.log`.
- Exact Replace, ValidUTF8, ASCII case, Join, and Repeat segmenters match the stdlib byte-for-byte, including the 32 vs 33 match boundary and empty `old` over invalid UTF-8. The oracle caught all 4 injected mutations (prop-unicode, prop-engine-fuzz, prop-string-exact).
- Wrapped calls return values byte-identical to the stdlib in 24.7M execs. Wrappers call the native function exactly once and preserve errors. `formatArgumentKey` cannot panic and never invokes user methods (prop-engine-fuzz, prop-string-coarse).
- No out-of-bounds range can reach consumers: Lookup window slicing, adopt's `ValidFor` check, Compose/Slice/Copy validation (prop-unicode, prop-concat-conv-json).
- Concat offsets for 2-16 operands (2244 tainted oracle cases); `BytesToString` window-relative ranges; JSON pointer arithmetic and `\u` escapes (prop-concat-conv-json).
- The `coarse.go:42` ToValidUTF8 identity guard is correct and necessary (prop-string-coarse).
- Owner isolation: per-owner ranges; stale values stay clean after slot, permit, root, and source-ID reuse; 0 mismatches over 817k cycles, and 0 under `-race` (prop-owner-isolation, `owner-iso-race.out.txt`).
- Writer Concat offsets, truncate, reset, and exposure invalidation; the woven writer tests pass (prop-writer). Mutation invalidation of byte roots and in-length windows (prop-bytes-exact).
- The no-active-store gate is allocation-free inside the engine itself (prop-engine-core). H8 and H9 are allocations in the woven wrappers and escape paths, not in this gate.

## 5. Coverage gaps

- Coarse fmt/JSON/writer paths were never fuzzed (M11). All fuzzing was single-goroutine, and fuzzing ran on Go 1.26.6 only (the Unicode differential also ran on 1.27.0).
- More than 4 owners and snapshot fanout under contention, and TryLock drop behavior, were left to the store part.
- Non-default `DD_IAST_MAX_RANGE_COUNT` was exercised only by prop-ranges-fuzz. The store overflow-pool truncation above 10 ranges was not fuzzed.
- Woven Go 1.27.0 verification of H1, H4, and others was blocked by the separate encoding/json weave compile failure (base-test-127).
- No wall-clock engine benchmarks exist. H8 and H9 rest on allocation counts, and H10 on falsifier benchmarks.
- Invalid UTF-8 in evidence parts cut mid-rune (prop-unicode) and redaction quality under whole-query coarse taint (prop-string-coarse) were not assessed.
- The documented safe misses (1-byte fresh roots, 32 windows, 16 inputs, mutable aliases, `NewReplacer` replacement terms, `text/template`, `path.Join`, `regexp`) were not re-reported. prop-semantics-parity flags them as likely SQLi/CMDi detection gaps in real code.
- Contradictions between artifacts: prop-concat-conv-json says "no Critical/High", but phase 3 confirms H8 and H9 as High. prop-engine-fuzz says "no correctness defect", but it did not assert outputs beyond index 32, so it could not see H5. prop-string-coarse-F2 (Medium) and hooks-yml-fmt-strconv-url-F4 (Low) conflict with the phase-3 High for the same root (H2). The phase-3 severities are used throughout.

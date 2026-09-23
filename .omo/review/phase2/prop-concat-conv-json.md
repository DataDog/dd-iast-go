# prop-concat-conv-json: operator concat, []byte->string conversion, and JSON literal propagation
Verdict: Provenance is correct and bounds-safe in all three files. Concat offsets for 2-16 operands, window-relative conversion ranges, and JSON literal pointer arithmetic and escape handling all check out, and there are no Critical or High issues. The problems are on the host-cost side: the woven conversion and concat wrappers add a heap allocation even when IAST is inactive (two Medium findings), plus a few Low items.
Scope covered: `internal/taint/propagation/{operator_concat,conversion,json}.go` in full; the helpers they rely on: `string_exact.go` (`JoinString`, `joinStringHit`, `collectStringOwners`, `stringOwnerRanges`), `propagation.go` (`stringAlias`, `bytesAlias`, `StringWindow`), `ranges/operations.go` (`Copy`, `Concat`, `Slice`, `Coarse`), `store/{store,lookup,root,value}.go` (`Key`, `Lookup`, `Entry.Handle`, `AdoptString`, `Derive`/`putWindow`); callers: `iast/propagation/operators.go` and `orchestrion.yml` (concat/conversion aspects), `iast/encoding/json/{json.go,orchestrion.yml}`, `internal/taint/jsonbridge/bridge.go`; the orchestrion `type-conversion` and `string-concat` join points at `23afa71d6dcb`; the existing tests `json_test.go` and `iast/propagation/operators_test.go`. I ran new reproducers in a private copy, both unwoven and under `go tool orchestrion go test`.

## Findings
### prop-concat-conv-json-F1: Woven `[]byte`->`string` conversion always heap-allocates, even with IAST inactive
- Severity: Medium
- Category: perf
- Location: iast/propagation/operators.go:198-204; internal/taint/propagation/conversion.go:15,42
- Claim: The conversion aspect rewrites `s := string(b)` to `string(iastprop.BytesToString(b))`. In the generic wrapper, `result := string(value)` (operators.go:199) is returned from a function that cannot be inlined (`cost 131 exceeds budget 80`). In addition, `internal.BytesToString` leaks `result` to the heap through `owner.AdoptString(result, ...)` (conversion.go:42). As a result, a conversion that the native compiler keeps on the stack (non-escaping, <=32 bytes, via tmpBuf) becomes a heap allocation on every call. This happens in every root-application package, whether or not IAST is disabled, unsampled, or idle, because escape analysis is compile-time and ignores the `HasValues()` gate. The README calls these conversions "allocation-preserving", which is only true for results that already escape. Rule 2 ("never slow the host more than strictly necessary") is violated on a hot path.
- Evidence: `.omo/review/evidence/prop-concat-conv-json/zz_review_woven_test.go` (package `zzreview`, woven). Command: `go tool orchestrion go test -count=1 -run TestReviewWovenAllocs -v ./zzreview/` gives `WOVEN-ALLOCS s:=string(b) 1`; the unwoven baseline gives `0` (`woven_allocs.out`). The unit version `zz_review_alloc_test.go` prints `ALLOCS native string(b) 0` and `ALLOCS woven BytesToString 1` (`unit_reproducers.out`). The escape analysis output in `escape_analysis.out` shows `conversion.go:15:34: parameter result leaks to {heap} ... from (*store.Owner).AdoptString(owner, result, &copied)` and `operators.go:199:19: string(propagation.value) escapes to heap`.
- Fix: (1) On the tainted hit path, clone into a managed copy and adopt/return that clone, as `joinStringHit` does, so that `result` leaks only to `~r0`. I verified in a trial that this removes the heap leak. (2) The wrapper must also become inlinable (<=80 cost, for example with a non-generic thin wrapper plus a `//go:noinline` slow helper). Otherwise, restrict the aspect to contexts where the result already escapes. Fix (1) alone left 1 alloc in my trial, because the wrapper itself returns `string(value)`. If neither is done, correct the README "allocation-preserving" wording.

### prop-concat-conv-json-F2: Woven concat forces every operand to escape, adding an allocation for `"lit" + string(b)` even when IAST is inactive
- Severity: Medium
- Category: perf
- Location: internal/taint/propagation/operator_concat.go:9-79 -> internal/taint/propagation/string_exact.go:56
- Claim: `Concat2..16` pass `[]string{a, b, ...}` to `JoinString`, and `joinStringHit` does `copy(inputs[:inputCount], elements[:inputCount])` into a local array. Go escape analysis models `copy` of a pointer-bearing slice as a heap flow, so every operand of every woven `+` chain is tagged "leaking param". For `"p" + string(b)`, the native compiler uses a zero-copy temporary conversion (`slicebytetostringtmp`) and needs no allocation. The conversion is intentionally unwrapped, but the concat is woven to `Concat2("p", string(b))`, so `string(b)` must now be a real heap copy on every call, regardless of IAST state. Any other stack-resident operand is affected the same way.
- Evidence: Woven run (`woven_allocs.out`): `WOVEN-ALLOCS s:="p"+string(b) 1` versus `0` unwoven, while `s:=a+b` stays `0`. Escape analysis (`escape_analysis.out`): `string_exact.go:50:36: parameter elements leaks to {heap} ... from copy(inputs[:inputCount], elements[:inputCount])` and `operator_concat.go:9:14: parameter a leaks to {heap}`. Trial fix in the private copy: after replacing the `copy` with an index loop (`for i := 0; i < inputCount; i++ { inputs[i] = elements[i] }`), `-m` reports `operator_concat.go:9:14: a does not escape`, `ALLOCS woven Concat2(p,string(b))` drops to `0`, and all reproducers still pass.
- Fix: Replace the `copy` at string_exact.go:56 with an element-wise loop (verified above), and add an allocs regression test for a woven `"lit"+string(b)`.

### prop-concat-conv-json-F3: `JSONString` reports success and records telemetry even when no owner adopted the clone
- Severity: Low
- Category: quality
- Location: internal/taint/propagation/json.go:56-68
- Claim: `owner.AdoptString(clone, &coarse)` ignores its result. When every adoption fails (store saturation, contention, a stale handle), the function still returns `(clone, true)` and calls `recordExecuted()` and `recordCoarse()`. The caller then calls `value.SetString(clone)` with an untracked copy. The value is still equal, so there is no host impact, but it costs an allocation and inflates the executed/coarsened telemetry. `conversion.go:41-49` does track a `published` flag, so the two paths are inconsistent.
- Evidence: static reasoning only (NEEDS-REPRO). json.go:60 discards `(RootRef, bool)`, and json.go:63 checks only `clone == ""`.
- Fix: Track `published` as conversion.go does. Return `(result, false)` and skip telemetry when nothing was adopted.

### prop-concat-conv-json-F4: JSON literal range includes the delimiting quotes, so quote-only taint coarsens the whole value
- Severity: Low
- Category: provenance
- Location: internal/taint/propagation/json.go:33,49
- Claim: The intersection window is the raw token `[offset, offset+len(literal))`, which includes the opening and closing `"`. If a document's taint touches only a delimiter (for example a partially tainted document whose tainted range ends at or starts on the quote), the whole decoded string gets a coarse range. In practice documents are uniformly tainted body roots, so the impact is small.
- Evidence: `zz_review_concat_conv_json_test.go` `TestReviewJSONStringBoundsAndEscapes`: taint only on byte 11 (the closing quote) of `{"v":"clean"}` prints `QUOTE-ONLY: propagated=true ranges=[{0 5 9 0}]` (`unit_reproducers.out`).
- Fix: For quoted tokens, intersect `[offset+1, offset+length-1)`. For the `,string` outer token, the same trimming applies to the outer quotes.

### prop-concat-conv-json-F5: Concat tests do not pin offsets, and the operator benchmarks run unwoven
- Severity: Low
- Category: test-gap
- Location: iast/propagation/operators_test.go:25-60,98-104,145-178
- Claim: The arity tests always place the tainted operand last and assert only `IsTaintedString`. No test checks exact ranges for first, middle, or multiple tainted operands, empty operands, or two owners. `internal/taint/propagation` has no direct `Concat*` test. `BenchmarkOperator*Inactive` live in `iast/propagation`, which is excluded from the operator aspects (orchestrion.yml:17-20), so they measure native code and cannot catch F1 or F2.
- Evidence: I read the test file. My randomized per-byte oracle test (`TestReviewConcatOffsetsProperty`, 3000 cases, 2244 tainted comparisons, 2-16 operands, empty/clean/tainted mixes) passes, so this is a coverage gap, not a defect.
- Fix: Keep a property test like the reproducer, and move the alloc and benchmark checks into a woven root package (as `zzreview` in the evidence does).

### prop-concat-conv-json-F6: The tainted concat path repeats snapshot lookups per owner
- Severity: Low
- Category: perf
- Location: internal/taint/propagation/string_exact.go:59,76-80
- Claim: `collectStringOwners` already looks up every operand, and then `stringOwnerRanges` looks each one up again for every owner. A tainted `Concat16` therefore does up to 16 + 4x17 `Lookup` calls, each with three TryRLocks, `AdoptCanonical`, and `Slice`. This is only on the tainted path and is bounded.
- Evidence: static reasoning only (NEEDS-REPRO).
- Fix: Cache each operand's snapshot once (16 x `Snapshot` on the stack is bounded) and select per-owner entries from the cache.

## Checked and found correct
- Concat offsets for 2-16 operands: `joinStringHit` accumulates `currentLen` per element with an empty separator. `ranges.Concat` shifts by `leftLen`, and the `currentLen == len(clone)` guard holds. The randomized per-byte oracle agreed in all 2244 tainted cases, including empty operands, clean operands, and the same source repeated. Arity cannot exceed `maxInputs`, so the coarse fallback is unreachable for operators.
- `"" + s` alias path (the runtime returns the lone non-empty operand): `JoinString` derives the identical key, and `putWindow` dedups same-owner/same-key slots, so repeated calls neither grow the store nor misplace ranges (`TestReviewConcatAliasSingleNonEmpty`, all arities).
- A concat result that lives on the stack (a non-escaping inlined `a+b`) is never adopted. The non-alias path adopts a heap `strings.Clone`, and stack pointers are only compared as `uintptr`.
- `BytesToString`: an equal-length check, `len>=2` (which avoids the runtime's static one-byte strings), and `MaxRootBytes`. `Entry.Ranges` is already window-relative (lookup.go:180-182), so `ranges.Copy` over `len(input)` is exact, even for a derived window whose root has spare capacity (`TestReviewBytesToStringCopiesWindowRanges`). The result is a fresh `slicebytetostring` heap allocation at base, adopted per owner after `Handle` revalidation, and the host value is returned unchanged.
- JSON pointer arithmetic (json.go:31-33): `bytesAlias` bounds `literal` fully inside `document[:len]`, including an overflow guard. `BytesKey` caps the length at uint32, so `offset` and `offset+length` cannot overflow and are `<= key.Length`. `ranges.Slice` revalidates. I checked literal == whole document, a literal at the end, a document that is a derived window with a non-zero root offset, and a literal in the root prefix outside the window (rejected). Nothing is dereferenced through `uintptr`.
- `\u` escapes: the coarse output uses `len(result)` and the part uses `len(literal)`, so a length change is harmless. `"\u0041\u0042"`->`"AB"` gives `{0,2}`, and `"\u00e9\u00e9"`->`"éé"` gives `{0,4}`. Whole-value coarse ranges are documented in the README.
- Two owners on one document each adopt the same clone (2 snapshot entries).
- jsonbridge's `,string` and mapped-clone re-slicing keep `literal` inside `document`. A fresh `[]byte(qv)` item fails `bytesAlias`, which is a safe miss.

## Not covered / open questions
- One-byte results are never tainted: a JSON string like `"'"`, a 1-byte `string(b)`, and any `len<2` concat result (json.go:20, conversion.go:16, string_exact.go:60). This is the documented "new roots >=2 bytes" rule, noted here only as a known false-negative class for single-character payloads.
- I did not do an end-to-end check of the orchestrion string-concat join point's constant-expression and type-parameter (`~string|~int`) exclusions, or of the jsonbridge decoder-slot and reentrancy behavior. Those belong to other nodes.
- The F1 fix is unverified: I could not make the generic wrapper inlinable in a quick trial.
- I ran no wall-clock benchmarks, per the brief. F1 and F2 are evidenced by allocation counts only.

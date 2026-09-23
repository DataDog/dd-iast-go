# Phase 1 audit: every uncovered `internal/taint/propagation` coverage block

Classification of the 128 zero-hit blocks (142 statements) in the propagation
engine at source revision `3168522002ee7e5eee83338e6c991c659415b6a7`. The driver
checked every table coordinate and statement count against the exact profile,
then resolved the audit's testability questions below. Only planning documents
have changed. Baseline profile: `/tmp/dd-iast-pr39-coverage-20260922/ci-published/coverage-merged/coverage.merged.txt`
(`mode: atomic`, 4,356 block records, no duplicate block keys, so no merge
arithmetic was needed). No production or test code changed. The source auditor used no git/jj command.
See [review evidence](propagation-coverage-review.md) for driver validation.

## Reconciliation

Per-file statement totals, computed from the uploaded profile by summing the
statement counts of every block record whose path ends in the named file:

| File | Statements | Covered | Uncovered | Coverage | Zero-hit blocks |
| --- | ---: | ---: | ---: | ---: | ---: |
| `bytes_exact.go` | 290 | 262 | 28 | 90.3% | 24 |
| `conversion.go` | 25 | 19 | 6 | 76.0% | 6 |
| `json.go` | 34 | 30 | 4 | 88.2% | 4 |
| `operator_concat.go` | 15 | 15 | 0 | 100.0% | 0 |
| `propagation.go` | 395 | 348 | 47 | 88.1% | 46 |
| `string_coarse.go` | 119 | 104 | 15 | 87.4% | 14 |
| `string_exact.go` | 194 | 171 | 23 | 88.1% | 18 |
| `telemetry.go` | 3 | 3 | 0 | 100.0% | 0 |
| `writer.go` | 119 | 100 | 19 | 84.0% | 16 |
| **Engine total** | **1,194** | **1,052** | **142** | **88.1%** | **128** |

The engine total matches the plan's recorded baseline (1,052 / 1,194 = 88.1%) and
the reported 142 unexecuted statements exactly. `conversion.go` 76.0% and
`writer.go` 84.0% also match the plan's named weak files.

Every row in the block table below appears exactly once, and the per-file row
counts and statement sums equal the columns above (verified programmatically:
128 rows, 142 statements, zero missing and zero extra blocks against the
profile's zero-hit set).

## Classification scheme

The requested four buckets do not cleanly hold two distinct honest cases, so the
scheme below splits them and maps back. Nothing is called unreachable merely
because a test cannot force it.

| Code | Meaning | Maps to requested bucket |
| --- | --- | --- |
| **R** | Reachable ordinary scenario: a real native call site or a documented internal-engine contract (explicitly marked when not a native wrapper path). | reachable ordinary scenario |
| **D** | Deterministic failure seam that exists today through the exported API (the finished-owner stale slot, note N6). | deterministic failure seam |
| **DN** | Deterministic, but only from a **new in-package white-box test file** that passes an already-stale `store.Snapshot` to an unexported publish helper. Included in the proposed plan; verify linkage under coverage-instrumented Orchestrion builds before extending it. | deterministic failure seam (conditional) |
| **DA** | Deterministic, but only by calling the exported engine function with **arguments outside the native caller contract** (negative counts, mismatched result lengths, negative `written`). Do not add tests solely to force these guards; preserve existing defensive tests. | outside native caller contract |
| **X** | **Race-dependent and genuinely reachable**, requiring a specific lookup/finish/publication order. Confirmed: no propagation seam can pause lookup or publication, and none can hold the store lifecycle lock, so these cannot be forced today. Not unreachable. | race-dependent requiring specific order |
| **I** | Reachable in principle but **outside the test-resource budget** (needs a value above 4 GiB). Legal Go, not a corrupt value; intentionally not allocated by these bounded tests. Not unreachable. | (separated; see note) |
| **U** | **Unreachable under the native contract** and the engine's own established invariants: no argument a native call site can produce reaches the block. | unreachable under native contract |

Class totals: **R 53, D 8, DN 7, DA 5, X 17, I 10, U 42 = 142 statements.**
The driver reclassified the documented count-one byte alias as R (2 statements),
and the two large string/byte writer guards as I (4 statements): native writes
above 4 GiB can reach those guards even though negative counts cannot.

| File | Blocks | Stmts | R | D | DN | DA | X | I | U |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `bytes_exact.go` | 24 | 28 | 6 | 1 | 0 | 0 | 5 | 4 | 12 |
| `conversion.go` | 6 | 6 | 3 | 0 | 0 | 0 | 1 | 0 | 2 |
| `json.go` | 4 | 4 | 1 | 1 | 0 | 0 | 0 | 0 | 2 |
| `propagation.go` | 46 | 47 | 14 | 5 | 6 | 3 | 4 | 0 | 15 |
| `string_coarse.go` | 14 | 15 | 10 | 1 | 1 | 0 | 1 | 0 | 2 |
| `string_exact.go` | 18 | 23 | 10 | 0 | 0 | 0 | 2 | 2 | 9 |
| `writer.go` | 16 | 19 | 9 | 0 | 0 | 2 | 4 | 4 | 0 |
| **Total** | **128** | **142** | **53** | **8** | **7** | **5** | **17** | **10** | **42** |

### Shared invariants referenced by the table

- **N1** `snapshot.At(i)` / `set.At(i)` returning `!ok` inside a loop bounded by
  `Len()`: the index is always in range. `Snapshot.At` fails only for a nil
  receiver or an out-of-range index (`internal/taint/store/lookup.go:61`).
  Structurally impossible, not merely untested.
- **N2** Every range set handed to `ranges.Copy`/`Slice`/`Concat`/`Compose` comes
  from `store.Store.Lookup`, which slices each window to `key.Length` and
  validates it (`lookup.go:160-176`), so every input is `ValidFor` its own length.
  These primitives fail only on invalid input or uint32 overflow, and the engine
  caps `len(result)` at `store.MaxRootBytes` (64 KiB), so the accumulation cannot
  overflow.
- **N3** `total` / `currentLen` equals `len(result)` by the definition of the
  native operation being wrapped (`strings.Join`, `bytes.Replace`,
  `bytes.ToValidUTF8`, ...). Divergence requires a fabricated direct call.
- **N4** `!ValidFor(cap(result))`: the immediately preceding guard already proved
  the set spans exactly `len(result)`, and `len(result) <= cap(result)`.
- **N5** Once `MayContain` has matched, `store.Store.Lookup` returns `false` only
  when the shard `TryRLock` fails (key validity is already proven). A concurrent
  writer must hold that shard lock.
- **N6 (finished-owner stale slot, the one exported-API failure seam)**
  `Owner.Finish` releases roots and stores `stateDead` but leaves the shard value
  slot in place; slot reclamation happens only on a later insertion
  (`store/value.go:putWindow`, `store/owner.go:Finish`). `MayContain` performs no
  owner validation by design (`lookup.go:81`). So after finishing one owner while
  the request scope stays active, `MayContain(key)` still returns true while
  `Lookup(key,&snap)` returns true with `snap.Len()==0`. That is deterministic and
  reachable from `package propagation_test` today.
- **N7 (clean window of a tainted root)** `Owner.Derive` registers a window with
  no requirement that the window carry ranges, so a window over the untainted part
  of a tainted root yields a `Lookup` entry with `Ranges.Len()==0`. That owner is
  collected but contributes nothing, which is how the `Len()==0` / `!found` /
  `currentLen` mismatch branches become deterministic without any fabricated value.
- **N8** `utf8.DecodeRune`/`DecodeRuneInString` returning width 0 requires an
  empty slice; the loop already breaks when `position == len(input)`.
- **N9 (owner fanout)** `Lookup` caps one snapshot at `store.MaxSnapshotOwners`
  (4) per key, so reaching `ownerCount >= len(owners)` needs 5+ distinct live
  owners spread over at least two inputs of the same call.
- **N10** The coarse single-range `AdoptCanonical` call cannot be invalid:
  `Start == 0`, `Length == len(output) > 0`, and the marks are an intersection of
  marks already validated by the store, so `validCanonicalSlice` always accepts.

## Block table

`Loc` is `startLine.startCol-endLine.endCol` exactly as recorded in the profile.

### `bytes_exact.go` - 24 blocks, 28 statements

| Loc | n | Class | Scenario / invariant | Existing test or seam | Planned smallest test |
| --- | ---: | --- | --- | --- | --- |
| 69.22-71.10 | 2 | U | `ranges.Concat` invalid for an element in `joinBytesHit`; N2. | `TestJoinBytesPreservesElementAndSeparatorRanges` | none; document N2 in `joinBytesHit` |
| 77.23-79.11 | 2 | U | Same for the separator leg of the `Concat` chain; N2. | `TestJoinBytesCoarseFallbackIncludesSeparator` | none; document N2 |
| 86.72-87.12 | 1 | R | `currentLen != len(result)` or `current.Len()==0`: an owner contributing only a clean window; N7. | `TestJoinBytesTwoOwnersKeepLocalSourceIDs` (no clean-window case) | `bytes_exact_test.go` `TestCleanWindowOfTaintedRootPublishesNothing` |
| 89.45-90.12 | 1 | U | `!current.ValidFor(cap(result))`; N4. | `TestByteExactOpsRejectOversizedAndInteriorAliasResults` | none; document N4 |
| 93.10-94.12 | 1 | X | `entry.Handle` fails: owner must go active->dead between `joinBytesHit`'s inline `Lookup` and this publication. | `TestByteExactOpsFinishRaceIsSafe` (stress; proves safety, not ordering) | none forceable; keep stress, record residual |
| 131.45-134.3 | 2 | I | `len(input) > MaxUint32` coarse fallback: needs a >4 GiB slice. | none | none; document the bound |
| 164.35-165.12 | 1 | U | `total != len(result)` after replace segmentation; N3. | `TestReplaceBytesMapsCopiedAndReplacementSegments` | none; document N3 |
| 169.45-170.12 | 1 | R | `Compose` invalid or `resultSet.Len()==0`: input and replacement both clean windows; N7. | `TestReplaceBytesPreservesPartialRanges` | `TestCleanWindowOfTaintedRootPublishesNothing` |
| 172.47-173.12 | 1 | U | `!resultSet.ValidFor(cap(result))`; N4. | `TestByteExactOpsRejectOversizedAndInteriorAliasResults` | none; document N4 |
| 176.10-177.12 | 1 | X | `entry.Handle` fails in `replaceBytesHit` (inline `Lookup`, no pause point). | `TestByteExactOpsFinishRaceIsSafe` | none forceable; residual |
| 214.18-216.5 | 1 | U | `utf8.DecodeRune` width 0; N8. | `TestReplaceBytesEmptyOldUnicodeAndInvalidUTF8` | none; document N8 |
| 245.51-247.3 | 1 | R | `ValidUTF8Bytes` result bound: empty, one-byte, or len/cap above `MaxRootBytes`. | `TestByteExactOpsRejectOversizedAndInteriorAliasResults` covers Join/Replace/Case only | extend that test with `ValidUTF8Bytes` |
| 249.80-251.3 | 1 | R | No active scope, or neither input nor replacement may be tainted. | `TestByteExactOpsNoActiveAndUntaintedAreAllocationFree` omits `ValidUTF8Bytes` | extend that test with `ValidUTF8Bytes` |
| 261.21-263.3 | 1 | D | `ownerCount == 0` after a `MayContain` hit; N6. | Only the nondeterministic finish-race test covers the Join/Replace/Case twins; `ValidUTF8Bytes` is not in that stress loop at all | `bytes_exact_test.go` `TestFinishedOwnerStaleSlotIsDropped` |
| 264.45-267.3 | 2 | I | `len(input) > MaxUint32`; >4 GiB input. | none | none; document the bound |
| 297.35-298.12 | 1 | U | `total != len(result)` for `ToValidUTF8` segments; N3. | `TestValidUTF8BytesUsesOnlyContributingReplacement` | none; document N3 |
| 388.10-389.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 400.45-401.12 | 1 | R | `Copy`/`Coarse` invalid or `resultSet.Len()==0` in `caseBytesHit`: clean window into `bytes.ToUpper`; N7. | `TestCaseBytesExactASCIIAndCoarseUnicode` | `TestCleanWindowOfTaintedRootPublishesNothing` |
| 403.47-404.12 | 1 | U | `!resultSet.ValidFor(cap(result))`; N4 (exact path equal length, coarse path one range of `len(result)`). | `TestByteExactOpsRejectOversizedAndInteriorAliasResults` | none; document N4 |
| 407.10-408.12 | 1 | X | `entry.Handle` fails in `caseBytesHit` (inline `Lookup`). | `TestByteExactOpsFinishRaceIsSafe` | none forceable; residual |
| 435.32-436.12 | 1 | X | `s.Lookup` false in `collectBytesOwners`; N5 shard contention. | `TestByteExactOpsFinishRaceIsSafe` | none forceable; residual |
| 443.33-444.13 | 1 | R | `ownerCount >= MaxSnapshotOwners`; N9 (5+ owners across Join/Replace/ValidUTF8 inputs). | `TestJoinBytesTwoOwnersKeepLocalSourceIDs` uses two owners | `bytes_exact_test.go` `TestOwnerFanoutBeyondSnapshotBound` |
| 460.31-462.3 | 1 | X | `s.Lookup` false in `bytesOwnerRanges`; N5. | `TestByteExactOpsFinishRaceIsSafe` | none forceable; residual |
| 465.10-466.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |

### `conversion.go` - 6 blocks, 6 statements

| Loc | n | Class | Scenario / invariant | Existing test or seam | Planned smallest test |
| --- | ---: | --- | --- | --- | --- |
| 16.86-18.3 | 1 | R | `BytesToString` rejects `len(result)<2`, `len(input)!=len(result)`, or `len(result)>MaxRootBytes`. | `range_behavior_test.go:54` covers only the success path | `range_behavior_test.go` `TestBytesToStringRejectsIneligibleInputs` |
| 20.19-22.3 | 1 | R | No active analysis scope. | `TestNoActiveStoreIsNoOpAndAllocationFree` omits `BytesToString` | extend `TestNoActiveStoreIsNoOpAndAllocationFree` |
| 24.36-26.3 | 1 | R | `BytesKey` fails (empty input) or `MayContain` misses (untainted input). | `TestUntaintedPathIsAllocationFree` omits `BytesToString` | extend `TestUntaintedPathIsAllocationFree` |
| 28.36-30.3 | 1 | X | `active.Lookup` false; N5. This guard has **no** `Len()==0` companion, so the N6 seam does not reach it: a stale slot falls through the empty loop and returns the unpublished result instead. | none | none forceable; residual |
| 34.10-35.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 38.91-39.12 | 1 | U | `ranges.Copy` invalid; N2 with `len(input)==len(result)`. | `range_behavior_test.go:54` | none; document N2 |

### `json.go` - 4 blocks, 4 statements

| Loc | n | Class | Scenario / invariant | Existing test or seam | Planned smallest test |
| --- | ---: | --- | --- | --- | --- |
| 24.14-26.3 | 1 | R | `JSONString` with no active analysis scope. | `TestJSONStringRejectsIneligibleInputs` covers length/alias guards only | extend that test with a no-scope case |
| 39.54-41.3 | 1 | D | `Lookup` false **or** `snapshot.Len()==0`. The `Len()==0` disjunct is deterministic via N6; the `Lookup`-false disjunct is contention only (N5). | `TestJSONStringPropagatesLiteralProvenance` | `json_test.go` `TestJSONStringDropsFinishedOwnerDocument` |
| 45.10-46.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 53.175-54.12 | 1 | U | `Coarse` invalid or `coarse.Len()==0`: `intersected.Len()>0` was just proven and `len(result)>=2`, so `Coarse` always finds a contributor and emits exactly one range. | `TestJSONStringUsesExactRepeatedLiteral` | none; document the invariant |

### `propagation.go` - 46 blocks, 47 statements

| Loc | n | Class | Scenario / invariant | Existing test or seam | Planned smallest test |
| --- | ---: | --- | --- | --- | --- |
| 43.41-45.3 | 1 | R | `stringAlias` with an empty input or empty result, e.g. `strings.Replace("ab","ab","",-1)` reaching `CoarseString`/`JoinString`/`ReplaceString` with an empty operand. | `TestPropagationGuardAndRejectionPaths` passes `""` to `StringWindow`, which returns earlier | `propagation_test.go` `TestEmptyOperandsAreRejected` |
| 72.9-74.3 | 1 | U | `StringKey` fails in `deriveStringWindow`. `StringKey` fails only for an empty or >4 GiB value, and every caller (`copyStringHit`, `caseStringHit`, `stringWindowHit`, `stringWindowsHit`, `coarseStringAlias`, `repeatStringHit`) proves `len(result)>0` first. | n/a | none; document the caller contract |
| 77.10-78.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 81.10-82.12 | 1 | DN | `entry.Handle` fails for every entry in `deriveStringWindow`. Deterministic only in-package: `store.Lookup` into a `Snapshot`, `owner.Finish()`, then call the helper with the stale snapshot. | finish-race stress only | NEW `stale_owner_internal_test.go` (`package propagation`) `TestPublishHelpersDropStaleOwners` |
| 91.9-93.3 | 1 | U | `BytesKey` fails in `deriveBytesWindow`; all callers prove `len(result)>0`. | n/a | none; document the caller contract |
| 96.10-97.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 100.10-101.12 | 1 | DN | `entry.Handle` fails in `deriveBytesWindow`; same stale-snapshot seam. | finish-race stress only | NEW `stale_owner_internal_test.go` |
| 129.54-131.3 | 1 | D | `adoptStringCopyHit`: `Lookup` false or `Len()==0`; `Len()==0` deterministic via N6. | `TestPropagationGuardAndRejectionPaths` uses live owners only | `propagation_test.go` `TestFinishedOwnerStaleSlotIsDropped` |
| 167.21-169.3 | 1 | R | `copyStringHit` non-alias result under 2 bytes. A one-byte **window** of a tainted root is tracked (one-byte roots are not), so `CopyString(oneByteWindow, freshOneByte)` reaches this guard after `recordExecuted`. | `TestOneByteWindowDerivesButOneByteRootIsRejected` uses a 2-byte input, so `CopyString` returns at the length guard instead | extend that test with a tracked one-byte input |
| 180.10-181.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 184.10-185.12 | 1 | DN | `publishStringCopy`: `entry.Handle` fails; stale-snapshot seam (helper takes the snapshot as a parameter). | finish-race stress only | NEW `stale_owner_internal_test.go` |
| 188.108-189.12 | 1 | U | `ranges.Slice` invalid: window `[0,len(clone)]` of a source `ValidFor inputLen == len(clone)`; N2. | n/a | none; document N2 |
| 202.31-204.3 | 1 | R | `StringWindow` with an aliasing output but an unkeyable or untainted input. | `TestPropagationGuardAndRejectionPaths` calls `StringWindow(managed,"")`, which returns at the earlier guard | extend `TestUntaintedPathIsAllocationFree` with `StringWindow` |
| 244.32-245.9 | 1 | R | `outputIndex >= maxWindows` break: >32 outputs of which fewer than 32 publish (e.g. 40 outputs, every other one empty), so the `published >= maxWindows` break does not preempt it. | `TestStringWindowsPublishesAtMost32NonEmptyWindows` uses 33 publishable windows and exits on the published bound | extend that test with a sparse output slice |
| 280.54-282.3 | 1 | D | `repeatStringHit`: `Lookup` false or `Len()==0`; N6. | `TestRepeatStringCountOneDerivesAndCountNClones` | `TestFinishedOwnerStaleSlotIsDropped` |
| 302.10-303.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 306.10-307.12 | 1 | DN | `publishStringRepeat`: `entry.Handle` fails; stale-snapshot seam. | finish-race stress only | NEW `stale_owner_internal_test.go` |
| 310.93-311.12 | 1 | DA | `ranges.Repeat` invalid: `RepeatString(managed, nonAliasResult, -1)`. No native call site produces a negative count (`strings.Repeat` panics first), so this is an engine-API defensive guard. | `propagation_test.go:378` already does exactly this for the `RepeatBytes` twin | none; outside native caller contract |
| 313.46-314.12 | 1 | DA | `Repeat` valid but the set exceeds the clone: e.g. `RepeatString(fiveByteManaged, fourByteFresh, 3)` builds a 15-byte set over a 4-byte clone. Requires a count/result pair no native caller produces. | no equivalent; the byte twin at 590.47 is also uncovered | none; outside native caller contract |
| 377.32-378.12 | 1 | X | `coarseStringHit`: `s.Lookup` false; N5. | `TestCoarseStringPreservesEachOwnerSourceAndMarks` | none forceable; residual |
| 382.11-383.13 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 387.34-388.14 | 1 | R | `ownerCount >= MaxSnapshotOwners` for `CoarseString`; N9. | `TestCoarseStringPreservesEachOwnerSourceAndMarks` uses two owners | `propagation_test.go` `TestOwnerFanoutBeyondSnapshotBound` |
| 405.15-406.12 | 1 | R | `!o.found`: an owner recorded from a value whose window carries no ranges, so `coarseAccumulate` never set `found`; N7. | `TestCoarseOperationsIntersectSecureMarksPerOwner` | `range_behavior_test.go` `TestCleanWindowOfTaintedRootPublishesNothing` |
| 409.10-410.12 | 1 | X | `o.entry.Handle` fails between `coarseStringHit`'s inline `Lookup` and publication. | finish-race stress | none forceable; residual |
| 415.104-416.12 | 1 | U | Coarse `AdoptCanonical` invalid; N10. | n/a | none; document N10 |
| 437.31-439.3 | 1 | R | `CopyBytes` with an unkeyable or untainted input. | `TestUntaintedPathIsAllocationFree` and `TestByteExactOpsNoActiveAndUntaintedAreAllocationFree` both omit `CopyBytes` | extend `TestUntaintedPathIsAllocationFree` with `CopyBytes` |
| 446.54-448.3 | 1 | D | `copyBytesHit`: `Lookup` false or `Len()==0`; N6. | `TestCopyBytesDerivesAliasAndAdoptsNonAlias` | `TestFinishedOwnerStaleSlotIsDropped` |
| 464.10-465.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 468.10-469.12 | 1 | DN | `publishBytesCopy`: `entry.Handle` fails; stale-snapshot seam. | finish-race stress only | NEW `stale_owner_internal_test.go` |
| 472.109-473.12 | 1 | U | `ranges.Slice` invalid; N2. | n/a | none; document N2 |
| 505.14-507.3 | 1 | R | `ByteWindows` with no active analysis scope. | `TestNoActiveStoreIsNoOpAndAllocationFree` omits `ByteWindows` | extend that test |
| 509.31-511.3 | 1 | R | `ByteWindows` with an unkeyable or untainted input. | `TestUntaintedPathIsAllocationFree` omits `ByteWindows` | extend that test |
| 518.54-520.3 | 1 | D | `byteWindowsHit`: `Lookup` false or `Len()==0`; N6. | `TestSplitEmptyAndSingleByteWindowsPreserveProvenance` | `TestFinishedOwnerStaleSlotIsDropped` |
| 527.32-528.9 | 1 | R | `outputIndex >= maxWindows` break for byte windows: >32 outputs, fewer than 32 publishable. | `TestWindowFanoutClipsRangesAndDropsExcessSafely` | extend that test with a sparse output slice |
| 561.54-563.3 | 1 | D | `repeatBytesHit`: `Lookup` false or `Len()==0`; N6. | `TestRepeatBytesAdoptsCountOneAndCountNResults` | `TestFinishedOwnerStaleSlotIsDropped` |
| 565.31-568.3 | 2 | R | `bytesAlias(input,result)` derive path. The `RepeatBytes` doc comment documents it, but `bytes.Repeat` in the pinned toolchain always allocates (verified on this host: `bytes.Repeat(b,1)` does not alias, while `strings.Repeat(s,1)` does), so no native caller produces it. Only a direct `RepeatBytes(managed, managed, 1)` call reaches it. | `TestRepeatBytesAdoptsCountOneAndCountNResults` asserts the non-alias native behaviour instead, with an explicit Go 1.26.6 comment | direct-call extension testing the documented count-one alias contract; do not call this native bytes.Repeat evidence |
| 579.10-580.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 583.10-584.12 | 1 | DN | `publishBytesRepeat`: `entry.Handle` fails; stale-snapshot seam. | finish-race stress only | NEW `stale_owner_internal_test.go` |
| 590.47-591.12 | 1 | DA | `Repeat` valid but the set exceeds `cap(result)`: e.g. `RepeatBytes(fiveByteManaged, resultWithCap4, 3)`. Not a native pairing. | `propagation_test.go:378` covers the invalid-`Repeat` twin, not this one | none; outside native caller contract |
| 655.32-656.12 | 1 | X | `coarseBytesHit`: `s.Lookup` false; N5. | `TestCoarseByteAliasesKeepExactWindows` | none forceable; residual |
| 660.11-661.13 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 665.34-666.14 | 1 | R | `ownerCount >= MaxSnapshotOwners` for `CoarseBytes`; N9. | `TestCoarseOperationsIntersectSecureMarksPerOwner` | `bytes_exact_test.go` `TestOwnerFanoutBeyondSnapshotBound` |
| 682.15-683.12 | 1 | R | `!o.found` for `CoarseBytes`; N7. | `TestCoarseOperationsIntersectSecureMarksPerOwner` | `TestCleanWindowOfTaintedRootPublishesNothing` |
| 686.10-687.12 | 1 | X | `o.entry.Handle` fails between `coarseBytesHit`'s inline `Lookup` and publication. | finish-race stress | none forceable; residual |
| 692.105-693.12 | 1 | U | Coarse byte `AdoptCanonical` invalid; N10 with `Length == len(result) <= cap(result)`. | n/a | none; document N10 |
| 724.10-725.12 | 1 | U | `set.At` `!ok` in `coarseAccumulate`; N1. | n/a | none |

### `string_coarse.go` - 14 blocks, 15 statements

| Loc | n | Class | Scenario / invariant | Existing test or seam | Planned smallest test |
| --- | ---: | --- | --- | --- | --- |
| 21.58-23.3 | 1 | R | `CaseString` with an empty or oversized result, e.g. `strings.ToUpper("")`. | `TestCaseStringUsesExactASCIIAndCoarseUnicodeRanges` | `propagation_test.go` `TestEmptyAndOversizedResultsAreRejected` |
| 25.14-27.3 | 1 | R | `CaseString` with no active analysis scope. | `TestNoActiveStoreIsNoOpAndAllocationFree` omits `CaseString` | extend that test |
| 29.31-31.3 | 1 | R | `CaseString` with an unkeyable or untainted input. | `TestUntaintedPathIsAllocationFree` omits `CaseString` | extend that test |
| 38.54-40.3 | 1 | D | `caseStringHit`: `Lookup` false or `Len()==0`; N6. | `TestCaseStringUsesExactASCIIAndCoarseUnicodeRanges` | `TestFinishedOwnerStaleSlotIsDropped` |
| 42.32-45.3 | 2 | R | `stringAlias(input,result)` derive path: `strings.ToUpper`/`ToLower` return the input itself when nothing changes (verified on this host for ASCII and non-ASCII), so an already-upper tainted value derives. | `TestCaseBytesDerivesAliasWithoutReplacement` covers the byte twin only | `propagation_test.go` `TestCaseStringDerivesUnchangedAlias` |
| 46.21-48.3 | 1 | R | Non-alias result under 2 bytes: `strings.ToLower("\u212a")` is `"k"` (3 bytes -> 1 byte, verified non-alias), so a tainted Kelvin-sign root reaches this guard after `recordExecuted`. | none | `propagation_test.go` `TestShrinkingCaseTransformRejectsOneByteResult` |
| 56.10-57.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 68.45-69.12 | 1 | R | `Copy`/`Coarse` invalid or `resultSet.Len()==0`: clean window into a case transform; N7. | `TestCaseStringUsesExactASCIIAndCoarseUnicodeRanges` | `TestCleanWindowOfTaintedRootPublishesNothing` |
| 104.57-106.3 | 1 | R | `CoarseFormattedString` with `len(result)<2` or `>MaxRootBytes`, e.g. `fmt.Sprintf("%s","")`. | `range_behavior_test.go:84` uses a long result | `range_behavior_test.go` `TestEmptyAndOversizedResultsAreRejected` |
| 153.31-155.3 | 1 | X | `accumulateCoarseKey`: `s.Lookup` false; N5. No `Len()==0` companion, so the N6 seam falls through the empty loop instead. | none | none forceable; residual |
| 158.10-159.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |
| 163.33-164.13 | 1 | R | `ownerCount >= MaxSnapshotOwners` in the format path; N9 (format string plus arguments). | `TestCoarseOperationsIntersectSecureMarksPerOwner` | `range_behavior_test.go` `TestOwnerFanoutBeyondSnapshotBound` |
| 184.19-185.12 | 1 | R | `!state.found`: an owner accumulated from a clean window among the format arguments; N7. | `TestCoarseFormatSupportsDefinedStringsAndBytes` | `TestCleanWindowOfTaintedRootPublishesNothing` |
| 188.10-189.12 | 1 | DN | `state.entry.Handle` fails. `publishCoarseOwners` is a separate unexported function taking the owners array, so an in-package test can build it from a real `store.Entry`, finish the owner, then call it. | finish-race stress only | NEW `stale_owner_internal_test.go` `TestPublishCoarseOwnersDropsStaleOwner` |

### `string_exact.go` - 18 blocks, 23 statements

| Loc | n | Class | Scenario / invariant | Existing test or seam | Planned smallest test |
| --- | ---: | --- | --- | --- | --- |
| 22.58-24.3 | 1 | R | `JoinString` with an empty or oversized result, e.g. `strings.Join([]string{"",""},"")`. | `TestJoinStringPreservesElementAndSeparatorRanges` | `TestEmptyAndOversizedResultsAreRejected` |
| 60.40-62.3 | 1 | R | `ownerCount==0` or `len(result)<2` in `joinStringHit`. Ordinary: joining a tracked one-byte window with an empty element yields a fresh one-byte result (verified non-alias), so the owner is found and the result is rejected. | `TestJoinAndReplaceActiveUntaintedAreAllocationFree` exits before the hit | `propagation_test.go` `TestOneByteJoinAndReplaceResultsAreRejected` |
| 83.22-85.10 | 2 | U | `ranges.Concat` invalid for an element; N2. | `TestJoinStringPreservesElementAndSeparatorRanges` | none; document N2 |
| 91.23-93.11 | 2 | U | Same for the separator leg; N2. | `TestJoinStringCoarseFallbackIncludesSeparator` | none; document N2 |
| 99.71-100.12 | 1 | R | `!valid`, `currentLen != len(clone)`, or `current.Len()==0`: clean-window elements; N7. | `TestJoinStringPreservesElementAndSeparatorRanges` | `TestCleanWindowOfTaintedRootPublishesNothing` |
| 114.58-116.3 | 1 | R | `ReplaceString` with an empty or oversized result, e.g. `strings.Replace("ab","ab","",-1)`. | `TestReplaceStringMapsCopiedAndReplacementSegments` | `TestEmptyAndOversizedResultsAreRejected` |
| 117.32-120.3 | 2 | R | `stringAlias(input,result)` derive path: `strings.Replace` returns the input itself when there is no match (verified), so `ReplaceString(managed,"zz","y",result,-1)` derives the window. | `TestReplaceStringMapsCopiedAndReplacementSegments` always replaces something | `propagation_test.go` `TestReplaceStringNoMatchDerivesAlias` |
| 138.40-140.3 | 1 | R | `ownerCount==0` or `len(result)<2` in `replaceStringHit`: `strings.Replace("ab","b","",-1)` yields a fresh one-byte result from a tainted input. | `TestJoinAndReplaceActiveUntaintedAreAllocationFree` exits before the hit | `TestOneByteJoinAndReplaceResultsAreRejected` |
| 141.45-144.3 | 2 | I | `len(input) > MaxUint32` coarse fallback; >4 GiB input string. | none | none; document the bound |
| 175.34-176.12 | 1 | U | `total != len(clone)`; N3. | `TestReplaceStringMapsCopiedAndReplacementSegments` | none; document N3 |
| 180.88-181.12 | 1 | R | `Compose` invalid, not `ValidFor`, or `Len()==0`: input and replacement both clean windows; N7. | `TestReplaceStringMapsCopiedAndReplacementSegments` | `TestCleanWindowOfTaintedRootPublishesNothing` |
| 193.16-196.3 | 2 | U | `mapReplaceSegments` `count==0`. `strings.Replace(s,old,new,0)` returns `s` (verified), so `ReplaceString` takes the `stringAlias` fast path at 117 and never reaches the hit. The byte twin (`bytes_exact.go:190`) **is** covered because `bytes.Replace` always copies. | `TestReplaceBytesMapsCopiedAndReplacementSegments` covers the byte twin | none proposed; document the string/byte asymmetry rather than fabricating a call |
| 205.36-207.5 | 1 | R | Empty `old` with more than 32 matches: `strings.ReplaceAll` over a 40-rune string with `old==""` yields 41 matches and must fall back to coarse. | `TestReplaceStringHandlesEmptyPatternAndCoarseLimit` uses a 2-rune input, so it only covers the non-empty-`old` overflow at 228 | extend that test with a >32-rune empty-`old` case |
| 217.18-219.5 | 1 | U | `utf8.DecodeRuneInString` width 0; N8. | `TestReplaceStringHandlesEmptyPatternAndCoarseLimit` | none; document N8 |
| 251.32-252.12 | 1 | X | `collectStringOwners`: `s.Lookup` false; N5. | finish-race stress | none forceable; residual |
| 259.33-260.13 | 1 | R | `ownerCount >= MaxSnapshotOwners`; N9 across Join/Replace inputs. | `TestJoinBytesTwoOwnersKeepLocalSourceIDs` covers the byte twin with two owners | `propagation_test.go` `TestOwnerFanoutBeyondSnapshotBound` |
| 301.31-303.3 | 1 | X | `stringOwnerRanges`: `s.Lookup` false; N5. | finish-race stress | none forceable; residual |
| 306.10-307.12 | 1 | U | `snapshot.At` `!ok`; N1. | n/a | none |

### `writer.go` - 16 blocks, 19 statements

Every `iast/propagation/writer.go` wrapper gates on `internal.WriterActive()`
before calling the engine, so all seven `s == nil` blocks below are reachable only
through a direct engine call with no active scope. That is an ordinary engine-API
scenario (the engine is an internal package with its own contract), not a
fabricated value.

| Loc | n | Class | Scenario / invariant | Existing test or seam | Planned smallest test |
| --- | ---: | --- | --- | --- | --- |
| 43.14-45.3 | 1 | R | `PrepareBufferWriter` with no active scope. | `iast/propagation/writer_inactive_test.go` tests the wrapper gate, not this branch | `writer_behavior_test.go` `TestWriterEngineNoActiveStoreIsNoOp` |
| 57.100-60.3 | 2 | I | A native string write above `MaxUint32` reaches the reset path on 64-bit systems. A negative count is non-native, but the size disjunct is real. | wrappers call `UpdateStringWriter` after the native write, even when writer capacity exceeds the tracking bound | no >4 GiB allocation; document the resource-budget exclusion |
| 62.14-64.3 | 1 | R | `UpdateStringWriter` with no active scope. | wrapper gate only | `TestWriterEngineNoActiveStoreIsNoOp` |
| 71.100-74.3 | 2 | I | Same native >4 GiB size disjunct for `UpdateBytesWriter`. | `BuilderWrite` and `BufferWrite` pass the actual native count | no >4 GiB allocation; document the resource-budget exclusion |
| 76.14-78.3 | 1 | R | `UpdateBytesWriter` with no active scope. | wrapper gate only | `TestWriterEngineNoActiveStoreIsNoOp` |
| 85.57-88.3 | 2 | DA | `UpdateUntaintedWriter` receives only 0 for Grow, 1 for WriteByte, or 1-4 for WriteRune from native callers; neither disjunct can occur. | native wrappers bound the count | none; outside native caller contract |
| 90.14-92.3 | 1 | R | `UpdateUntaintedWriter` with no active scope. | wrapper gate only | `TestWriterEngineNoActiveStoreIsNoOp` |
| 111.10-112.12 | 1 | X | `ref.Handle` fails after `store.LookupWriterValue` captured the ref: the owner must die in between. `updateWriter` performs that lookup inline and takes no refs parameter, so **no seam exists even in-package**. | `TestWriterResultsPreserveContributorsMarksAndNativeIdentity` | none forceable; residual (would need a store-level seam, out of scope) |
| 115.10-116.12 | 1 | X | `ref.Identity` fails immediately after `ref.Handle` succeeded - two adjacent calls on the same ref, the tightest window in the engine. | none | none forceable; residual |
| 129.10-130.12 | 1 | X | `entry.Handle` fails for an input-snapshot owner that was not already seen as a writer owner. | `TestWriterResultsPreserveContributorsMarksAndNativeIdentity` | none forceable; residual |
| 163.14-165.3 | 1 | R | `ResetWriter` with no active scope. | wrapper gate only | `TestWriterEngineNoActiveStoreIsNoOp` |
| 178.14-180.3 | 1 | R | `TruncateWriter` with no active scope. | `TestWriterTruncateResetAndAnchoredCopyLifetime` | `TestWriterEngineNoActiveStoreIsNoOp` |
| 192.57-194.3 | 1 | R | `BuilderString` with `len(result)<2` or `>MaxRootBytes` - an active scope plus a one-byte builder result. (The `BufferString` twin at 204 is already covered.) | `writer_behavior_test.go:90` builds a longer string | `writer_behavior_test.go` `TestOneByteWriterResultsAreRejected` |
| 196.14-198.3 | 1 | R | `BuilderString` with no active scope. | wrapper gate only | `TestWriterEngineNoActiveStoreIsNoOp` |
| 208.14-210.3 | 1 | R | `BufferString` with no active scope. | wrapper gate only | `TestWriterEngineNoActiveStoreIsNoOp` |
| 228.10-229.12 | 1 | X | `refs[index].Handle` fails inside `publishWriterString`, which performs `LookupWriterValue` itself. | `TestWriterResultsPreserveContributorsMarksAndNativeIdentity` | none forceable; residual |

## Seam availability, stated explicitly

Confirmed against the source: **no existing propagation seam can pause a lookup
or a publication, and none can hold or fail the store lifecycle lock from this
package.** `store.forceCollision` and `store.forceWriterLockFail`
(`internal/taint/store/value.go:10-11`) are unexported and usable only by
`package store`'s own tests. Therefore:

1. **Seam present today (D, 8 statements).** The finished-owner stale slot (N6) is
   the only deterministic engine failure seam reachable from the existing external
   test package. It works because `Finish` leaves the shard slot while
   `MayContain` does no owner validation. It reaches exactly the guards written as
   `!Lookup(...) || snapshot.Len() == 0` (and the `ownerCount == 0` guards), never
   the bare `!Lookup(...)` guards.
2. **Seam absent from the exported API but constructible in-package (DN, 7
   statements).** Only for publish helpers that accept an already-populated
   `*store.Snapshot` or owners array: `deriveStringWindow`, `deriveBytesWindow`,
   `publishStringCopy`, `publishStringRepeat`, `publishBytesCopy`,
   `publishBytesRepeat`, `publishCoarseOwners`. A new in-package file can look up
   a real snapshot, finish the owner, and then call the helper. No pausing and no
   production hook are involved. One build prerequisite: Orchestrion's
   coverage-instrumented for-test variant linkage for an in-package test file in
   this directory is **unverified** (the existing five test files are all
   `package propagation_test`; `internal/taint/store` uses 17 in-package files, so
   the pattern is established elsewhere in the tree but not here).
3. **Seam absent entirely (X, 17 statements).** Every block where the failing
   `Lookup`/`Handle`/`Identity` call sits inline in the same function as the state
   it depends on: `joinBytesHit`, `replaceBytesHit`, `caseBytesHit`,
   `collectBytesOwners`, `bytesOwnerRanges`, `collectStringOwners`,
   `stringOwnerRanges`, `coarseStringHit`, `coarseBytesHit`,
   `accumulateCoarseKey`, `BytesToString`, `updateWriter`, `publishWriterString`.
   These are **reachable** - they are the documented contention and stale-owner
   drops - but no current seam can order them. Stress tests do not prove a
   specific interleaving and must not be presented as doing so.
4. **Aggregate coverage does not prove a deterministic order.** The existing
   `TestByteExactOpsFinishRaceIsSafe` can exercise some stale-owner guards, but
   the merged profile does not identify which test or interleaving hit a block.
   Add the N6 cases even for covered twins. Keep stress tests as safety evidence,
   not proof that any particular lookup/finish/publication order occurred.

## Bounded engine sequence oracle

Use the existing cell-vector approach from `internal/taint/ranges/property_test.go`
for exact operations. Re-declare only the small cell type and folding helper in
`internal/taint/propagation/oracle_sequence_test.go`; test packages cannot import
each other's unexported helpers. Do not add a shared production helper package.

Keep one byte/source/mark vector per value and owner, because local source IDs
can overlap across owners. Generate at most eight exact operations on two owners,
256 input bytes, and 4 KiB of output, with 2,000 fixed-seed sequences and the
separate finite fuzz campaigns defined in the main plan. Reuse existing scope,
owner, and snapshot helpers. Assert native value equality and source/mark cells
after each step, including alias identity where the contract promises it.

Start with copy, slice, concat/join, repeat, and byte-to-string conversion. Add
replacement and UTF-8 mapping only with an independent cell transform, not a
copy of production segmentation code. If a generated operation would cross the
exact/coarse boundary, terminate that exact sequence before the transition.
Cover every such boundary with the named coarse/drop fixtures instead; do not
silently skip it from the scenario matrix. Those fixtures assert exact expected
source selection and mark intersection, not just a subset of input sources.

Lifecycle fuzzing uses a separate `FuzzOwnerLifecycle` target with bounded,
sequential begin/derive/publish/finish/reuse operations and explicit checks for
cleanup and stale-handle rejection. It does not claim to force concurrency.
Use `FuzzEngineSequence` for exact value/provenance sequences. Keep writer
anchoring, allocation counts, and the X-class interleavings in their named tests.

## Key actionable cases

1. **One test extension closes ~12 statements.** Every engine entry point missing
   from `TestNoActiveStoreIsNoOpAndAllocationFree` and
   `TestUntaintedPathIsAllocationFree` - `BytesToString`, `CaseString`,
   `JSONString`, `CopyBytes`, `ByteWindows`, `StringWindow`, `ValidUTF8Bytes`, and
   the seven writer entry points - accounts for the largest single cluster.
2. **One deterministic N6 test replaces nondeterministic stress coverage** for
   `conversion`/`json`/`string_coarse`/`propagation`/`bytes_exact` `Len()==0`
   guards (8 statements), and removes the current dependence on
   `TestByteExactOpsFinishRaceIsSafe` happening to win a race.
3. **Clean window of a tainted root (N7)** is the single highest-leverage new
   fixture: it closes 8 reachable blocks across five files that otherwise look
   like dead defensive code.
4. **Owner fanout beyond 4 (N9)** needs 5+ owners across two inputs and closes 4
   blocks; today the strongest test uses two owners.
5. **Three genuine gaps in ordinary native behaviour** that current tests miss
   entirely: `CaseString` deriving an unchanged alias (`strings.ToUpper` returns
   the input), `ReplaceString` deriving on no match, and the empty-`old`
   >32-match coarse fallback. Each is a real provenance path, not a guard.
6. **One-byte and shrinking results**: a tracked one-byte window copied to a fresh
   one-byte result, `strings.ToLower("\u212a") == "k"`, and one-byte join/replace
   and builder results close 5 blocks and pin the "window is tracked, root is not"
   contract.
7. **Residual set to publish, not hide**: 17 X-class statements (reachable,
   unforceable), 10 I-class statements (>4 GiB), 42 U-class statements
   (invariant-protected). The U set is documented in this table
   (notes N1-N4, N8, N10); no production comment changes are required.

## Resolved testability decisions proposed for approval

1. Include the seven DN statements through one new in-package test file that
   passes real snapshots to existing private helpers after finish/reuse. No
   production hook or exported symbol is needed. Verify the ordinary and woven
   coverage builds with that file before adding the remaining cases. If linking
   fails, report the concrete conflict rather than exporting test access.
2. Do not add DA cases with negative native counts or mismatched native results.
   Preserve the existing defensive tests without treating them as native proof.
   The documented count-one alias contract of `RepeatBytes` is different: test
   that valid internal-engine contract directly, with equal input/output bytes,
   and label it as engine-only evidence. Leave the production comment intact.
3. Retain the zero-count string replacement guard as a documented native-
   unreachable branch. No production cleanup or guard-comment edits are needed.
4. Accept X (17 statements) as explicitly tracked race-dependent residuals with
   lower-level deterministic tests and engine stress evidence, not forced block
   execution. Accept I (10 statements) as a test-resource exclusion for >4 GiB
   values. Both decisions require approval of the revised main plan.
5. Keep the oracle's small cell folder local to the test package. Do not add a
   generic framework, shared production utility, or a duplicate coarse engine.
6. The audit observed possible rangeless publication in `BytesToString`. It is
   not a demonstrated provenance defect. Do not change production code for it
   in this testing task; a new test may expose a material failure independently.

## Method and limits of this audit

- Classification used the exact uploaded profile plus the current source of
  `internal/taint/propagation`, `internal/taint/store`
  (`lookup.go`, `value.go`, `owner.go`, `root.go`, `store.go`, `writer.go`,
  `limits.go`), `internal/taint/ranges` (`ranges.go`, `operations.go`), the
  `iast/propagation` wrappers, and all five existing propagation test files.
- The stdlib aliasing and length facts used above were verified by a throwaway
  program under `/tmp/probe-stdlib` (outside the repository): `ToUpper`/`ToLower`
  alias when unchanged; `strings.Replace` aliases on no match and on `n==0`;
  `strings.Repeat(s,1)` aliases but `bytes.Repeat(b,1)` does not;
  `strings.Join` aliases a lone element but not when empty elements are present;
  `bytes.Join` never aliases; `strings.ToLower("\u212a") == "k"`. That probe ran
  first on the host toolchain (go1.27.1). The driver re-ran it on pinned
  Go 1.26.6 with exit code 0 and confirmed every alias/length result above.
  Tests must assert alias identity rather than silently skip changed behavior.
- No test was written or executed for this audit; the saved profile was readable
  and self-consistent, so no re-run was needed. No production or test code was
  added, and no repository file was modified.

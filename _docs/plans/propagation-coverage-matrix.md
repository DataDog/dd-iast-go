# Phase 1 operation-to-test matrix - dd-iast-go propagation

Source audit of code at `3168522002ee7e5eee83338e6c991c659415b6a7`. The driver
verified counts and key mappings before saving this report in the separate
planning change requested by the user. No test or production code changed.
This matrix records source-level evidence; current validation is recorded in
[propagation-coverage-review.md](propagation-coverage-review.md).

The [engine path table](propagation-coverage-paths.md) classifies uncovered
blocks separately. External System Tests are outside the user's requested scope.

## 1. Sources of truth used

| Artifact | Role |
| --- | --- |
| `README.md:26-77` | Advertised propagation contract: coverage table `:28-36`, direct-call and exclusion notes `:38-51`, buffer-copy rules `:53-59`, JSON rules `:61-68`, writer limits `:70-77` |
| `iast/propagation/orchestrion.yml` (1680 lines, 125 aspects) | Named + operator + writer advice |
| `iast/encoding/json/orchestrion.yml` (6 aspects) | JSON bootstrap + 5 `encoding/json` hooks |
| `iast/io/orchestrion.yml` (4 aspects) | Reader composition + `io.ReadAll` |
| `iast/bufio/orchestrion.yml` (1 aspect) | `bufio.NewReaderSize` (covers `NewReader` by delegation) |
| `iast/net/url/orchestrion.yml` (1 aspect) | `net/url.URL.Query` - *lazy source*, not a propagation op (see section 8) |
| `AGENTS.md`, `CONTRIBUTING.md` | Operating constraints, `built.WithOrchestrion` skip rule, external-test-package rule |

### Aspect counts (mechanically extracted, not estimated)

| File | Aspects | Notes |
| --- | ---: | --- |
| `iast/propagation/orchestrion.yml` | **125** | 15 concat + 1 bytes-to-string + 2 slice + 72 named funcs + 30 writer method forms + 2 Replacer forms + 3 invalidation bodies = 125 |
| `iast/encoding/json/orchestrion.yml` | 6 | 1 bootstrap + 5 `encoding/json` function bodies |
| `iast/io/orchestrion.yml` | 4 | |
| `iast/bufio/orchestrion.yml` | 1 | |
| `iast/net/url/orchestrion.yml` | 1 | source, not propagation |
| **Total in scope** | **137** | of which 136 are propagation (url `Query` excluded) |

`iast/propagation/telemetry.go:12` hardcodes `instrumentedPropagationPoints = 125`
and `iast/propagation/strings_test.go:25` (`TestInstrumentedPropagationTelemetry`)
asserts `strings.Count(orchestrion.yml, "\n  - id:") == telemetry.InstrumentedPropagation`.
This is an existing **enumeration guard**: adding an aspect without updating the
constant fails. `iast/encoding/json/json_test.go:32` does the same for the 5
`- import-path: encoding/json` aspects. **No equivalent guard exists for
`iast/io` (4), `iast/bufio` (1), or `iast/net/url` (1)** - those packages register
no telemetry counter at all (`iast/io/io.go` and `iast/net/url/url.go` are
doc-only files; `iast/bufio/bufio.go:21` has no `init`).

## 2. Strength legend (used in every table)

| Code | Meaning |
| --- | --- |
| **N** | *Native injection*: the native syntax/call appears in an injected root-module package (`iast/internal/propagationtest`, or a `*_test` external package under `iast/...`) and is exercised from a test that skips unless `built.WithOrchestrion`. Proves Orchestrion rewrote the call. |
| **W** | *Direct wrapper call*: `iastpropagation.X(...)` called explicitly. Proves wrapper logic, **not** injection. |
| **E** | *Engine primitive*: `internal/taint/propagation` exported primitive tested directly. Proves range math, **not** wrapper or injection. |

Assertion depth codes:

| Code | Meaning |
| --- | --- |
| **A3** | source identity **and** offsets/lengths **and** marks asserted |
| **A2** | offsets/lengths + source origin/name asserted, marks not asserted |
| **A1** | taint presence only (`IsTaintedString` / `IsTaintedBytes`) |
| **A0** | value/error/panic parity only (negative or host-behavior control) |

Shared helpers, referenced by every row below:

| Helper | Location | What it asserts |
| --- | --- | --- |
| `requireTaintedStrings` | `iast/propagation/strings_test.go:55-72` | exactly 1 range, `Start==0`, `Length==len(value)`, `Origin==OriginHttpRequestParameter`, `Name=="input"`. **No** `Source.Value`, **no** `Marks`. -> **A2** |
| `requireTaintedBytes` | `iast/propagation/bytes_test.go:40-56` | exactly 1 range, `Start==0`, full length, `Origin==OriginHttpRequestBody`. **No** name/value/marks. -> **A2** |
| `requireAnyTaintedBytes` | `iast/propagation/bytes_test.go:58-63` | `IsTaintedBytes` only -> **A1** |
| `requireBufferSource` | `iast/propagation/writer_test.go:39-51` | 1 range, exact `Start`/`Length`, full `SourceValue{Origin,Name,Value}`, `Marks{}` -> **A3** |
| `requireWriterRange` | `iast/propagation/writer_test.go:72-82` | 1 range, exact `Start`/`Length` only -> **A2** (no source, no marks) |

**Important nuance on A2 for the window and coarse families.** In
`TestStringWindowOperations` and `TestByteWindowOperations` the input is tainted
over its *entire* length, and every asserted result is also tainted over its
entire length. A regression that shifts an offset inside a *partially* tainted
input, or that swaps which contributor wins, cannot be detected by these tests.
They do not catch a whole-result taint regression: the fixtures expect
whole-result taint already. This is the concrete substance of the
plan's "some native-call assertions are too weak" finding at
`iast/propagation/strings_test.go:116` and `bytes_test.go:108`.

## 3. Operator family (18 aspects)

Every aspect is enumerated; grouped rows are never collapsed.

### 3.1 `operator string concat 2` ... `operator string concat 16` (15 aspects)

Wrapper: `iast/propagation/operators.go:18-195` (`Concat2`..`Concat16`, each
`[T ~string]`, gated by `operatorbridge.HasValues()`).
Engine: `internal/taint/propagation/operator_concat.go:9-79` -> `JoinString(elements, "", result)`.
Contract: **exact** (`JoinString` maps each operand exactly; `maxInputs = 16` at
`internal/taint/propagation/propagation.go:37`).

| Aspect | Wrapper test (W) | Native test (N) | Strength | Depth |
| --- | --- | --- | --- | --- |
| concat 2 | `operators_test.go:34` via `TestOperatorWrappersPropagateAllAritiesAndSlices:91` (+ inactive `:64`) | `operators_test.go:175` `genericConcat` in `TestOperatorConcatAndSlices:137`; `:153` `source + ""` checks alias identity but does not by itself prove injection | **N+W** | N: A1 + value + alias identity via `unsafe.StringData`; W: A1 |
| concat 3 | `operators_test.go:35` | `operators_test.go:149` `"before:" + source + ":after"` in `TestOperatorConcatAndSlices:137`; `:252` checks single evaluation and left-to-right order | **N+W** | N: A1 plus value/order assertions; W: A1 |
| concat 4 | `operators_test.go:36` | **none** (only `BenchmarkOperatorConcat4ActiveClean:197`, clean data, no assertion) | **W only** | A1 |
| concat 5 | `operators_test.go:37` | **none** | **W only** | A1 |
| concat 6 | `operators_test.go:38` | **none** | **W only** | A1 |
| concat 7 | `operators_test.go:39` | **none** | **W only** | A1 |
| concat 8 | `operators_test.go:40` | **none** | **W only** | A1 |
| concat 9 | `operators_test.go:41` | **none** | **W only** | A1 |
| concat 10 | `operators_test.go:42` | **none** | **W only** | A1 |
| concat 11 | `operators_test.go:43-45` | **none** | **W only** | A1 |
| concat 12 | `operators_test.go:46-48` | **none** | **W only** | A1 |
| concat 13 | `operators_test.go:49-51` | **none** | **W only** | A1 |
| concat 14 | `operators_test.go:52-54` | **none** | **W only** | A1 |
| concat 15 | `operators_test.go:55-57` | **none** | **W only** | A1 |
| concat 16 | `operators_test.go:58-60` | **none** | **W only** | A1 |

Engine backing for exactness: `TestJoinStringPreservesElementAndSeparatorRanges`
(`internal/taint/propagation/propagation_test.go:503-518`) asserts the exact
4-range layout for a 3-element join with a tainted separator (**E, A2** -
`SourceID`, no marks). `TestExactNativeTransformsPreserveRangesAndMarks`
(`range_behavior_test.go:20-57`) asserts single-element join alias identity plus
marks (**E, A3**).

Missing, by plan dimension:
- **Shape/bounds**: arities 4-16 have no native proof (plan already states this).
- **Shape/bounds**: the **17-operand boundary** (first arity with no matching
  aspect, therefore a drop) has no test in either mode. That is the
  "first excluded input" boundary for this family.
- **Contributors**: no native concat test with two *different* sources or a
  partially tainted operand. The existing three-operand test has clean prefix
  and suffix values, but does not check the exact range between them. W tests
  use one tainted operand plus literal `"x"` padding.
- **Ownership/marks**: no concat test asserts `Marks` at N or W level. Only the
  engine `JoinString` path has an A3 test.
- **Analysis state**: inactive covered (`:64`); active-clean only via a
  benchmark, with no assertion.
- `+=` and compiler-optimized concat contexts (`README.md:43-44`, `:47-49`) have
  **no negative test** in any mode.

### 3.2 `operator bytes to string conversion` (1 aspect)

Wrapper: `iast/propagation/operators.go:198-204` `BytesToString[T ~[]byte]`.
Engine: `internal/taint/propagation/conversion.go:15-51`. Contract: **exact**,
equal-length only, `len>=2`, `<= store.MaxRootBytes`.

| Form | Evidence | Strength | Depth |
| --- | --- | --- | --- |
| plain assignment `string(bytes)` | `operators_test.go:169-171` in `TestOperatorConcatAndSlices:137` | **N** | A1 + value |
| named-type declaration `var x definedString = definedString(bytes)` | `operators_test.go:172-174` | **N** | A1 + value |
| engine exact ranges + marks | `range_behavior_test.go:53-56` (`BytesToString`, asserts `{Start:1,Length:2,SourceID:8,Marks:0xa}` and result identity) | **E** | **A3** |
| direct wrapper call | **none** - no test calls `iastpropagation.BytesToString` | - | - |

Missing: **return-position** conversion (`README.md:31` advertises
"assignments, declarations, and *returns*") has no test. Excluded optimized
contexts (call argument, comparison, map key, range, concatenation) have only
`BenchmarkOperatorOptimizedConversionExcluded:224` - a benchmark, with **no
negative assertion** that taint is absent there.

### 3.3 `operator string slice` (1 aspect, 4 template forms)

Wrappers `iast/propagation/operators.go:207-244`; engine `StringWindow`
(`propagation.go:196`). Contract: **exact** window derive.

| Template form | Wrapper test (W) | Native test (N) | Strength |
| --- | --- | --- | --- |
| `StringSliceAll` (`v[:]`) | `operators_test.go:73` (inactive), `:112` (active, A1) | **none** | **W only** |
| `StringSliceLow` (`v[lo:]`) | `:74`, `:113` | **none** | **W only** |
| `StringSliceHigh` (`v[:hi]`) | `:75`, `:114` | **none** | **W only** |
| `StringSliceBounds` (`v[lo:hi]`) | `:76`, `:115` | `operators_test.go:152` `joined[7:13]`; `:158` `defined[1:5]` named type; `:178` `genericSlice` | **N+W** |

Panic parity for an out-of-range slice: `operators_test.go:255-257` (`value[0:4]`
must still panic) - **N, A0**.

Missing: native `[:]`, `[lo:]`, `[:hi]` forms (3 of 4 template branches never
proven injected). No slice test asserts marks or exact derived offsets at N level
(A1 only); the exact-offset proof lives at engine level
(`propagation_test.go:469-484` `TestPartialSlicedRangesPreservedAndSliced`,
asserting `{Start:2,Length:1,SourceID:1}` for `managed[3:6]`, **E/A2**).

### 3.4 `operator byte slice` (1 aspect, 6 template forms)

Wrappers `operators.go:247-304`; engine `ByteWindow` (`propagation.go:480`).
Contract: **exact** window; the window shares the parent managed root
(`README.md:44-45`).

| Template form | Wrapper test (W) | Native test (N) | Strength |
| --- | --- | --- | --- |
| `BytesSliceAll` (`v[:]`) | `operators_test.go:79`, `:124` | **none** | **W only** |
| `BytesSliceLow` (`v[lo:]`) | `:80`, `:125` | **none** | **W only** |
| `BytesSliceHigh` (`v[:hi]`) | `:81`, `:126` | **none** | **W only** |
| `BytesSliceBounds` (`v[lo:hi]`) | `:82`, `:127` | **none** (only `BenchmarkOperatorSlicesInactive:238`, inactive) | **W only** |
| `BytesSliceFull` (`v[lo:hi:max]`) | `:83-85` (+cap), `:128` | `operators_test.go:164-167` `definedByteValue[1:5:6]`, asserts value, `cap==5`, taint | **N+W** |
| `BytesSliceFullZero` (`v[:hi:max]`) | `:86-88` (+cap), `:129` | **none** | **W only** |

Missing: 5 of 6 native template branches; no N-level A3. The engine window
fanout bound is covered (`range_behavior_test.go:59-71`
`TestWindowFanoutClipsRangesAndDropsExcessSafely`: clipped ranges with marks for
outputs 0 and 1, empty for output 2, `nil` for output 32 - the **32-window bound
boundary**, E/A3).

## 4. Named string operations (33 aspects)

**All 33 have a native call site** in `iast/internal/propagationtest/strings.go`
(an injected root-module package: it sits under `iast/internal/...`, which the
advice excludes only for `github.com/DataDog/dd-iast-go/internal/**`, not
`iast/internal/**`), invoked from tests that skip unless `built.WithOrchestrion`.

### 4.1 Window family - exact, `StringWindow`/`StringWindows`

| Aspect | Wrapper | Helper decl | Native test call | Depth | Contract |
| --- | --- | --- | --- | --- | --- |
| `strings.Clone` | `strings.go:19` `AdoptStringCopy` | `propagationtest/strings.go:17` | `strings_test.go:80,82` in `TestStringWindowOperations:74`; `:314` in `TestIndirectStringCallIsUnsupported:309` | A2 + **1-alloc audit** (`:82-83`) | exact copy |
| `strings.Cut` | `strings.go:25` | `strings.go:18` | `strings_test.go:84-86` | A2 (both halves) + `found` | exact x2 |
| `strings.CutPrefix` | `strings.go:33` | `strings.go:19` | `strings_test.go:87-91` | A2 | exact |
| `strings.CutSuffix` | `strings.go:40` | `strings.go:20` | `strings_test.go:89-91` | A2 | exact |
| `strings.Split` | `strings.go:47` | `strings.go:21` | `strings_test.go:92` | A2 (all parts) | exact, <=32 windows |
| `strings.SplitN` | `strings.go:54` | `strings.go:22` | `strings_test.go:93` | A2 | exact, <=32 |
| `strings.SplitAfter` | `strings.go:61` | `strings.go:25` | `strings_test.go:94` | A2 | exact, <=32 |
| `strings.SplitAfterN` | `strings.go:68` | `strings.go:26` | `strings_test.go:95` | A2 | exact, <=32 |
| `strings.SplitSeq` | `strings.go:75` -> `stringWindowSeq` | `strings.go:29` | `strings_test.go:96` | A2 | exact, **<=32 inspected** |
| `strings.SplitAfterSeq` | `strings.go:80` | `strings.go:32` | `strings_test.go:97` | A2 | exact, <=32 inspected |
| `strings.Lines` | `strings.go:85` | `strings.go:35` | `strings_test.go:98` | A2 | exact, <=32 inspected |
| `strings.Fields` | `strings.go:90` | `strings.go:36` | `strings_test.go:99` | A2 | exact, <=32 |
| `strings.FieldsFunc` | `strings.go:97` | `strings.go:37` | `strings_test.go:100` | A2 | exact, <=32 |
| `strings.FieldsSeq` | `strings.go:104` | `strings.go:40` | `strings_test.go:101` | A2 | exact, <=32 inspected |
| `strings.FieldsFuncSeq` | `strings.go:109` | `strings.go:41` | `strings_test.go:102` | A2 | exact, <=32 inspected |
| `strings.Trim` | `strings.go:158` | `strings.go:58` | `strings_test.go:104` | A2 | exact |
| `strings.TrimSpace` | `strings.go:165` | `strings.go:59` | `strings_test.go:105` | A2 | exact |
| `strings.TrimLeft` | `strings.go:172` | `strings.go:60` | `strings_test.go:106` | A2 | exact |
| `strings.TrimRight` | `strings.go:179` | `strings.go:61` | `strings_test.go:107` | A2 | exact |
| `strings.TrimPrefix` | `strings.go:186` | `strings.go:62` | `strings_test.go:108` | A2 | exact |
| `strings.TrimSuffix` | `strings.go:193` | `strings.go:63` | `strings_test.go:109` | A2 | exact |
| `strings.TrimFunc` | `strings.go:200` | `strings.go:64` | `strings_test.go:110` | A2 | exact |
| `strings.TrimLeftFunc` | `strings.go:207` | `strings.go:67` | `strings_test.go:111` | A2 | exact |
| `strings.TrimRightFunc` | `strings.go:214` | `strings.go:70` | `strings_test.go:112` | A2 | exact |

Engine backing: `TestStringWindowsPublishesAtMost32NonEmptyWindows`
(`propagation_test.go:442-467`) proves exactly 32 published and window 33
untainted; `TestSplitEmptyAndSingleByteWindowsPreserveProvenance`
(`range_behavior_test.go:160-175`) proves an **empty leading part stays
untainted** and a **one-byte part derives**;
`TestOneByteWindowDerivesButOneByteRootIsRejected`
(`propagation_test.go:634-649`) proves the 1-byte window vs 1-byte root asymmetry.

Missing for the whole window family:
- **Contributors**: every native call uses one fully tainted input
  `"  alpha,beta  "`. No native case with a clean prefix/suffix, a **partially**
  tainted input, or two different sources. Offset correctness is therefore not
  natively protected.
- **Ownership/marks**: no native window test asserts `Marks` or `Source.Value`.
- **Shape/bounds**: the **<=32 inspected bound of `stringWindowSeq`
  (`iast/propagation/strings.go:113-124`) is untested at any level** - the engine
  bound test covers `StringWindows`, not the `iter.Seq` wrapper's own counter.
  Last-included (index 31) and first-excluded (index 32) for the four `*Seq`
  aspects plus `Lines` is a real hole.
- **Shape/bounds**: Unicode and invalid-UTF-8 inputs are absent from all native
  window tests (present only in engine tests).
- **Analysis state**: no window aspect has a native "active but clean" or
  "finished owner" case.

### 4.2 Allocating exact family

| Aspect | Wrapper | Native call | Depth | Contract |
| --- | --- | --- | --- | --- |
| `strings.Join` | `strings.go:127` -> `JoinString` | `strings_test.go:121` in `TestAllocatingStringOperations:116` | **A1** | exact <=16 elements, **coarse** beyond |
| `strings.Repeat` | `strings.go:133` -> `RepeatString` | `strings_test.go:122` | **A1** | exact; count 1 derives the alias, count>1 clones |
| `strings.Replace` | `strings.go:139` -> `ReplaceString(...,count)` | `strings_test.go:123` | **A1** | exact <=32 matches, **coarse** beyond |
| `strings.ReplaceAll` | `strings.go:145` -> `ReplaceString(...,-1)` | `strings_test.go:124` | **A1** | exact <=32 matches, **coarse** beyond |

This is the weakest cell in the string matrix: four exact-contract operations
protected natively by `require.True(taint.IsTaintedString(...))` alone.
Engine compensation (all **E**):

| Behavior | Test |
| --- | --- |
| Join exact element + separator layout | `propagation_test.go:503-518` (A2) |
| Join coarse fallback includes separator | `propagation_test.go:520-531` (A2) |
| Replace exact copied + replacement segments | `propagation_test.go:533-548` (A2) |
| Replace empty pattern + Unicode + coarse limit | `propagation_test.go:550-570` (A2) |
| Repeat count-1 derive vs count-N clone | `propagation_test.go:574-589` (A2 + identity) |
| Repeat isolates static `repeatedSpaces` backing | `propagation_test.go:591-605` (A2 + identity) |
| Repeat/window/join/adopt **with marks** | `range_behavior_test.go:20-57` (**A3**) |
| Source-range limit (1 / DefaultLimit / HardLimit) through Replace->Copy->Coarse | `propagation_test.go:143-223` (A2 + full `Source` origin/name/value) |

Missing: no native test for the 33rd-match coarse transition, the >16-element
join coarse transition, a tainted separator, a tainted replacement, distinct
sources, or an unused tainted contributor. All of that exists only at engine
level.

### 4.3 Coarse family (case, map, valid-UTF-8)

| Aspect | Wrapper | Native call | Depth | Contract |
| --- | --- | --- | --- | --- |
| `strings.ToLower` | `coarse.go:19` -> `CaseString` | `strings_test.go:133` | A2 | **exact when ASCII length-preserving, coarse when Unicode** |
| `strings.ToUpper` | `coarse.go:24` | `strings_test.go:134` | A2 | same |
| `strings.ToTitle` | `coarse.go:29` | `strings_test.go:135` | A2 | same |
| `strings.Map` | `coarse.go:34` -> `CoarseString` | `strings_test.go:136` | A2 | coarse |
| `strings.ToValidUTF8` | `coarse.go:39-46` (alias check selects 1 or 2 contributors) | `strings_test.go:137`; **and** `TestToValidUTF8UsesOnlyContributingProvenance` `strings_test.go:163-238` | **A3-minus** (see note) | coarse; contributor is the value, plus the replacement **only if repair occurred** |

`TestToValidUTF8UsesOnlyContributingProvenance` is the strongest native coarse
test in the repository: 8 sub-cases spanning tainted value / tainted replacement
/ clean / empty / invalid-run permutations, asserting native value parity, the
whole-result coarse range (`Start==0`, `Length==len(got)`), and the **exact set
of contributing `Source.Name` -> `Source.Value` pairs**. It does not assert
`Marks`, hence A3-minus.

The ASCII-exact vs Unicode-coarse split for `ToLower`/`ToUpper`/`ToTitle` is
**only** proven at engine level:
`TestCaseStringUsesExactASCIIAndCoarseUnicodeRanges`
(`propagation_test.go:651-663`) asserts `{Start:1,Length:2}` preserved for
`"aBcD"` and a whole-value coarse range for `"a\u00e9"`. Natively the input
`"Attack Value"` is ASCII and fully tainted, so the A2 assertion cannot
distinguish the two branches.

Missing: native Unicode / invalid-UTF-8 case input; native partially tainted case
input (which would distinguish exact from coarse); mark intersection at N level.

### 4.4 Formatting and encoding (11 aspects)

| Aspect | Wrapper | Native call | Depth | Contract |
| --- | --- | --- | --- | --- |
| `fmt.Sprint` | `coarse.go:49` -> `CoarseFormatString` | `strings_test.go:139`; **bounded drop** `:254-257` | A2 + **telemetry drop count + exact surviving source set** | coarse, <=16 args, **drop beyond** |
| `fmt.Sprintf` | `coarse.go:54` -> `CoarseFormattedString` | `strings_test.go:140`; `:259-263` | same | coarse, format + <=15 args, drop beyond |
| `fmt.Sprintln` | `coarse.go:59` -> `CoarseFormatString` | `strings_test.go:141`; `:266-269` | same | coarse, <=16 args, drop beyond |
| `net/url.QueryEscape` | `coarse.go:64` | `strings_test.go:142` | A2 | coarse |
| `net/url.PathEscape` | `coarse.go:69` | `strings_test.go:143` | A2 | coarse |
| `net/url.QueryUnescape` | `coarse.go:74` | `strings_test.go:150-152`; **error parity** `:304-306` | A2 + A0 error | coarse; error preserved, empty result |
| `net/url.PathUnescape` | `coarse.go:80` | `strings_test.go:154-156` | A2 | coarse |
| `strconv.Quote` | `coarse.go:86` | `strings_test.go:144` | A2 | coarse |
| `strconv.QuoteToASCII` | `coarse.go:91` | `strings_test.go:145` | A2 | coarse |
| `strconv.QuoteToGraphic` | `coarse.go:96` | `strings_test.go:146` | A2 | coarse |
| `strconv.Unquote` | `coarse.go:101` | `strings_test.go:158-160` | A2 | coarse; error path untested |

`TestCoarseFormattingRecordsBoundedDrops` (`strings_test.go:240-288`) is the
model for the drop contract: it asserts native value equality,
`telemetry.DroppedPropagation` incremented by exactly 1, and that the surviving
source set is exactly `{"included"}` while the 17th argument's source is dropped.
That covers the **last-included / first-excluded boundary** for the three `fmt`
aspects. Engine analogue: `propagation_test.go:385-392` (17 coarse inputs, result
not replaced) and `TestPropagationTelemetry:93-118`.

Missing: `strconv.Unquote` error path natively (only `QueryUnescape` has one);
`PathUnescape` error path; mark intersection at N level for any of these 11; no
native case where a coarse op receives two different owners' sources (engine:
`TestCoarseStringTwoOwnersKeepLocalSourceIDs` `propagation_test.go:709-751` and
`TestCoarseStringPreservesEachOwnerSourceAndMarks` `:682-707`, **A3**).

### 4.5 `strings.Replacer.Replace` - pointer and value forms (2 aspects)

Wrapper: `iast/propagation/strings.go:152-155` -> `CoarseString(result, value)`.
Contract: **coarse on the input value; replacement-term provenance is
deliberately dropped** (`README.md:49-51` and the wrapper doc comment).

| Aspect | Native evidence | Depth |
| --- | --- | --- |
| `strings.Replacer.Replace.pointer` | `propagationtest/strings.go:53` `strings.NewReplacer(...).Replace(value)` - the receiver is the `*strings.Replacer` returned by `NewReplacer`, so this is the **pointer** form. Called from `strings_test.go:138` (positive, A2) and `strings_test.go:295` in `TestReplacerReplacementProvenanceIsUnsupported:290` (negative: a tainted replacement must **not** taint the result) | A2 + negative control |
| `strings.Replacer.Replace.value` | **no test.** No `strings.Replacer` value-receiver call exists anywhere in the repository. | - |

**Justified N/A?** No. `strings.Replacer` is conventionally used as a pointer
from `NewReplacer`, but a value receiver is legal (`r := *strings.NewReplacer(...)`
then `r.Replace(x)` compiles and matches the value-only aspect). The value
template only inserts `&`, so the wrapper body is identical; the residual risk is
that the value-form aspect could stop matching silently. Recorded as a
**low-severity gap**, not an invariant-backed N/A.

## 5. Named byte operations (28 aspects)

All 28 have native call sites in `iast/internal/propagationtest/bytes.go`.

### 5.1 Window family - exact `ByteWindow`/`ByteWindows`

| Aspect | Wrapper | Helper | Native call (all in `TestByteWindowOperations:65`) | Depth |
| --- | --- | --- | --- | --- |
| `bytes.Clone` | `bytes.go:15` -> `CopyBytes` | `bytes.go:10` | `bytes_test.go:70` | A2 |
| `bytes.Cut` | `bytes.go:33` | `bytes.go:13` | `bytes_test.go:71-73` | A2 x2 + `found` |
| `bytes.CutPrefix` | `bytes.go:41` | `bytes.go:14` | `bytes_test.go:74-78` | A2 |
| `bytes.CutSuffix` | `bytes.go:48` | `bytes.go:15` | `bytes_test.go:76-78` | A2 |
| `bytes.Split` | `bytes.go:55` | `bytes.go:16` | `bytes_test.go:79` | A2 |
| `bytes.SplitN` | `bytes.go:62` | `bytes.go:17` | `bytes_test.go:80` | A2 |
| `bytes.SplitAfter` | `bytes.go:69` | `bytes.go:18` | `bytes_test.go:81` | A2 |
| `bytes.SplitAfterN` | `bytes.go:76` | `bytes.go:19` | `bytes_test.go:82` | A2 |
| `bytes.Fields` | `bytes.go:83` | `bytes.go:20` | `bytes_test.go:83` | A2 |
| `bytes.FieldsFunc` | `bytes.go:90` | `bytes.go:21` | `bytes_test.go:84` | A2 |
| `bytes.Trim` | `bytes.go:97` | `bytes.go:22` | `bytes_test.go:86` | A2 |
| `bytes.TrimSpace` | `bytes.go:104` | `bytes.go:23` | `bytes_test.go:87` | A2 |
| `bytes.TrimLeft` | `bytes.go:111` | `bytes.go:24` | `bytes_test.go:88` | A2 |
| `bytes.TrimRight` | `bytes.go:118` | `bytes.go:25` | `bytes_test.go:89` | A2 |
| `bytes.TrimPrefix` | `bytes.go:125` | `bytes.go:26` | `bytes_test.go:90` | A2 |
| `bytes.TrimSuffix` | `bytes.go:132` | `bytes.go:27` | `bytes_test.go:91` | A2 |
| `bytes.TrimFunc` | `bytes.go:139` | `bytes.go:28` | `bytes_test.go:92` | A2 |
| `bytes.TrimLeftFunc` | `bytes.go:146` | `bytes.go:29` | `bytes_test.go:93` | A2 |
| `bytes.TrimRightFunc` | `bytes.go:153` | `bytes.go:30` | `bytes_test.go:94` | A2 |

`requireTaintedBytes` asserts only `Origin` - not `Source.Name` - so a byte
window row is one notch weaker than its string equivalent.

### 5.2 Allocating and transform family

| Aspect | Wrapper | Native call | Depth | Contract |
| --- | --- | --- | --- | --- |
| `bytes.Join` | `bytes.go:21` -> `JoinBytes` | `bytes_test.go:113` in `TestAllocatingByteOperations:107` | **A1** | exact <=16, coarse beyond |
| `bytes.Repeat` | `bytes.go:27` -> `RepeatBytes` | `bytes_test.go:114` (count 1), `:115` (count 2) | **A1** | exact |
| `bytes.Replace` | `bytes.go:160` | `bytes_test.go:116` | **A1** | exact <=32 matches, coarse beyond |
| `bytes.ReplaceAll` | `bytes.go:166` | `bytes_test.go:117` | **A1** | exact <=32, coarse beyond |
| `bytes.ToLower` | `bytes.go:172` -> `CaseBytes` | `bytes_test.go:118` | **A1** | exact ASCII / coarse Unicode |
| `bytes.ToUpper` | `bytes.go:177` | `bytes_test.go:119` | **A1** | same |
| `bytes.ToTitle` | `bytes.go:182` | `bytes_test.go:120` | **A1** | same |
| `bytes.Map` | `bytes.go:187` -> `CoarseBytes` | `bytes_test.go:121` | **A1** | coarse |
| `bytes.ToValidUTF8` | `bytes.go:192` -> `ValidUTF8Bytes` | `bytes_test.go:122` (positive, A1) and `bytes_test.go:103` in `TestValidUTF8IgnoresUnusedReplacement:98` (**negative**: an unused tainted replacement must not taint a valid input) | A1 + negative | exact <=32 invalid runs, coarse beyond |

Engine compensation (all **E**): `bytes_exact_test.go` covers Join exact layout
(`:43-60`), single-element adopt-not-derive (`:62-73`), >16-element coarse
(`:75-87`), coarse with separator (`:89-100`), Replace exact segments
(`:102-119`), the **32 vs 33 match exact/coarse boundary distinguished by
SourceID** (`:121-142`), empty-old plus Unicode plus invalid-UTF-8 byte-for-byte
parity (`:144-177`), partial-range survival (`:179-192`), two-owner local
SourceIDs (`:194-234`), ValidUTF8 contributing-replacement-only (`:236-258`),
Case ASCII-exact/Unicode-coarse (`:260-274`), Case alias derive without extra
charge (`:276-288`), oversized and interior-alias rejection (`:290-324`),
zero-allocation inactive and untainted paths (`:326-368`), and the finish race
(`:370-404`). `range_behavior_test.go:100-141` adds the **33-run ValidUTF8 coarse
fallback with mark intersection** (A3) and the `count==0` unchanged-alias case.

Missing natively for the byte matrix: everything the string matrix misses, plus
`Source.Name`; no native partially tainted byte input; no native mark assertion
anywhere in `bytes_test.go`.

## 6. Stateful writers (30 aspects) plus 3 invalidation aspects

Wrappers: `iast/propagation/writer.go`. Engine:
`internal/taint/propagation/writer.go`. Contract: **exact** offsets through
writer state; `Reset` -> **drop**; `Truncate` -> exact slice;
`Grow`/`WriteByte`/`WriteRune` advance untainted length; `String` publishes
(Builder clones, Buffer adopts the audited fresh result).

Native forms in `iast/internal/propagationtest/writer.go` are all on addressable
locals, so Go's auto-address makes the *value-only* aspect the matching one for
`var b strings.Builder; b.WriteString(x)`; explicit `*bytes.Buffer` receivers
(from `bytes.NewBuffer`/`bytes.NewBufferString`) match the *pointer-only* aspect.

### 6.1 `strings.Builder` (14 aspects)

| Aspect | Native evidence | Wrapper-only evidence | Depth |
| --- | --- | --- | --- |
| `Write.value` | `propagationtest/writer.go:80` (`BuilderBytes`) via `writer_test.go:97` | `writer_inactive_test.go:24` | A2 (`requireWriterRange 0,5`) |
| `Write.pointer` | **none** | `writer_inactive_test.go:24` (inactive only) | - |
| `WriteString.value` | `writer.go:71,72,87,89` (`BuilderString`, `BuilderReset`) via `writer_test.go:89`, `:106` | `writer_inactive_test.go:27` | A2 (`7,6`) + negative after Reset |
| `WriteString.pointer` | **none** | `writer_inactive_test.go:27` | - |
| `WriteByte.value` | `writer.go:74` via `writer_test.go:89` | `writer_inactive_test.go:30` | A2 |
| `WriteByte.pointer` | **none** | `writer_inactive_test.go:30` | - |
| `WriteRune.value` | `writer.go:81` via `writer_test.go:97` | `writer_inactive_test.go:31` | A2 |
| `WriteRune.pointer` | **none** | `writer_inactive_test.go:31` | - |
| `Grow.value` | `writer.go:73` via `writer_test.go:89` | `writer_inactive_test.go:22` + panic on `-1` at `:38` | A2 |
| `Grow.pointer` | **none** | `writer_inactive_test.go:22,38` | - |
| `Reset.value` | `writer.go:88` via `writer_test.go:106` (`require.False(IsTaintedString)`) | `writer_inactive_test.go:35` | negative |
| `Reset.pointer` | **none** | `writer_inactive_test.go:35` | - |
| `String.value` | `writer.go:75,82,90` via `writer_test.go:89,97,106` | `writer_inactive_test.go:34,37` | A2 |
| `String.pointer` | **none** | `writer_inactive_test.go:34,37` | - |

**Pointer/value injection gap.** Both forms call the same wrapper, but the
receiver matching and inserted address operation differ. This is a reachable
native-injection gap, not an N/A invariant. Add pointer-form cases for the seven
Builder methods without duplicating the entire engine scenario matrix.

Engine-level Builder proof (**E, A3**): `writer_behavior_test.go:72-104` asserts
the exact 2-range layout `{8,4,SourceID 3,Marks 0xe}` plus
`{13,3,SourceID 7,Marks 0x4}` for a prefix / tainted-string / tainted-bytes /
untainted-byte sequence, plus `BuilderString` clone identity
(`unsafe.StringData` differs) and `WriterInvalidationActive()` transitions.

### 6.2 `bytes.Buffer` (16 aspects)

| Aspect | Native evidence | Depth |
| --- | --- | --- |
| `Write.value` | `propagationtest/writer.go:104` (`BufferBytes`), `:170` (`BufferCopyAppend` mode `bytes`) via `writer_test.go:98`, `:145` | A2 / **A3** (`requireBufferSource`) |
| `Write.pointer` | **none** | - |
| `WriteString.value` | many helpers (`writer.go:18,95,96,111,118,120,126,134,142,154,161,168,179,215,229,230,237,241,248,262,269,271,272,279,300,307,315,321`) via `writer_test.go:32,145,159,192,206,217,227,228,240,246,256,311,339,340,363` | **A3** in `TestBufferCopyReadProvenance:25`, `TestBufferCopyAppend:134`, `TestBufferCopyAppendSeparateOwners:154` (two distinct sources at distinct offsets), `TestBufferCopyPreservesSecureMarks:318` (**marks asserted**) |
| `WriteString.pointer` | `writer.go:188` (`BufferCopyReset` on `buffer := bytes.NewBuffer(...)`), `:215` (`BufferCopyCompaction`), `:225`/`:229` (`BufferCopyExhausted`) via `writer_test.go:192`, `:206`, `:217` | A3 / negative |
| `WriteByte.value` | `writer.go:98,172` via `writer_test.go:92`, `:145` | A2 / A3 |
| `WriteByte.pointer` | **none** | - |
| `WriteRune.value` | `writer.go:105,175,177` via `writer_test.go:98`, `:145` (`rune`, `wide-rune`) | A2 / A3 |
| `WriteRune.pointer` | **none** | - |
| `Reset.value` | `writer.go:119,195,240,261` via `writer_test.go:107,192,227,240` | negative + A3 |
| `Reset.pointer` | `writer.go:228` (`buffer.Reset()` on a `*bytes.Buffer`) via `writer_test.go:217` | negative |
| `Truncate.value` | `writer.go:112,155,281,318` via `writer_test.go:108`, `:131`, `:256`, `:363` | A2 + **A3** (`TestBufferCopyTruncate:251`, including length 0) + panic parity (`TestBufferWrapperPreservesPanic:127`) |
| `Truncate.pointer` | **none** | - |
| `String.value` | ubiquitous (`writer.go:30,99,113,121,181,204`) via `writer_test.go:92,108,145,192,256` | A2 / A3 |
| `String.pointer` | `writer.go:197,204` (`BufferCopyReset`), `:231` (`BufferCopyExhausted`) via `writer_test.go:192`, `:217` | A3 |
| `Grow.value` | `writer.go:97,143,167,218,239` via `writer_test.go:92,116,145,206,227` | A2 + **A3** (`TestBufferCopyInteriorCompaction:202` asserts `Available()` 22 -> 118 and range `{4,6,"attack"}`) |
| `Grow.pointer` | **none** - see note | - |

Note on `Grow.pointer`: `BufferOldAllocation` (`writer.go:236-243`) declares
`var buffer bytes.Buffer` then calls `buffer.Grow(1024)`, which is the **value**
form; `copied.Grow(30)` at `writer.go:218` is also a value form because
`copied := *buffer`. I found **no** pointer-receiver `Grow`, `Write`,
`WriteByte`, `WriteRune`, or `Truncate` call anywhere. Likewise
`copied.WriteString` at `writer.go:199,202` and `buffer.String()` at
`writer.go:251` are value forms, not pointer forms.
`writer_inactive_test.go:42-62` calls every Buffer wrapper with an explicit
`&buffer`, but only with **no active request**, so it proves host-behavior parity
(values, errors, panics, `nil` receiver), not provenance.

Additional native writer behaviors with tests, all **N**:

| Behavior | Test | Depth |
| --- | --- | --- |
| Buffer value copy read (direct / value-arg / return / struct-field) | `TestBufferCopyReadProvenance` `writer_test.go:25-37` | **A3** x4 modes |
| `Peek` alias overwrite invalidates (direct / method-value / copy / interface / eof / zero) | `TestBufferPeekOverwrite` `writer_test.go:53-70` | negative x6 + `io.EOF` parity |
| Reset then overwrite through a copy; header vs backing distinction; direct and method-value | `TestBufferCopyResetThenOverwrite` `writer_test.go:185-200` | A3 + pointer/len/cap/available equality |
| Exhausted zero-capacity unread view | `TestBufferCopyExhaustedBackingInvalidation` `:213-220` | negative |
| Old allocation after reallocation, plus assigned receiver | `TestBufferCopyOldAndAssignedBacking` `:222-233` | A3 + negative |
| Equal content is not alias identity; expected peer write | `TestBufferCopyIndependentAndPeerWrites` `:235-249` | A3 + negatives |
| Host panic parity (peek / truncate / grow / nil-grow / nil-write) compared against an uninstrumented capture | `TestBufferOriginalPanics` `:262-298` | **A0, strongest parity form in the repo** |
| `ReadFrom` error parity plus invalidation | `TestBufferOriginalReadFromError` `:306-316` | A0 + negative |
| Secure marks survive a value copy and a copy-append | `TestBufferCopyPreservesSecureMarks` `:318-355` | **A3 with marks**, seeded through `store.Owner.AdoptString` + `ranges.MarkAll` (no new public API) |
| Divergent and historical copies are safe misses | `TestBufferCopyDivergentViewsRemainSafeMisses` `:357-367` | negative x2 |
| Indirect `Read` method value and `Bytes()` mutation invalidate | `TestWriterResetTruncateAndIndirectMutation` `:101-117` | negative x2 |
| `nil` Buffer `String()` -> `"<nil>"` | `TestNilBufferStringPreservesHostBehavior` `:119-125` | A0 |

Engine-level Buffer proof: `writer_behavior_test.go:106-133`
(`TestWriterTruncateResetAndAnchoredCopyLifetime`) asserts exact ranges with
marks across an anchored copy, `TruncateWriter` slicing, and `ResetWriter`
clearing `HasWriterStates()` and `WriterInvalidationActive()`.

### 6.3 Invalidation aspects (3)

| Aspect | Hooked methods | Evidence | Gap |
| --- | --- | --- | --- |
| `bytes.Buffer.invalidate-backing` | `Write`, `WriteString`, `WriteByte`, `WriteRune`, `Grow`, `ReadFrom` | `ReadFrom` at `writer_test.go:306`; write and grow paths exercised throughout 6.2; `writerbridge` unit tests `internal/taint/writerbridge/bridge_test.go:15,36,50,81` cover Expect/Cancel/nested/peer classes | no test isolates the `BackingWrite` classification per method |
| `bytes.Buffer.invalidate-header` | `Reset`, `Truncate` | `writer_test.go:185-200` (Reset header-only, before==after) and `:363` (Truncate divergent) | none material |
| `bytes.Buffer.invalidate-exposure` | `Read`, `Next`, `ReadByte`, `ReadRune`, `ReadBytes`, `ReadString`, `WriteTo`, `Bytes`, `AvailableBuffer`, `Peek` | `Read` at `writer_test.go:114`; `Next` at `propagationtest/writer.go:214,227` via `writer_test.go:206,217`; `Bytes` at `writer_test.go:115`; `Peek` at `writer_test.go:53-70` (6 modes) | **`ReadByte`, `ReadRune`, `ReadBytes`, `ReadString`, `WriteTo`, `AvailableBuffer` have no test at all.** `README.md:41-42` explicitly promises `AvailableBuffer` results stay untainted and that accessing them invalidates overlapping views - untested. |

### 6.4 Writer limits (`README.md:70-77`)

`store.MaxWriters = 8` (`internal/taint/store/limits.go:30`), 4 owners per
receiver, 64 KiB charged capacity. Covered at **store** level only
(`internal/taint/store/writer_test.go:102-110` overflow, `:373`, `:386-408`
full-table charge; `internal/taint/store/saturation_test.go`). **No
propagation-level or native test drives a real application to 9 writers or 5
owners.**

## 7. JSON decoding (6 aspects) and destination classes

### 7.1 Aspects

| Aspect | Hook | Evidence | Depth |
| --- | --- | --- | --- |
| `application JSON propagation bootstrap` | `_ = iastjson.Activate` prepended to a root `main` (non-test-main) | `iast/integration/testapp/bootstrap_test.go:19-38` builds `./cmd/bootstrap.test` with Orchestrion and asserts `iast/encoding/json.init.0` is linked (`cmd/bootstrap/symbols.txt:2`), then runs the binary | structural, strong |
| `encoding/json Decoder reader binding` | `*json.Decoder.Decode` prologue -> `jsonbridge.Bind(d.r,&d.d)` with deferred `Unbind` | `e2e_test.go:110-132` (two decodes, **exact source document per decode**), `json_regression_test.go:23` (reinit with a clean reader), `:97` (failure), `:115` (panic), `:133` (oversized), `:60` (10 documents through a bound reader, asserting per-document `Source.Value`) | **A2 + source value** |
| `encoding/json decode state lifetime` | `*decodeState.unmarshal` prologue | `e2e_test.go:84-108`, `json_regression_test.go:41`, `:152`, `:174` | A1 / A2 |
| `encoding/json quoted string source` | `*decodeState.valueQuoted` defer -> `jsonbridge.Quoted` | `json_regression_test.go:41` (`,string` nested), `:152` (repeated `\"same\"` in nested and map value), `:174` (null/number/boolean leave the destination unchanged); unit `internal/taint/jsonbridge/bridge_test.go:92-155`; engine `internal/taint/propagation/json_test.go:32-53` (repeated equal literals: only the token at the tainted offset propagates; copied bytes rejected) | **A2 + identity** |
| `encoding/json document publication` | `*decodeState.init` prologue -> `jsonbridge.Document` | `json_regression_test.go:133` (>64 KiB drops), `e2e_test.go:110` | A1 + negative |
| `encoding/json typed string materialization` | `*decodeState.literalStore` defer -> `jsonbridge.Literal` | `iast/encoding/json/json_test.go:104-132` (`propagateLiteral` direct: plain, named + `,string`, custom-unmarshaler skip) and `:134-152` (5 rejection classes); engine `json_test.go:18-95` | A1 at wrapper, **A2 exact range** at engine (`{Length:6,SourceID:7}`) |

`iast/encoding/json/json_test.go:40-98` (`TestSourceShape`) additionally pins the
five hooked `encoding/json` symbols and the `Decoder.r`, `Decoder.d`,
`decodeState.data` field types against the live GOROOT - a real structural guard
against Go-version drift.

### 7.2 Destination classes (`README.md:36`, `:61-68`)

Contract: **coarse whole-value range, exact intersecting source identity**
(`internal/taint/propagation/json.go:49-61` - `ranges.Slice` then `ranges.Coarse`).

| Destination class | Supported? | Evidence | Gap |
| --- | --- | --- | --- |
| nested struct `string` | yes | `e2e_test.go:84-108` (`destination.Nested.Value`), `json_regression_test.go:41` | assertion is `IsTaintedString` only |
| slice `[]string` element | yes | `e2e_test.go:93,99` (`Values[0]`, with `escaped\\nvalue`) | A1 only |
| **array `[N]string`** | yes per README ("arrays") | **no test** | **gap** |
| typed map value `map[string]string` | yes | `e2e_test.go:94,99` | A1 only |
| typed map value of a struct with named + `,string` | yes | `json_regression_test.go:152-172` | A1 |
| named string type | yes | `json_regression_test.go:41-58`, `iast/encoding/json/json_test.go:121-127` | A1 |
| `,string` tag field | yes | `json_regression_test.go:41`, `:152`, `:174` | A1 |
| custom `UnmarshalJSON` output | **not supported** | `e2e_test.go:134-148` (`customString` -> `"sanitized"`, untainted), `iast/encoding/json/json_test.go:100-102,129-131` | covered |
| panicking unmarshaler | panic preserved, no taint | `e2e_test.go:150-164`, `json_regression_test.go:115-131` | covered |
| **decoded `[]byte` destination** | **not supported** | **no test** | **gap** (README lists it explicitly) |
| **`interface{}` / `any` value** | **not supported** | `e2e_test.go:95` declares `Any any` but **never asserts it** | **gap - declared, unverified** |
| **typed map keys** | **not supported** | **no test** | **gap** |
| **`map[string]any` keys** | **not supported** | **no test** | **gap** |
| invalid document | no taint | `e2e_test.go:166-180`, `json_regression_test.go:97` | covered |
| >64 KiB document (`README.md:64`) | drops provenance | `json_regression_test.go:133-150` | covered (the boundary tested is `MaxRootBytes+1`, not `MaxRootBytes`) |
| 64 decoder slots / 4-probe admission (`README.md:64-66`) | excess or colliding concurrent decodes drop | **no test at any level**; `jsonbridge.addDecoderState` (`bridge.go:206-227`) returns `nil` after 4 probes - untested | **gap** |
| reentrant use of the same decoder | can lose outer provenance | `internal/taint/jsonbridge/bridge_test.go:61-66` (a nested bind preserves the outer reader); the *loss* case is not asserted | partial |

## 8. Reader propagation (io 4 + bufio 1) and the url source

| Aspect | Hook | Evidence | Depth / gap |
| --- | --- | --- | --- |
| `io.LimitReader` | body prologue, `iobridge.Propagate(arg0,result0)` | `iast/io/io_test.go:84` inside `TestReadAllThroughSupportedWrappers:77` | only in composition; no isolated positive or negative |
| `io.TeeReader` | same | `io_test.go:86`; the side writer content is asserted at `:93` (`side.String()=="request-body"`) | **no assertion that the side `bytes.Buffer` stays untainted** - the design note says never bind the writer. Gap. |
| `io.MultiReader` | loop over inputs, **`break` at index >= 8** | `io_test.go:87` with **2** readers | **the 8-input bound (last included index 7, first excluded index 8) is untested.** Gap. |
| `io.ReadAll` | `iobridge.ReadAll(arg0,result0)` | `TestReadAllThroughSupportedWrappers:77` (composed chain, terminal error, read count, `Source.Value`), `TestReadAllEOFWithData:100`, `TestReadAllBodySizeBound:128` (sizes 0, 1, 2, 1024, `MaxRootBytes-1`, `MaxRootBytes`, `MaxRootBytes+1`) | **strongest reader coverage; full bound sweep.** Missing: a multi-`Read` accumulation where the final slice is reallocated |
| `bufio.NewReaderSize` | prologue; propagate only when `Size() <= 4096` | `iast/bufio/bufio_test.go:21`, `:25`, `32-75`: sizes 16 / **4096 (limit)** / **4097 (above limit)** / unbound input, in both manual `iastbufio.Propagate` and automatic injection modes, plus a post-`Finish` nil check and "propagation must not read input"; `io_test.go:88` (size 32); `io_test.go:115-126` (8192 drops); `TestPropagateNilReaders:77` | **boundary covered on both sides.** Missing: `bufio.NewReader` (the delegating entry point) is never called in a test - coverage relies on documented delegation |
| `net/url.URL.Query` | result rewritten by `urlbridge.Query` | `internal/taint/urlbridge/bridge_test.go:15-25` (callback plumbing only); exercised indirectly by `e2e_test.go:55`, `:75`, `:186` (`r.URL.Query().Get(...)` feeding SQL and command sinks) | **Classified N/A for this matrix**: the aspect creates a *source*, it does not propagate an input taint. Invariant: `urlbridge.Query` receives an untainted native map and taints values from the request, so no input provenance exists to preserve. |

Reader-binding limits (8 bindings per owner) are covered at store level
(`internal/taint/store/saturation_test.go:114` `TestReaderBindingLimit`,
`binding_behavior_test.go:15,37`), not through the `io`/`bufio` aspects.

## 9. Principal gaps (ranked)

1. **Structural, blocks Phase 2.** `iast/integration/testapp/orchestrion.tool.go:10-19`
   imports `iast/database/sql`, `iast/encoding/json`, `iast/net/http`,
   `iast/net/url`, `iast/os/exec` and `tracer` - but **not** `iast/propagation`,
   `iast/io`, or `iast/bufio`. The root `orchestrion.tool.go:16-26` imports all of
   them. Consequence: in the `iast/integration/testapp` nested module, `+`,
   slicing, `strings.*`, `bytes.*`, writer methods and reader composition are
   **not injected**. Any Phase 2 "HTTP -> trim/slice -> join/concat -> SQL" chain
   written in that module will silently exercise *uninstrumented* transforms
   unless the tool file is extended first. (`iast/database/sql/testapp` and
   `iast/os/exec/testapp` tool files are likewise sink-only, which is appropriate
   for their scope.)
2. **Allocating operations protected natively by boolean assertions only**:
   `strings.Join`, `strings.Repeat`, `strings.Replace`, `strings.ReplaceAll`
   (`strings_test.go:121-124`) and all ten entries of
   `TestAllocatingByteOperations` (`bytes_test.go:112-123`). A regression that
   taints the whole result, shifts offsets, or swaps the contributing source
   passes. This is exactly the plan's Phase 3 target.
3. **The standalone native string and byte operation fixtures seed fully tainted inputs.** Their input setup uses full-length taint (`strings_test.go:78`, `:120`,
   `:131`; `bytes_test.go:69`, `:111`). Offset correctness, contributor selection
   and the exact/coarse distinction are therefore protected only at engine level.
4. **Native concat arities 4-16 unproven**, and the 17-operand drop boundary is
   untested in both modes.
5. **Native slice template branches**: 3 of 4 string forms and 5 of 6 byte forms
   have no native call. `StringSliceAll/Low/High` and
   `BytesSliceAll/Low/High/Bounds/FullZero` are wrapper-only.
6. **`stringWindowSeq` 32-inspect bound untested**
   (`iast/propagation/strings.go:117`) for `SplitSeq`, `SplitAfterSeq`, `Lines`,
   `FieldsSeq`, `FieldsFuncSeq`.
7. **`io.MultiReader` 8-input bound untested**, and the TeeReader side writer is
   never asserted untainted.
8. **Six `bytes.Buffer` exposure hooks untested**: `ReadByte`, `ReadRune`,
   `ReadBytes`, `ReadString`, `WriteTo`, `AvailableBuffer` - including the
   explicit `AvailableBuffer` promise at `README.md:41-42`.
9. **JSON negative classes declared but unverified** (`README.md:62-63`): `any`/interface destination
   (declared at `e2e_test.go:95`, never asserted), decoded `[]byte`, typed map
   keys, `map[string]any` keys; plus the positive `[N]string` array class. The
   decoder 64-slot / 4-probe collision drop is untested.
10. **Marks are asserted natively in exactly one place**
    (`TestBufferCopyPreservesSecureMarks`, `writer_test.go:318-355`). No native
    string, byte, operator, coarse, or JSON test asserts mark preservation or
    coarse mark intersection; all of that lives in `range_behavior_test.go:73-98`
    and `:100-141` (engine).
11. **Native multi-owner coverage is narrow**: `TestBufferCopyAppendSeparateOwners`
    at `writer_test.go:154-183` drives two owners and checks both source values
    and offsets. String/byte transforms still rely on engine tests at
    `propagation_test.go:682-751` and `bytes_exact_test.go:194-234`; add native
    owner-local source-ID and fanout-bound cases.
12. **Aspect counts do not prove behavior.** Reader cases must require provenance
    after actual native calls. No new telemetry counter or aspect-count guard is
    needed for this testing plan; existing reader tests already detect some
    missing advice through behavior.

## 10. Explicit N/A cells with named invariants

| Cell | N/A justification |
| --- | --- |
| `net/url.URL.Query` propagation contract | Source-creating aspect. Invariant: the hooked function returns a freshly built `url.Values` from request text, so there is no input provenance to preserve and exact/coarse/drop does not apply. Its *source* behavior is covered by `internal/taint/urlbridge/bridge_test.go:15` and, end to end, by `e2e_test.go:55,75,186`. |
| `*.pointer` vs `*.value` writer aspect pairs | **Not N/A.** Twelve of 30 writer aspects have no positive native call: seven Builder pointer forms and five Buffer pointer forms. Identical wrapper callees do not prove advice matching. The aspect-count test also cannot prove matching. |
| `strings.Builder` value-copy propagation | `README.md:50-51`: "Builder value copies are not supported." Invariant: `strings.Builder` forbids copy-after-use at runtime, so there is no supported copy semantics to preserve. No positive test is required; no negative test exists either (accepted). |
| `Bytes`, `AvailableBuffer`, `Peek` results | `README.md:41-42`: results are contractually untainted. Invariant: mutable exposure conservatively invalidates. `Peek` is covered negatively (`writer_test.go:53-70`) and `Bytes` at `:115`; `AvailableBuffer` is **not** - that is a gap, not an N/A. |
| `+=`, `append`, `copy`, string-to-byte conversion, direct byte index/slice assignment | `README.md:43-44`: intentionally not tracked (no new mutable roots). Invariant: no aspect matches these forms, so "no propagation" is the contract. Negative tests are **absent**; a negative control would be cheap and is recommended. |
| Compiler-optimized conversion contexts (call argument, comparison, map key, range, concatenation) | `README.md:47-49`: intentionally unwrapped. Only `BenchmarkOperatorOptimizedConversionExcluded` (`operators_test.go:224`) touches this, without assertion. Currently neither N/A-proven nor covered; recommend a negative test. |
| Indirect calls through function or method values | `README.md:38-40`. Covered negatively: `TestIndirectStringCallIsUnsupported` (`strings_test.go:309-317`), `BufferIndirectRead` (`writer_test.go:114`), `BufferPeekOverwrite` modes `method` and `interface` (`:57`), `BufferCopyReset` with `indirect=true` (`:189`). |
| Tainted `strings.Replacer` replacement terms | `README.md:49-51` plus the wrapper doc. Covered negatively: `TestReplacerReplacementProvenanceIsUnsupported` (`strings_test.go:290-297`). |
| Divergent and historical buffer views | `README.md:53-59`. Covered negatively: `TestBufferCopyDivergentViewsRemainSafeMisses` (`writer_test.go:357-367`), `BufferOldAllocation` and `BufferAssignedReceiver` (`:222-233`), `BufferCopyExhausted` (`:213-220`). |

## 11. Driver verification of uncertain mappings

1. The pinned injector's `join/method_call.go:72-89` calls
   `ResolveType(selector.X)` and distinguishes a pointer from a named value.
   These are distinct native call forms. A value's pointer-receiver method
   does not make its expression match the pointer-only advice. The missing
   pointer-form cases in section 6 are real injection gaps.
2. The root-only filter and exact import-path exclusions do not exclude
   `iast/internal/propagationtest`. Its source calls and baseline assertions
   are native evidence. Existing `TestOperatorConcatAndSlices` also contains
   fresh-result generic and three-operand concatenations with taint assertions;
   its current woven check is recorded in the review document. Alias identity
   alone is not injection proof.
3. `BufferInvalidTruncate` is passed as a function value to the test harness,
   but the operation inside that helper is a direct native method call. Its
   wrapper panic-parity classification is valid.
4. Store limit tests are credited as lower-level evidence, not native advice
   coverage. Additional native cases must target the distinct propagation
   decisions rather than repeat every store limit test.

## 12. Bottom line for the Phase 1 acceptance criterion

Every one of the 136 propagation-related aspects (125 + 6 JSON + 4 io + 1 bufio)
is mapped to an existing test location or an explicit native-test gap, and the one remaining aspect (`net/url.URL.Query`) is an
explicit N/A with a stated invariant. All 72 named-function aspects have a native
call site through `iast/internal/propagationtest`. The unmet half of the
criterion is **assertion strength, not enumeration**: 14 allocating native
call results (four string and ten byte, including one repeated operation and
both exact and coarse contracts) assert taint presence only, marks appear in exactly one native assertion,
and eight advertised behaviors (section 9 items 4-9) have no test in any mode.
The second half of the Phase 1 acceptance clause - classifying every remaining
uncovered engine block - is owned by another worker and is intentionally absent.

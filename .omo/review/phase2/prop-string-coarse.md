# prop-string-coarse: coarse (whole-value) string propagation
Verdict: Mostly correct and host-safe. Case, escape, quote, and UTF-8 transforms are sound, and the coarse.go:42 identity guard is correct and necessary. The one High problem is that `fmt.Sprint*` coarse propagation taints output based on argument identity instead of on what fmt actually printed, which produces proven false-positive SQL injection findings.
Scope covered: `internal/taint/propagation/string_coarse.go` (all), `iast/propagation/coarse.go` (all), `CoarseString`/`coarseStringAlias`/`coarseStringHit`/`coarseOwner`/`coarseMatch`/`coarseAccumulate` in `internal/taint/propagation/propagation.go:320-735`, `ranges.Coarse` (`ranges/operations.go:257-290`), `store.Lookup`/`Snapshot`/`Entry.Handle` (`store/lookup.go`), `evidence.addAt` (`evidence/evidence.go:209-235`), `iast/database/sql/sql.go:34-49`, relevant `orchestrion.yml` join points (661-803), and the Go 1.26.6 `strings.ToValidUTF8`/`strings.Map` fast paths. The reproducers ran on go1.26.6 in a private copy.

## Findings

### prop-string-coarse-F1: fmt coarse propagation taints output that a String()/Error() method produced from nothing in the argument
- Severity: High
- Category: false-positive
- Location: internal/taint/propagation/string_coarse.go:206-220 (`formatArgumentKey`), reached from 90-146; iast/propagation/coarse.go:49-61
- Claim: `formatArgumentKey` selects any argument whose reflect Kind is `String` (or `[]uint8`) and uses the identity of its underlying data as a propagation input. For a string-kind type that implements `fmt.Stringer`, `error`, `fmt.Formatter`, or `fmt.GoStringer`, fmt prints the method's return value, not the underlying bytes. The whole result is still coarse-tainted with the argument's source and `Marks: 0`. A common Go allowlist idiom is a named string type whose `String()` maps user input to a fixed column name. That pattern makes a query containing no request data reach the SQL sink as unsafe. `evidence.addAt` (`evidence.go:214`) reports every range without the vulnerability's mark, so `sql.Report` goes on to `ReportTainted`. The doc comment "never invokes String methods again" acknowledges Stringers, but the code still attributes their output to the argument.
- Evidence: `.omo/review/evidence/prop-string-coarse/zz_review_coarse_test.go` (copied into `internal/taint/propagation/` of a private copy), output in `.omo/review/evidence/prop-string-coarse/repro-output.txt`. Command: `GOTOOLCHAIN=go1.26.6 go test -count=1 -run 'TestReview' -v ./internal/taint/propagation/`. Key lines:
  - `query="SELECT * FROM users ORDER BY id" containsParam=false status=1 (StatusCollected=1)`
  - `part 0 source=0 value="SELECT * FROM users ORDER BY id"` / `source 0 origin=http.request.parameter name="sort" value="name; DROP TABLE users"`
  - `Error method output="failure: bad request" containsAttack=false ranges=[{Start:0 Length:20 SourceID:0 Marks:0}]`
- Fix: In `formatArgumentKey`, skip an argument when a cheap type assertion shows it implements `fmt.Formatter`, `fmt.Stringer`, `error`, or `fmt.GoStringer`. Any of these may replace the underlying bytes (this matches fmt's `handleMethods` precedence). That turns a false positive into a safe miss, which is the direction this codebase prefers. Add a regression test with an allowlisting Stringer.

### prop-string-coarse-F2: fmt coarse propagation taints results for verbs that do not render the argument's bytes
- Severity: Medium
- Category: false-positive
- Location: internal/taint/propagation/string_coarse.go:118-146
- Claim: Every inspected string or byte argument contributes, whatever verb consumes it. `%T` (prints the type name), `%.0s` (prints nothing), and `%p` on `[]byte` (prints an address) produce output that contains no argument bytes, yet the whole result is tainted with `Marks: 0`. Argument-index verbs (`%[2]s`) that skip an argument behave the same way. These forms are rare in SQL or command construction, so the impact is limited. Each one is still an FP on a supported call.
- Evidence: same reproducer, `TestReviewCoarseFormatTaintsUnprintedStringKindArguments`: `%T verb output="SELECT string FROM t" containsAttack=false ranges=[{Start:0 Length:20 SourceID:0 Marks:0}]`; `%.0s verb output="SELECT * FROM t" ... ranges=[{Start:0 Length:15 ...}]`.
- Fix: Cheapest option is to document it. A precise fix needs a verb scan of `format`, which is linear and allocation-free, and would drop arguments consumed by `%T`/`%p`, zero precision, or skipped indices. Alternatively, accept the imprecision and note it in the README.

### prop-string-coarse-F3: README advertises `fmt.Sprint*` without saying that only direct string/[]byte arguments propagate
- Severity: Medium
- Category: doc
- Location: README.md:31 (Formatting row); internal/taint/propagation/string_coarse.go:88-89, 206-220
- Claim: Only top-level string-kind and `[]uint8`-kind arguments are inspected. Tainted data inside `[]string`, struct fields, maps, pointers, and `error` values (for example `errors.New(tainted)`, whose `Error()` returns the tainted string itself) is printed into the result, which stays untainted. That is a safe miss consistent with the bounded design, but the customer-facing README lists `fmt.Sprint*` as supported with no restriction. Readers will assume `fmt.Sprintf("... IN (%v)", ids)` or `%v` of an error propagates.
- Evidence: `TestReviewCoarseFormatMissesIndirectArguments`: `[]string output="SELECT * FROM t WHERE a IN ([' OR 1=1 --])" containsAttack=true ranges=[]`; `struct field ... ranges=[]`; `errors.New ... ranges=[]`.
- Fix: Add one README sentence: "`fmt.Sprint*` propagates only direct string and byte-slice operands and the format string; composite values, pointers, and values formatted through methods are not tracked."

### prop-string-coarse-F4: the coarse source is the first contributor, not one that lacks the surviving secure marks
- Severity: Low
- Category: provenance
- Location: internal/taint/propagation/propagation.go:721-735 (`coarseAccumulate`); internal/taint/ranges/operations.go:257-290 (`Coarse`)
- Claim: Marks are intersected across contributors, but the reported `SourceID` is always the first contributing range. If the first source carries a secure mark and a later one does not, the resulting unsafe range (marks 0) is attributed to the marked (sanitized) source, and the unsanitized source is dropped. This is latent today: no production code sets secure marks (only `ranges` operations and tests do, and the public `taint` API has no mark setter). It becomes a wrong-provenance bug as soon as sanitizers are added.
- Evidence: `TestReviewCoarseSourceIsNotTheUnsanitizedContributor`: `ranges=[{Start:0 Length:55 SourceID:11 Marks:0}]`, where source 11 had marks 0x6 and source 12 had marks 0.
- Fix: After intersecting, pick the first contributing range whose `Marks == intersection`, which is a second pass over at most 16 inputs. Or keep the first source unless its marks exceed the intersection.

### prop-string-coarse-F5: owner slots are consumed by snapshot entries that contribute no ranges
- Severity: Low
- Category: false-negative
- Location: internal/taint/propagation/string_coarse.go:159-170; internal/taint/propagation/propagation.go:383-395, 661-673
- Claim: `accumulateCoarseKey`/`coarseStringHit` allocate one of the 4 `coarseOwner` slots before `coarseAccumulate` knows whether the entry has any range. An entry for a clean window of a tainted root has `Ranges.Len()==0`, `found` stays false, and publication skips it (`!state.found`). The slot is still used, so with 4+ owners a later owner that really contributes can be dropped. This needs 4 concurrent owners sharing clean windows, so it is an edge case.
- Evidence: static reasoning only.
- Fix: `if entry.Ranges.Len() == 0 { continue }` before allocating a slot.

### prop-string-coarse-F6: inconsistent range limit between the two coarse publishers
- Severity: Info
- Category: quality
- Location: internal/taint/propagation/propagation.go:415, 692 vs string_coarse.go:194
- Claim: `coarseStringHit`/`coarseBytesHit` publish with `ranges.DefaultLimit`, while `publishCoarseOwners` uses `state.entry.Ranges.Limit()`. The result always has exactly one range, so behavior is identical. The inconsistency only invites drift.
- Evidence: static reasoning only.
- Fix: Use the entry limit in both, or factor the three copies of the accumulate/publish loop (`coarseStringHit`, `coarseBytesHit`, `accumulateCoarseKey`+`publishCoarseOwners`) into one.

## Checked and found correct
- **coarse.go:42 identity guard is correct and necessary, not redundant.** In Go 1.26.6, `strings.ToValidUTF8` returns `s` unchanged only when `b.Cap()==0` (no invalid byte), and otherwise builds a fresh allocation, so "same length and same data pointer" means exactly "unchanged value". Without the guard, an unchanged clean value plus a tainted `replacement` would be cloned and fully tainted by the replacement. The reproducer shows `without guard: ranges=[{Start:0 Length:17 SourceID:0}]` versus `wrapper (guarded): ranges=[]`. With a tainted unchanged value, the alias path keeps exact partial ranges (`{Start:4 Length:3 SourceID:5}`). An empty `value` is safe because `CoarseString` returns early when `len(result)<2`.
- **Exact vs coarse choice in `CaseString`** (string_coarse.go:42-49): aliasing results derive exact windows. ASCII input with equal length uses `ranges.Copy`, which is correct because `unicode.ToUpper/Lower/Title` map ASCII to ASCII byte-for-byte. Everything else is coarse. Verified: ASCII upper/lower keep `{Start:10 Length:3}`, and non-ASCII widens to the whole value with the source and marks retained. The widening only affects strings that already carry taint, and marks are intersected, so it cannot create a vulnerability on an untainted value or invent sanitization.
- **Stdlib fast paths that return the input or a window** (`strings.Map` unchanged, `ToLower`/`ToUpper` unchanged, `url.*Escape` with nothing to escape, `QueryUnescape` without `%`/`+`, `strconv.Unquote` without escapes returning `in[1:end-1]`) are caught by `coarseStringAlias`/`stringAlias` and derived as exact windows, never adopted, so no static or shared backing gets tainted.
- **Error paths**: `URLQueryUnescape`, `URLPathUnescape`, and `StrconvUnquote` return `""` on error, `CoarseString` skips it (`len<2`), and the error is returned unchanged.
- **Host safety**: every wrapper evaluates the stdlib call first with the same arguments, exactly once, and returns an equal value and error. The only change is backing identity (a clone), which safe Go cannot observe. `formatArgumentKey` reflection calls (`Kind`, `String`, `Type().Elem().Kind()`, `IsNil`, `Bytes` on byte-kind slices including named element types) cannot panic, and it never invokes user methods. Disabled or inactive requests exit at `request.ActiveStore()==nil` before any reflection.
- **Owner separation and source identity**: `coarseMatch` keys on (OwnerIndex, OwnerGen, OwnerID). Publication revalidates through `Entry.Handle`, and each owner's own first source ID is published back into that same owner (`TestCoarseStringPreservesEachOwnerSourceAndMarks` and the fanout tests cover this). Keeping only the first source per owner is the documented design ("first contributing source in deterministic order"), which answers the open question in digest check 11: distinct sources in one owner do not stay distinct through coarse `fmt`/`url` paths.
- **Bounds**: at most 16 inputs (format plus 15 arguments), 4 owners, result length in `[2, MaxRootBytes]`, one clone per tainted call, and drops recorded by telemetry.

## Not covered / open questions
- End-to-end woven (orchestrion) run of F1 through a real `database/sql` call was not done. The reproducer calls the same wrapper (`iast/propagation.FmtSprintf`) that the `replace-function` advice inserts, then `evidence.CollectString`, which is the exact first step of `sql.Report`.
- Whether whole-query coarse taint (from `Sprintf` or non-ASCII case conversion) degrades redaction, since any SQL literal overlap marks the source sensitive and redacts its value, is left to the redaction node.
- `bytes`-side coarse wrappers (`CoarseBytes`, byte case conversion) were out of this node's primary scope. They share `coarseAccumulate` and the F4/F5 observations apply to them.

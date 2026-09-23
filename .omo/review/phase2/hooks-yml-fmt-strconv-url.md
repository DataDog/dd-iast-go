# hooks-yml-fmt-strconv-url: fmt, strconv and net/url join points and wrappers
Verdict: Host behavior is preserved. Each wrapper evaluates the stdlib call once, invokes `String`/`Format`/`Error` exactly once, and returns identical values and errors. Alias fast paths propagate exact ranges. There is one reproduced High provenance defect: fmt argument inspection ignores formatting methods, so a named string/byte type whose `String`/`Format`/`Error` method discards the value (the allowlist-enum pattern) still taints the whole formatted result, which is a false positive on a supported path. The coarse fmt path also has documentation and precision gaps.

Scope covered: `iast/propagation/orchestrion.yml:706-803` (fmt/url/strconv aspects, including the shared package filters); `iast/propagation/coarse.go:48-104`; `internal/taint/propagation/string_coarse.go:88-221` (`CoarseFormatString`, `CoarseFormattedString`, `accumulateCoarseKey`, `publishCoarseOwners`, `formatArgumentKey`); `internal/taint/propagation/propagation.go:40-90,320-420,700-736` (`stringAlias`, `deriveStringWindow`, `CoarseString`, `coarseStringAlias`, `coarseStringHit`, `coarseMatch`, `coarseAccumulate`); `iast/net/url/orchestrion.yml`, `iast/net/url/url.go`; `internal/taint/urlbridge/bridge.go` and its test; `internal/taint/request/lazy.go:16-230` (`ManageURLQuery`, `manageMap`); `internal/taint/request/http.go:43-49` and `internal/taint/store/binding.go:112-146` (typed-nil-safe object lookup); `request/lookup.go:73-80` (`ActiveStore`); the existing tests `iast/propagation/strings_test.go:116-232`. I ran a woven reproducer suite with Go 1.26.6 and the pinned Orchestrion, covering 7 tests and about 35 cases.

## Findings

### hooks-yml-fmt-strconv-url-F1: fmt wrappers taint output produced by a Stringer/Formatter/error method that discards the tainted value
- Severity: High
- Category: false-positive
- Location: internal/taint/propagation/string_coarse.go:206-221 (reached from iast/propagation/coarse.go:48-61)
- Claim: `formatArgumentKey` keys an argument by its reflect `Kind` only (`case reflect.String: return store.StringKey(value.String())`, and likewise for `[]uint8`-kinded slices). fmt, however, prints a named type through its `Format`, `String`, `Error` (or `GoString` for `%#v`) method whenever one exists, and never prints the underlying bytes in that case. When such a method returns constants, the wrapper still publishes a whole-output coarse range with the argument's source. The common allowlist idiom `type SortOrder string; func (s SortOrder) String() string { if s=="desc" {return "DESC"}; return "ASC" }` combined with `fmt.Sprintf("... ORDER BY name %s", SortOrder(r.FormValue("order")))` produces a query that is built only from constants but is fully tainted, so it reports SQL injection at the sink. Redacting Stringers (`type Password string` with `String() = "***"`) and constant `Format` methods behave the same way.
- Evidence: .omo/review/evidence/hooks-yml-fmt-strconv-url/zz_review_fmt.go (fixture, copied into `iast/internal/propagationtest/`) and zz_review_fmt_test.go (copied into `iast/propagation/`). Command: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -vet=off -count=1 -timeout 15m -run TestReview -v ./iast/propagation/`. Output in run_woven_go1.26.6.out.txt:
  - `ALLOWLIST query="SELECT id FROM users ORDER BY name ASC" tainted=true ranges=[0,+38 src=input]` followed by `--- FAIL: TestReviewFmtAllowlistStringerFalsePositive`
  - `OVERTAINT-CHECK RedactedSecret Stringer (%s) result="SELECT '[redacted]'" contains-input=false ranges=[0,+19 src=input]`
  - `OVERTAINT-CHECK ConstFormatter (%v) result="SELECT constant" contains-input=false ranges=[0,+15 src=input]`
- Fix: in `formatArgumentKey`, return `false` before the reflect switch when `argument.(type)` is `fmt.Formatter`, `fmt.Stringer`, `error` or `fmt.GoStringer`. These are cheap cached itab assertions. The result is a safe miss, consistent with the existing "never invoke String methods again" rule. Add a regression test for the allowlist case.

### hooks-yml-fmt-strconv-url-F2: README advertises `fmt.Sprint*` without saying that only direct string/[]byte operands propagate
- Severity: Medium
- Category: false-negative
- Location: README.md:32; internal/taint/propagation/string_coarse.go:206-221
- Claim: Only top-level arguments of Kind `string` or `[]uint8` are inspected. Tainted data inside structs, slices, maps, pointers, `error` values (`errors.New(tainted)`), and Stringer wrappers returning a tainted field all yield untainted output. Examples that yield untainted output are `fmt.Sprintf("... IN (%v)", ids)` with a `[]string`, and `%v` on an error. The internal doc comment (`string_coarse.go:88`) states this restriction, but the README row reads as full `fmt.Sprint*` support, and the design docs list aggregates as "?" (shadow S14). These are silent false negatives on idioms that are common when building SQL and command strings.
- Evidence: same suite, `TestReviewFmtUnderTaint`: `struct %v result="SELECT {attacker}" ranges=UNTAINTED`, `slice %v ... UNTAINTED`, `map %v ... UNTAINTED`, `error %v result="SELECT attacker" ranges=UNTAINTED`, `Stringer wrap %s result="SELECT attacker" ranges=UNTAINTED` (the direct `%s` control is tainted: `[0,+15 src=input]`).
- Fix: document the limitation in the README "Propagation coverage" paragraph ("fmt propagates direct string and []byte operands only; aggregates, pointers, errors and Stringer results are not inspected"). Optionally, walk one level of `[]string` elements within the existing 16-input budget.

### hooks-yml-fmt-strconv-url-F3: coarse fmt/url/strconv output drops every source but the first and marks the whole SQL template as user input; README does not say these are coarse
- Severity: Medium
- Category: provenance
- Location: internal/taint/propagation/string_coarse.go:113-203; internal/taint/propagation/propagation.go:721-736; README.md:32
- Claim: `fmt.Sprintf` is the dominant way Go code assembles SQL. The coarse path publishes one `[0,len)` range per owner with the first contributing source only (`coarseAccumulate`). With two parameters in the same request, the second source disappears from evidence, and constant format-string text is attributed to the first source. This is the documented coarse design in the plans, but the README documents coarseness only for JSON (README.md:61), and it answers digest CHECK 11 negatively: sources do not stay distinct through fmt. Because the literal segments of a format string are cheaply known, a `%s`/`%v` of a string with no width, precision or flags could be mapped exactly, as the Java and Python tracers do for `String.format` and `%`/`format`.
- Evidence: `TestReviewFmtTwoSources` (a single request owner, two sources): `TWO-SOURCES sprintf result="SELECT * FROM t WHERE a='alpha' AND b='bravo'" ranges=[0,+45 src=a]`. Also `PARTIAL-INPUT sprintf result="xabalphacdy" ranges=[0,+11 src=a]`, where the input's exact range was `[2,+5]`.
- Fix: at minimum, state in the README that fmt, url and strconv transforms are coarse (whole value, first source). Follow-up: exact-range fast path for plain `%s`/`%v` verbs on direct string operands.

### hooks-yml-fmt-strconv-url-F4: verbs and argument indexes that do not emit the operand still taint the output
- Severity: Low
- Category: false-positive
- Location: internal/taint/propagation/string_coarse.go:115-129,132-145
- Claim: Every inspected operand contributes, whether or not the verb prints it. `%T`, `%p`, `%.0s`, and arguments skipped by explicit indexes (`%[2]s`) produce output without the tainted bytes, yet the output is fully tainted. This is rare in injection-relevant code, which is why it is rated Low.
- Evidence: `OVERTAINT-CHECK %T result="SELECT string" contains-input=false ranges=[0,+13 src=input]`; `%.0s result="SELECT 1" ... [0,+8 src=input]`; `%[2]s result="SELECT safe" ... [0,+11 src=input]`.
- Fix: accept and document it, or skip operands of `%T`/`%p` in a cheap format pre-scan when the exact fast path from F3 is added.

### hooks-yml-fmt-strconv-url-F5: DroppedPropagation telemetry fires on every Sprint* with more than 15/16 arguments, even when nothing is tainted
- Severity: Low
- Category: quality
- Location: internal/taint/propagation/string_coarse.go:116-118,133-135
- Claim: `recordDropped()` runs before any lookup, whenever an analysis is active and the argument count exceeds the budget, so clean formatting calls inflate the drop counter. `coarseStringHit` does not do this. The existing test `strings_test.go:152-200` only covers the tainted case.
- Evidence: static reasoning only. The counter is incremented unconditionally at the lines cited, before `accumulateCoarseKey`.
- Fix: record the drop only when one of the uninspected arguments has a `MayContain` hit, or after at least one owner was found.

### hooks-yml-fmt-strconv-url-F6: an Fprintf write into a tracked strings.Builder silently discards the builder's existing provenance
- Severity: Info
- Category: false-negative
- Location: iast/propagation/orchestrion.yml:706-731 (only Sprint* is hooked); writer state in internal/taint/propagation/writer.go
- Claim: `b.WriteString(tainted); fmt.Fprintf(&b, "-%s", clean); b.String()` returns untainted output: the unobserved write marks the writer dirty and drops everything. This is a safe miss (no stale or misaligned ranges), but `Fprintf(&builder, ...)` is a common query-building idiom. It belongs to the writer node's coverage story.
- Evidence: `BUILDER-FPRINTF result="attacker-clean!" ranges=UNTAINTED`. When the tainted write comes after the Fprintf, it is kept exactly: `BUILDER-FPRINTF-FIRST result="xclean-attacker" ranges=[7,+8 src=input]`.
- Fix: document it, or hook `fmt.Fprint*` when the writer is a `*strings.Builder`/`*bytes.Buffer`, reusing the writer propagation path.

## Checked and found correct
- Single evaluation and side effects: `FmtSprint`/`FmtSprintf`/`FmtSprintln` call `fmt.Sprint*` once and inspect arguments with `reflect.Value.String()`/`Bytes()`, which never invoke methods. The reproducer counted `String`=1, `Format`+`Error`=2, `Error`=1 (`TestReviewFmtMethodsInvokedOnce`). Multi-value call arguments (`fmt.Sprint(two())`), zero arguments, and spread `args...` compile and behave identically after `replace-function`.
- Result/error parity: `URLQueryUnescape`, `URLPathUnescape` and `StrconvUnquote` return the native `err` unchanged. On error the result is `""`, and `CoarseString` returns early for `len<2` (existing `TestCoarseOperationsPreserveErrors`, plus `unquote error="" err=invalid syntax ranges=UNTAINTED`). Values are never altered; only the backing changes (a `strings.Clone` of an identical value).
- Alias fast paths keep exact ranges: `strconv.Unquote` returns `in[1:len-1]` for escape-free input, and `url.QueryUnescape`/`QueryEscape` return the input itself when unchanged. `coarseStringAlias` derives a window instead of adopting, so no interior-window adoption happens (`unquoted="attacker" ranges=[0,+8]` from the quoted `[1,+8]`; `queryunescape alias ... [2,+8]`). A clean raw-string unquote stays untainted.
- Width and precision (`%20s`, `%.3s`) and `%q` produce whole-output coarse taint, which is expected for the coarse design. Arguments beyond 15/16 are dropped deterministically (existing test).
- Panics: `formatArgumentKey` handles nil interfaces, typed-nil pointers (Kind Ptr is ignored), nil byte slices, and named byte-element slices (`Bytes()` accepts `Elem().Kind()==Uint8`). None of these paths can panic.
- The package filter is identical across all 13 fmt/url/strconv aspects (root only, excluding `internal/**`, `iast/propagation`, and `taint`), and the wrapper signatures match the stdlib signatures exactly.
- `URL.Query` hook: the deferred advice assigns `iasturlbridge.Query(recv, map[string][]string(result))` back to the named `Values` result, which is assignable. The bridge returns its input when no callback is registered. `ManageURLQuery` uses `LookupObjectValue`, which is typed-nil safe, so the deferred call cannot panic during a nil-receiver panic. It returns the original map unless it changed. It is bounded at 48 names and 96 values, and multi-owner ambiguity is a safe drop. The stdlib already returns a fresh map, so a replacement map changes no aliasing.
- Evaluation order: all wrappers compute the native result first, then propagate.

## Not covered / open questions
- I did not run a full end-to-end SQL sink for F1. The reproducer proves the query string carries a full-length source range; any tainted range reaching `database/sql` is reported, according to the sink node's contract.
- `URL.Query` attribution trusts the bound `*url.URL` object. If an app rewrites `r.URL.RawQuery` to constants and then calls `Query()`, those values are managed as request parameters. I reasoned about this statically and did not reproduce it; it is likely rare.
- I did not measure performance. Each Sprint* call under an active analysis costs up to 16 `reflect.ValueOf` calls plus `MayContain` probes.
- The README phrases "strconv quote and unquote functions" and "net/url escape and unescape functions" do not cover `strconv.QuotedPrefix`/`AppendQuote*`/`QuoteRune*`/`UnquoteChar`, and `fmt.Fprint*`/`Append*`/`Errorf` are not hooked. This is consistent with the "direct named calls" scope and is not filed.

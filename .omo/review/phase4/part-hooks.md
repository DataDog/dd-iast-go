# Part report: hooks (propagation hooks, orchestrion.yml weaving, Orchestrion dependency)

Branch `romain.marcadier/taint-tracking` @ 2e23b46; evidence paths are relative to `.omo/review/`.

**After dedup: 8 Critical, 8 High, 4 Medium** root-cause entries owned by this part. Each Critical and High entry cites its phase-3 `fx-*` file. Other parts' Critical/High findings rooted in this part's code are listed in 2b and counted there.

## 1. Part verdict

Not shippable as-is. **Crash-safety at build time is the dominant failure:** eight phase-3-confirmed ways to break a valid customer build, all reachable with `DD_IAST_ENABLED` unset: Go 1.27 (JSON-v2 advice, plus a >17 GiB job-server blow-up), any released Orchestrion (MVS drops the pinned prerelease), import-free packages, integral float/complex slice bounds, method expressions, operators inside unevaluated `len`/`cap`/`range` operands (also new runtime panics), and plugin/c-shared builds. Most live in the pinned Orchestrion pseudo-version (`go.mod:14`, an unmerged PR with changes requested); dd-iast-go's root-scoped operator aspects make them reachable. **Runtime crash-safety** is acceptable: native panic identity is preserved, and the unshielded callbacks have no natural trigger (Medium). **Memory bounds:** typed Buffer anchors pin whole caller allocations while charging visible capacity (112 MiB retained vs a 24 MiB envelope). **Hot path:** woven `[]byte->string`/concat allocate while inactive, breaking customer `AllocsPerRun` tests. **Provenance:** four confirmed High defects (reset/pooled readers attribute across requests, `MultiReader` taints clean data, fmt taints constant method output and non-emitted arguments, intersected generic constraints drop taint). Value fidelity on Go 1.26.6 is excellent.

## 2. Findings by root cause

### C1. Go 1.27 (JSON v2) breaks every woven build. Critical, CONFIRMED
- **Location:** `iast/encoding/json/orchestrion.yml:28-47` (sink-json-sources cites `:36-47`).
- **Ids:** hooks-compile-matrix-F2, base-test-127-F1, sink-json-sources-F1 (cross-part: JSON sink).
- **Phase 3:** `phase3/fx-base-test-127-F1.json`, `phase3/fx-sink-json-sources-F1.json`.
- **Mechanism:** the woven `encoding/json.Decoder` advice references `dec.r`/`dec.d`. These fields do not exist in Go 1.27's default JSON-v2 Decoder. `encoding/json` is always in the woven dependency closure, so even a main package that imports only `strings` fails. It failed on 7/7 real targets; the phase-3 check was a one-package reproducer, and the 7-target matrix was not repeated. `GOEXPERIMENT=nojsonv2` and Go 1.26.6 both build.
- **Repro:** `evidence/fx-base-test-127-F1/build127-default.txt`. Command: `GOTOOLCHAIN=local go tool orchestrion go build -o /dev/null ./repro`.
- **Fix:** route the Decoder field access through `!goexperiment.jsonv2` build-tagged helpers; on JSON v2, drop Decoder propagation (safe miss).

### C2. After the JSON failure on Go 1.27, the Orchestrion job server balloons to 17-24 GiB RSS. Critical, CONFIRMED
- **Location:** trigger is `iast/encoding/json/orchestrion.yml:28-47`; the growth happens in orchestrion@23afa71 `internal/jobserver/nbt/nbt.go:161-162,252-253`, `internal/toolexec/aspect/oncompile.go:174`, and `internal/jobserver/server.go:109`.
- **Ids:** hooks-compile-matrix-F6.
- **Phase 3:** `phase3/fx-base-test-127-F1.json`.
- **Mechanism:** x/exp reached 18.3 GB, then 22.3 GiB (kill-switch); phase 3 reached 24.1 GB on a one-file JSON-free program vs 0.43 GB with `nojsonv2`, ending in `nats: maximum payload exceeded` (host/CI OOM). Not independently proven: exact x/exp figures, the user's ~40 GB process, the allocation mechanism.
- **Repro:** `evidence/fx-base-test-127-F1/build127-default.txt`, and `evidence/hooks-compile-matrix/mem/x-exp.woven-iast-127.time`. Command: `/usr/bin/time -l go tool orchestrion go build -o /dev/null ./repro`.
- **Fix:** C1 removes the trigger. Separately, file an upstream Orchestrion bug to bound the size of error payloads and job-server state.

### C3. A released Orchestrion cannot load the aspects, and the pin is an unmerged PR. Critical, CONFIRMED
- **Location:** `go.mod:14` and `iast/propagation/orchestrion.yml:21`.
- **Ids:** hooks-compile-matrix-F1 (Critical), hooks-orchestrion-dep-F5 (Medium, reviewer-reported), light-deps-license-F1 (High->Info).
- **Phase 3:** `phase3/fx-hooks-compile-matrix-F1.json`, `phase3/fx-light-deps-license-F1.json`.
- **Mechanism:** `v1.12.2-0.20260828141217-23afa71d6dcb` is a prerelease of v1.12.2, so minimal version selection prefers any released v1.12.2+. None of those releases contain `string-concat`/`slice-expression`/`type-conversion`. dd-trace-go `orchestrion/all/v2` v2.11.0-rc.1 requires v1.13.0, and `go mod tidy` picks it silently. The build then fails at configuration load with `unknown injection point type "string-concat"`. Forcing the pin downgrades or removes `orchestrion/all`. The pinned commit is from Orchestrion PR #881, which is unmerged with changes requested, so it gets no fixes (see C4-C8 and H4).
- **Artifacts disagree:** light-deps-license-F1 went to Info (documented release prerequisite; a program keeping the pin builds); fx-hooks-compile-matrix-F1 keeps Critical (MVS is the default outcome; prerequisite only in internal plans). Different triggers, so compatible.
- **Repro:** `evidence/fx-hooks-compile-matrix-F1/repro-released-v1.13.0.go1.26.6.log`. Command: `go mod tidy && go tool orchestrion go build -o /dev/null .` in `app-with-orchestrion-all`.
- **Fix:** require an Orchestrion release containing the join points plus the C4-C8/H4 fixes before shipping.

### C4. Import-free packages crash the weaver (`assignment to entry in nil map`). Critical, CONFIRMED
- **Location:** `iast/propagation/orchestrion.yml:13-31`; orchestrion@23afa71 `internal/toolexec/aspect/oncompile.go:195` and `internal/toolexec/importcfg/importcfg.go:52-83`.
- **Ids:** hooks-yml-operators-F3, hooks-orchestrion-dep-F3, hooks-compile-matrix-F3.
- **Phase 3:** `phase3/fx-hooks-yml-operators-F3.json`, `phase3/fx-hooks-orchestrion-dep-F3.json`, `phase3/fx-hooks-compile-matrix-F3.json`.
- **Mechanism:** `importcfg.parse` allocates `PackageFile` only when it sees `packagefile` lines. A root package with no imports has none. `OnCompile` then writes the injected `iast/propagation` import into the nil map. One non-constant concat, a slice, or a `[]byte->string` conversion in such a package (buildinfo- and textutil-style helpers) is enough, on Go 1.26.6 and on Go 1.27 with nojsonv2. Correction from phase 3: `string->[]byte` does not trigger it, because it is not instrumented. The bug is still present on Orchestrion origin/main and v1.13.0 (`:212`).
- **Repro:** `evidence/fx-hooks-orchestrion-dep-F3/run-output.txt` and `evidence/fx-hooks-compile-matrix-F3/woven-build-go1266.txt`. Command: `go tool orchestrion go build ./cmd/app`.
- **Fix:** upstream, initialize `PackageFile` in `importcfg.parse` (or guard at `oncompile.go:195`), then repin.

### C5. Integral float or complex slice bounds stop compiling. Critical, CONFIRMED
- **Location:** orchestrion@23afa71 `internal/injector/aspect/join/slice_expression.go:69-77`; `iast/propagation/orchestrion.yml:360-370,389`; `iast/propagation/operators.go:13-15`.
- **Ids:** hooks-yml-operators-F2, hooks-orchestrion-dep-F2.
- **Phase 3:** `phase3/fx-hooks-yml-operators-F2.json`, `phase3/fx-hooks-orchestrion-dep-F2.json`.
- **Mechanism:** go/types has already contextualized `s[:1e3]`, `b[0:2.0]` and `s[complex(1,0):3]` to `int`, so the matcher's UntypedFloat/UntypedComplex exclusion never fires. The template splices the raw constant into a generic helper constrained to `integer`, which infers `float64`/`complex128`. The error is `<generated>:1: float64 does not satisfy integer` at customer lines.
- **Repro:** `evidence/fx-hooks-yml-operators-F2/woven-go1266.txt`. Command: `go tool orchestrion go test ./reviewf2`.
- **Fix:** in the matcher, exclude bounds whose `constant.Value.Kind()` is Float or Complex. An alternative is to emit an explicit `int(...)` conversion for constant bounds.

### C6. Method expressions match pointer method-call advice and fail to compile. Critical, CONFIRMED
- **Location:** orchestrion@23afa71 `internal/injector/aspect/join/method_call.go` `Matches`. On the dd-iast-go side, all 16 pointer-only writer aspects, `iast/propagation/orchestrion.yml:1057-1507`, plus the Replacer aspect at `:1521-1535`.
- **Ids:** hooks-yml-strings-F1, hooks-fidelity-bytes-F1.
- **Phase 3:** `phase3/fx-hooks-yml-strings-F1.json` (covers both ids).
- **Mechanism:** `Matches` resolves `selector.X` through `typeInfo.Types` without checking `IsType()`. So `(*bytes.Buffer).WriteString(&b, s)` is treated as a call on a value, and the template emits `BufferWriteString((*bytes.Buffer), &b)`, which fails with `(type) is not an expression`.
- **Repro:** `evidence/fx-hooks-yml-strings-F1/woven-go1.26.6.txt`. Command: `go tool orchestrion go test ./zzfx/...`.
- **Fix:** upstream, reject a match when `typeInfo.Types[selector.X].IsType()`.

### C7. Operator advice evaluates operands that Go leaves unevaluated. Critical, CONFIRMED (phase-3 severity split: Critical vs High)
- **Location:** `iast/propagation/orchestrion.yml:12-31,343-370`; orchestrion@23afa71 `join/string_concat.go:83-95` and `join/slice_expression.go:63-94`.
- **Ids:** hooks-yml-operators-F1, hooks-orchestrion-dep-F1.
- **Phase 3:** `phase3/fx-hooks-yml-operators-F1.json` (Critical), `phase3/fx-hooks-orchestrion-dep-F1.json` (downgraded to High as "uncommon construct").
- **Mechanism:** wrapping a concat or slice inside `len`/`cap` of an array, an array-pointer conversion, or `for range [1]string{s[:hi]}` inserts a function call. That forces evaluation where the spec says none happens. Out-of-range bounds then panic at runtime (4 shapes), even with IAST disabled, and constant or array-length contexts stop compiling. `unsafe.Sizeof` is unaffected.
- **Repro:** `evidence/fx-hooks-yml-operators-F1/go1266-woven-runtime.txt` and `evidence/fx-hooks-orchestrion-dep-F1/run-results.txt`. Command: `DD_IAST_ENABLED=false go tool orchestrion go test -v ./reviewfxoperators ./reviewfxoperators/constantlen`.
- **Fix:** do not match concat or slice join points under a `len`/`cap`/`range` operand of array or array-pointer type that has no calls or receives (the spec's "not evaluated" case).
- This entry is counted as Critical because the two falsifiers disagree and the higher confirmed severity is kept.

### C8. Root-module plugin and c-shared builds fail. Critical, CONFIRMED (root cause corrected)
- **Location:** `iast/database/sql/orchestrion.yml:16-31` (finder); per phase 3, the real cause is Orchestrion OnLink.
- **Ids:** hooks-scope-root-F1 (related: life-bridges-F4, Info).
- **Phase 3:** `phase3/fx-hooks-scope-root-F1.json`.
- **Mechanism:** the finder blamed bootstrap selectors matching plugin `main` (they do match, contradicting `README.md:88-90`), but phase 3 shows plugins **without** `main`, c-shared, and dd-trace-go's own main aspect fail too: OnLink resolves link deps from `os.Getwd()`, which cmd/go sets to `$WORK/b001/exe` (nats max-payload / GOPATH-mode errors). Excluding plugins from bootstraps is insufficient.
- **Repro:** `evidence/fx-hooks-scope-root-F1/summary.md` and `repro.sh`. Command: `go tool orchestrion go build -buildmode=plugin -o ../out/s1.so ./cmd/pluginmain`.
- **Fix:** upstream, resolve link deps from the module root, not cwd; until then document plugin/c-shared as unsupported.

### H1. Reset or reused reader wrappers keep the original owner's binding (cross-request taint). High, CONFIRMED
- **Location:** `iast/bufio/orchestrion.yml:15-34`; `internal/taint/request/reader.go:27-39,67-88`; `internal/taint/store/binding.go:95-108,166-203`.
- **Ids:** hooks-io-bufio-F1 (related: hooks-io-bufio-F3 Info, store-binding-F1 High->Low address-only keying).
- **Phase 3:** `phase3/fx-hooks-io-bufio-F1.json`.
- **Mechanism:** bindings are keyed by wrapper address, set once; `bufio.Reader.Reset` and `LimitedReader.R` reassignment are unhooked. A reader over `r.Body` Reset onto a constant yields SQL_INJECTION with the constant as body source; a pooled reader reused by request B publishes B's clean query as A's source. Ends at owner finish. Sub-claim refuted: sampled-out requests do not report (only scope-less contexts do).
- **Repro:** `evidence/fx-hooks-io-bufio-F1/e2e-go1.26.6.out.txt`. Command: `go tool orchestrion go test -run TestFX .` in `iast/integration/testapp`.
- **Fix:** hook `(*bufio.Reader).Reset` to unbind (or rebind to the new source). At `ReadAll`, validate that the binding still matches the wrapper's current underlying reader and drop it if not.

### H2. A `MultiReader` with any bound input taints the whole result. High, CONFIRMED
- **Location:** `iast/io/orchestrion.yml:46-68`; `internal/taint/request/reader.go:27-45,67-88,119-126`.
- **Ids:** hooks-io-bufio-F2 (Medium), life-lazy-reader-F2 (High; cross-part).
- **Phase 3:** `phase3/fx-life-lazy-reader-F2.json`.
- **Mechanism:** the result is bound if any of the first 8 inputs is bound, and `ReadAll` adopts the whole buffer as one `http.request.body` source. Trusted prefixes, other owners' bytes, and results from an empty-but-bound body become tainted. One run produced a single [0,16) range over `"trusted-attacker"`.
- **Repro:** `evidence/fx-life-lazy-reader-F2/go1.26.6.out.txt`. Command: `go tool orchestrion go test -race -run TestReviewFXMixedMultiReaderAttributesTrustedPrefixToRequestBody ./iast/net/http`.
- **Fix:** bind the MultiReader only when every input is bound to the same owner and reader; otherwise drop provenance as a safe miss. Update the enshrining test.

### H3. Woven operators allocate while IAST is inactive. High, CONFIRMED
- **Location:** `iast/propagation/operators.go:18-26,198-204`; `iast/propagation/orchestrion.yml:23-31,327-341`; `internal/taint/propagation/operator_concat.go:9-79`; `internal/taint/propagation/string_exact.go:56`.
- **Ids:** hooks-yml-operators-F4, perf-escape-F1 (High), hooks-compile-matrix-F4, prop-concat-conv-json-F1, prop-concat-conv-json-F2, perf-escape-F2/F3/F4 (Medium), hooks-fidelity-strings-F3 (Info).
- **Phase 3:** `phase3/fx-hooks-yml-operators-F4.json`, `phase3/fx-perf-escape-F1.json`.
- **Mechanism:** the generic wrappers exceed the inlining budget (cost 131 vs 80). `BytesToString` computes `string(value)` before the `HasValues()` gate, so the result escapes. `copy()` into the local inputs array leaks concat operands. `len(a+b)`, concat comparisons and local `string(b)` each allocate 1/op against 0 natively, with `DD_IAST_ENABLED=false`. Breaks disabled-path allocation parity; woven x/exp/slog `TestTextHandlerAlloc` measures 11 allocs vs 0.
- **Repro:** `evidence/fx-hooks-yml-operators-F4/woven-go1266.txt`, `evidence/fx-perf-escape-F1/`, `evidence/hooks-compile-matrix/logs/x-exp.slogalloc-woven.log`. Command: `DD_IAST_ENABLED=false go tool orchestrion go test -v ./reviewf4`.
- **Fix:** in `BytesToString`, evaluate `string(value)` inside each branch. The hooks-fidelity-strings fix probe restores 0 allocs this way, but it showed that the same change *regresses* `Concat2`. Concat needs a separate fix: avoid copying operands into the local array (perf-escape-F3) and add an inlinable pre-gate (perf-escape-F2).

### H4. Core-type resolution drops valid intersected constraints (silent taint loss). High, CONFIRMED
- **Location:** orchestrion@23afa71 `internal/injector/typed/coretype.go:60-104` (`:93-95`); `iast/propagation/orchestrion.yml:12-31,343-405`.
- **Ids:** hooks-orchestrion-dep-F4.
- **Phase 3:** `phase3/fx-hooks-orchestrion-dep-F4.json`.
- **Mechanism:** `interfaceCoreType` returns nil at the first mixed embedded union, before it intersects the later terms. As a result, `interface{ ~string|~int; ~string }` and the `[]byte` analogue get no core type, and concat, string slice and byte slice all miss. Values are correct, but taint is lost. The `[T ~string]` control retains taint.
- **Repro:** `evidence/fx-hooks-orchestrion-dep-F4/run-results.txt`. Command: `go tool orchestrion go test -run 'TestF4IntersectedCoreTypeKeepsProvenance|TestReviewIntersectionCoreTypeRetainsProvenance' ./iast/propagation`.
- **Fix:** upstream, intersect all embedded terms before rejecting.

### H5. Buffer writer anchors retain unbounded caller allocations. High, CONFIRMED (documented trade-off; severity kept)
- **Location:** `iast/propagation/writer.go:213-216`; `internal/taint/store/writer.go:17-37,217-229`.
- **Ids:** hooks-yml-writers-F1; cross-part store-memory-bounds-F1 (Critical->Medium).
- **Phase 3:** `phase3/fx-hooks-yml-writers-F1.json`, `phase3/fx-store-memory-bounds-F1.json`.
- **Mechanism:** a small `Buffer` view over a large caller allocation is pinned by typed `Anchor` + receiver while the store charges `sizeClass(visible Capacity)`: 112 MiB retained after GC (~4.7x the 24 MiB envelope); 128 B charged vs 128 MiB retained. Released at owner finish.
- **Artifacts disagree:** both falsifiers note that `01-design-intent.md` / README:70-77 document this. fx-hooks-yml-writers-F1 keeps High because bounded anchor counts do not bound bytes. fx-store-memory-bounds-F1 (same interior-view mechanism plus bound readers) re-rates Medium because the memory is request-scoped and cannot accumulate.
- **Repro:** `evidence/fx-hooks-yml-writers-F1/`. Command: `go tool orchestrion go test -run TestFxBufferInteriorViewRetainsCallerAllocation ./iast/propagation`.
- **Fix:** cap retained anchor bytes per owner, charged by full backing capacity; drop provenance past the cap.

### H6. fmt wrappers taint constant output from `String`/`Format`/`Error`/`GoString`. High, CONFIRMED
- **Location:** `internal/taint/propagation/string_coarse.go:206-221` (`formatArgumentKey`).
- **Ids:** hooks-yml-fmt-strconv-url-F1, crash-diff-strings-F1, prop-string-coarse-F1.
- **Phase 3:** `phase3/fx-prop-string-coarse-F1.json`, `phase3/fx-crash-diff-strings-F1.json`.
- **Mechanism:** arguments are keyed by reflect Kind (String or `[]uint8`) and the receiver's backing, even though fmt prints named types through their methods. Attacker input mapped to the constant `AUDIT_OK` yields a fully tainted `SELECT ... WHERE level='AUDIT_OK'`, and a real SQL_INJECTION event is emitted.
- **Repro:** `evidence/fx-prop-string-coarse-F1/woven-go126.txt`. Command: build `./cmd/fx-coarse` woven and run `fx-coarse-126 stringer|formatter`.
- **Fix:** skip (drop taint for) arguments whose dynamic type implements `fmt.Formatter`, `fmt.Stringer`, `error` or `fmt.GoStringer` when the verb dispatches to that method.

### H7. fmt taints arguments whose bytes were never emitted. High, CONFIRMED
- **Location:** `internal/taint/propagation/string_coarse.go:115-145,175-197`.
- **Ids:** prop-semantics-parity-F2 (High; cross-part), hooks-yml-fmt-strconv-url-F4 (Low).
- **Phase 3:** `phase3/fx-prop-semantics-parity-F2.json`.
- **Mechanism:** every inspected argument coarsens the whole output. `%.0s`, `%T`, `%p` and index-skipped `%[2]s` emit none of the tainted bytes, yet the clean `SELECT 40 + 2 /*  */` is reported as SQLi.
- **Repro:** `evidence/fx-prop-semantics-parity-F2/woven_http_sql_go1.26.6.out.txt`. Command: `go tool orchestrion go test -run TestHTTPQuery_SprintfZeroPrecision_reportsCleanSQL .` in testapp.
- **Fix:** skip taint for arguments consumed by `%T`, `%p`, zero precision or skipped indexes. Conservatively, drop taint whenever the format string uses precision or explicit indexes.

### H8. fmt misses tainted data nested in structs, slices, maps, pointers or wrappers. High, CONFIRMED
- **Location:** `internal/taint/propagation/string_coarse.go:115-145,203-219`; `README.md:32`.
- **Ids:** prop-semantics-parity-F1 (High; cross-part), hooks-yml-fmt-strconv-url-F2 (Medium).
- **Phase 3:** `phase3/fx-prop-semantics-parity-F1.json`.
- **Mechanism:** only top-level string and `[]byte` operands are inspected, so a tainted field in a formatted struct produces an untainted query and a missed SQLi. The README row implies full `fmt.Sprint*` support.
- **Repro:** `evidence/fx-prop-semantics-parity-F1/review_f1_test.go`. Command: `go tool orchestrion go test -run '^TestReviewF1_' ./iast/propagation`.
- **Fix (minimal):** document the limitation in the README row that only direct string and `[]byte` operands propagate. Bounded one-level inspection is optional.

### M1. Hook bridges do not shield internal callback panics. Medium, CONFIRMED (downgraded)
- **Location:** `internal/taint/iobridge/bridge.go:30-43`, `internal/taint/writerbridge/bridge.go:75-95`, `iast/net/http/orchestrion.yml:131-158`.
- **Ids:** hooks-panic-safety-F1/F2/F3 (Critical->Medium), life-bridges-F1 (Medium), crash-panic-static-F2 (Low).
- **Phase 3:** `phase3/fx-hooks-panic-safety-F1.json`, `-F2.json`, `-F3.json`.
- **Mechanism:** fault injection: an IAST panic escapes reader wrappers and replaces an in-flight host panic; an invalidation-callback panic aborts the host Buffer write and leaks `lifecycleMu`; the deferred ParseForm callback replaces a customer panic. No natural trigger found (adversarial readers, 16x300 stress).
- **Repro:** `evidence/fx-hooks-panic-safety-F{1,2}/woven-go1.26.6*.out.txt`, `evidence/fx-hooks-panic-safety-F3/independent_deferred_panic_test.go`.
- **Fix:** wrap each bridge dispatch in a `defer recover()` scoped to the callback only, never to host code, and release locks with `defer`.

### M2. Coarse fmt/url/strconv output keeps only the first source and spans the whole output. Medium, reviewer-reported
- **Location:** `internal/taint/propagation/string_coarse.go:113-203`, `propagation.go:721-736`, `README.md:32`.
- **Ids:** hooks-yml-fmt-strconv-url-F3.
- **Mechanism:** Sprintf with two sources yields one [0,len) range from the first source. The coarse behavior is documented only in plans.
- **Repro:** `evidence/hooks-yml-fmt-strconv-url/run_woven_go1.26.6.out.txt` (`-run TestReviewFmtTwoSources`).
- **Fix:** document coarse, first-source behavior in the README.

### M3. Lazy string iterators allocate a wrapper with no active owner. Medium, CONFIRMED (High->Medium)
- **Location:** `iast/propagation/strings.go:75-119`.
- **Ids:** perf-hotpath-F1 (cross-part).
- **Phase 3:** `phase3/fx-perf-hotpath-F1.json`.
- **Mechanism:** each escaping `SplitSeq`-style iterator costs +32 B and 1 alloc; immediate `for range` use stays at 0. This matches hooks-fidelity-strings' allocation-parity result.
- **Repro:** `evidence/fx-perf-hotpath-F1/woven-test-1.26.6.txt`.
- **Fix:** return the native iterator when `HasValues()` is false.

### M4. README leaves the "application root" module boundary ambiguous. Medium, reviewer-reported
- **Location:** `README.md:38-39`.
- **Ids:** hooks-scope-root-F2.
- **Mechanism:** direct propagation covers only the module resolved from the cwd. `go.work` siblings and `replace`d modules stay uninstrumented, including under `-mod=vendor`.
- **Repro:** `evidence/hooks-scope-root/scope-matrix.md`.
- **Fix:** state the single-module boundary in the README.

### 2b. Cross-part Critical/High findings rooted in this part's code (counted in their owning parts)

| Root cause | Ids | Sev (phase 3) | Location | Verdict file |
|---|---|---|---|---|
| Weak-crypto hooks panic in package init (dies before main) | crash-panic-static-F1 | Critical | `iast/crypto/{hash,cipher}/orchestrion.yml` | fx-crash-panic-static-F1 |
| Header map replacement loses caller mutations | sink-http-sources-F1 | Critical | `iast/net/http/orchestrion.yml:109-119` | fx-sink-http-sources-F1 |
| ParseForm advice re-stores Form on every call (race) | life-lazy-reader-F1 (Critical), crash-race-hunt-F1 (Critical->High) | Critical/High | `iast/net/http/orchestrion.yml:152-162` | fx-life-lazy-reader-F1, fx-crash-race-hunt-F1 |
| Unanchored Builder view ABA (stale/cross-request taint) | crash-diff-bytes-F1, store-writer-F2, store-identity-gc-F1, life-cross-request-F2 | High | `iast/propagation/writer.go:202-205` | fx-crash-diff-bytes-F1, fx-store-identity-gc-F1 |
| Buffer view matched across receivers | life-cross-request-F3 | High | `internal/taint/store/writer.go:448-462`, `iast/propagation/writer.go:190-217` | fx-life-cross-request-F3 |
| Writer wrappers gate on any-request-active (~50x) | perf-hotpath-F2 | High | `iast/propagation/writer.go:29-35,104-129` | fx-perf-hotpath-F2 |
| Buffer invalidation hook scans owners per mutation | crash-stress-app-F2 (same gate pattern as hooks-io-bufio-F4) | High | `iast/propagation/orchestrion.yml:1553-1595` | fx-crash-stress-app-F2 |
| `strings.Map` keeps taint after deleting tainted runes | prop-semantics-parity-F3 | High | `iast/propagation/coarse.go:36-38` | fx-prop-semantics-parity-F3 |
| Tainted `Cmd.Path` not evidence | sink-exec-F1 | High | `iast/os/exec/orchestrion.yml:59-78` | fx-sink-exec-F1 |
| Disconnected stalled handlers keep admission slots | life-admission-F1 | **DISPUTED** (REFUTED once; re-run CONFIRMED High, overwrote file) | `iast/net/http/orchestrion.yml:27-33` | fx-life-admission-F1 |

## 3. Low / Info and code-quality notes
- hooks-fidelity-bytes-F2 (Low): tainted `Builder.String` returns `strings.Clone` (up to 64 KiB). Repeated `String()` in a loop becomes O(n^2). Documented.
- hooks-fidelity-bytes-F3 (Low): Go 1.27 `bytes`/`strings.CutLast` are unhooked, which contradicts README's `Cut*` claim (safe miss). Similar: prop-unicode-F3 (Low), `To*Special`/`Title` are unwoven.
- hooks-yml-fmt-strconv-url-F5 (Low): `DroppedPropagation` fires on every Sprint* with more than 15/16 args, even when the call is clean.
- hooks-fidelity-strings-F1 (Low): out-of-range sub-word constant index panic *text* differs from native. The wrapper's text is the correct one.
- hooks-fidelity-strings-F2 (Info): single-element tainted `Join` with a separator clones instead of aliasing.
- hooks-io-bufio-F3 (Info): Reset-initialized pooled readers, `NopCloser`, body-restore and bufio `ReadString`/`Scanner` lose taint, undocumented. hooks-io-bufio-F4 (Info): reader hooks scan 64 owners process-wide while any request is sampled; gate on a live-binding counter.
- hooks-yml-fmt-strconv-url-F6 (Info): `Fprintf` into a tracked Builder drops existing provenance.
- Info: hooks-compile-matrix-F5 (aggregate import silently enables tracer auto-start); perf-escape-F8 (woven builds reject `-gcflags=-m=2`); perf-binary-compile-F3 / base-bootstrap-F1 (63 weave sites in every binary, ~12.7x larger); sink-systemtests-F10, life-bridges-F4 (root-only / root-main-only scoping).

## 4. Verified correct
- Go 1.26.6: all real targets build woven (net/http, gin, gorilla+grpc+sqlite, 10 system-tests weblogs, samber/lo, 34 x/exp pkgs, cgo sqlite3); woven suites match plain; go-dvwa responses md5-identical, 2 SQLi + 1 CMDi emitted; RSS <=1.33 GiB. (hooks-compile-matrix)
- 420k byte-op and 288k writer-sequence differential comparisons per toolchain (1.26.6/1.27.0), 0 failures; no input mutation; identical nil/copy/Grow(-1) panics; woven call-site forms byte-identical; `-race` clean. (hooks-fidelity-bytes)
- Strings/fmt wrappers: single evaluation before taint work, identical stdlib panics and callback order, iterator parity, native error identity; `reflect` inspection never re-invokes user methods; `URL.Query` advice typed-nil safe and bounded. (hooks-fidelity-strings, hooks-yml-strings, hooks-yml-fmt-strconv-url)
- Operators: once-only evaluation order, 35 slice-panic comparisons identical, exact offsets through slice->concat->conversion, all 2-16 arities pass. (hooks-yml-operators, hooks-orchestrion-dep)
- io/bufio: 12 reader shapes identical; `ReadAll` adoption invariant holds on 1.26.6/1.27.0; bindings bounded (8/owner, 256 total, 8 inputs, 4096 bufio); `-race` ok. (hooks-io-bufio)
- bytes call sites keep alias offsets and provenance (hooks-yml-bytes, no findings); Buffer `Backing` is numeric-only, checkptr=2 clean (hooks-yml-writers); native panic type/value preserved, HTTP permit reused after unwinding (hooks-panic-safety); root filter, test-main exclusion, loud bare-`go.work` failure (hooks-scope-root).

## 5. Coverage gaps
- Go 1.27 runtime almost entirely unverified (C1 blocks woven builds; C5/C7 phase-3 1.27 checks blocked).
- No 32-bit, cross-compile, `-race` or `-cover` woven compile matrix; no large (>40k lines) or `go.work` customer builds beyond scope-root fixtures; plugin runtime unreachable.
- Panic boundaries proven by fault injection only; JSON/SQL/exec/crypto panic paths traced statically.
- No woven randomized differential for native Buffer invalidation hooks; no `sourceMu.TryLock` contention check on `ReadAll`.
- No wall-clock latency data (H3 rests on allocation counts); no full Orchestrion suite, overlapping third-party aspects, or >16-deep constraints; C2 job-server mechanism unproven.

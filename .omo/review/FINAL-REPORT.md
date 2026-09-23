# dd-iast-go taint tracking: final review report

Branch `romain.marcadier/taint-tracking` @ 2e23b46. Paths are relative to [`.omo/review/`](https://github.com/DataDog/dd-iast-go/tree/eliottness/taint-tracking-review/.omo/review). Phase-3 adjusted severity is authoritative for every High and Critical.

## 1. Executive summary

**Verdict: NOT ready for any customer exposure.** After cross-part root-cause dedup there are **15 Critical, 30 High (29 CONFIRMED + 1 DISPUTED) and 49 Medium** findings. Independent phase-3 falsifiers confirmed all 15 Criticals with reproducers. Most are reachable in the default configuration, and several also with IAST disabled.

Top problems:
1. **Valid customer builds fail.** Every woven Go 1.27 build breaks, with a 24.1 GB peak RSS (C1). A released Orchestrion drops the unmerged pin through MVS (C2). Import-free packages, float slice bounds, method expressions and plugin builds also break (C3, C5-C7).
2. **The host crashes.** Crypto calls in `init` panic before `main` (C8). Operator advice evaluates operands that Go leaves unevaluated, which panics even with IAST disabled (C4).
3. **Secrets leak unredacted.** SQL comments (C9), a q-quote lexer desync (C10), and a redaction pattern that can equal the secret (C11).
4. **Host behavior changes and data races.** Header map (C12), ParseForm (C13), `SetMetaStruct` on a finished span (C14), and slot index (C15).
5. **Cross-request taint bleed and false SQLi.** Writer views (H1, H2), pooled bodies and readers (H3, H4), stale owner handles (H5), and fmt (H8).
6. **Silent loss of findings.** Sampled-out requests starve the 2-slot annotation store (H18).
7. **Hot-path cost.** Process-wide writer scans (+10,675%, H25), report work done before its gates (H26), and allocations with IAST disabled (H27).

**Solid:**
- Range algebra: about 128M fuzz execs, no crasher.
- Wrapped stdlib results are byte-identical to plain Go, across millions of differential cases.
- Memory is bounded and released: no leak over about 820k requests.
- Permit accounting and the lock graph (acyclic, try-lock) are sound.
- Config never panics.
- The kill switch restores allocation counts (except H27).
- 39/39 supported SQLi/CMDi flows are detected exactly.
- The Go 1.26.6 test and race baselines are green.

## 2. Review method

- **Phase 1:** 12 nodes: 5 baselines, 2 maps (synthesized into `00-architecture.md` and `01-design-intent.md`), and 5 research nodes.
- **Phase 2:** 92 lanes (12 each for crash, hooks, life, prop, sink and store; 10 each for light and perf). They produced 290 raw findings: 32 Critical, 58 High, 78 Medium, 79 Low, 43 Info.
- **Phase 3:** 78 falsifier files holding 91 entries, one per High and Critical finding (including `base-test-127-F1`).
  - 90 were CONFIRMED and 1 REFUTED ([perf-contention-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-contention.md), to Info).
  - Downgraded to Medium: [hooks-panic-safety-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-panic-safety.md)/F2/F3, [perf-algorithmic-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-algorithmic.md), [perf-hotpath-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-hotpath.md), [sink-evidence-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-evidence.md), [sink-parity-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-parity.md), [sink-redaction-source-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-redaction-source.md), [store-lookup-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-lookup.md), [store-memory-bounds-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-memory-bounds.md).
  - Downgraded to Low: [store-binding-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-binding.md). To Info: [light-deps-license-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-deps-license.md).
  - Downgraded from Critical to High: [crash-race-hunt-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-race-hunt.md), [hooks-orchestrion-dep-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-orchestrion-dep.md), [store-memory-bounds-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-memory-bounds.md).
- **Phase 4:** 10 reducers (8 part reports, a perf verdict and a research comparison), then this report.
- **Toolchains:** go1.26.6 (go.mod target) and go1.27.0 (machine default), plus a go1.25.9 guard check. Orchestrion pinned at 23afa71 (unmerged PR #881). darwin/arm64 only.
- **Benchmarks:** [`benchmarks/overhead`](https://github.com/DataDog/dd-iast-go/tree/eliottness/taint-tracking-review/benchmarks/overhead) control vs woven at s100 (count=10) and s0 (count=6), plus package micro-benchmarks ([`evidence/bench/`](https://github.com/DataDog/dd-iast-go/tree/eliottness/taint-tracking-review/.omo/review/evidence/bench)).
- **Limits:**
  - The machine was shared (load average above 200; a CPU control varied 9x), so most perf claims rest on allocation counts or profiles. perf-verdict's "quiet machine" claim does not appear in [`bench/overhead-s100/metadata.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/bench/overhead-s100/metadata.txt).
  - One verdict is DISPUTED (H30), and the refutation was overwritten.
  - Go 1.27 woven runtime behavior is untested, because C1 blocks the builds.
  - End-to-end runs forced 100% sampling. There was no real database or agent, no `-asan`, and fuzzing was single-goroutine.

## 3. Baseline results

| Check | Result | Note |
|---|---|---|
| Tests go1.26.6 | PASS | Root woven: 36 pass, 0 skip. Plain: 36 pass, 77 expected skips. 4 nested modules pass. |
| Tests go1.27.0 | **FAIL** | Woven `encoding/json`: `dec.r`/`dec.d undefined` (C1). Plain fails only [`iast/encoding/json/json_test.go:40`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/encoding/json/json_test.go#L40). |
| Race | PASS | Plain `-count=3`, woven `-count=2`, 3 testapps. Later nodes found races on untested paths (C13-C15). |
| go vet | PASS | All 5 modules. |
| gofmt | PASS | Clean. |
| checklocks | PASS | The store has no `+checklocks:` annotations, so it verifies nothing there ([store-concurrency-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-concurrency.md)). |
| golangci-lint | FAIL (non-blocking) | 89 diagnostics. 2 are in production code (unparam, Low): [`store/root.go:323`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/root.go#L323), [`store/writer.go:498`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/writer.go#L498). |
| staticcheck | FAIL (non-blocking) | 8 diagnostics, all test-only. |
| govulncheck | PASS | No vulnerabilities. |
| Bootstrap symbols | PASS | All present. Binaries are 12.7x larger (+20.4 MB). |

## 4. Findings (deduplicated by root cause)

Each entry gives its status and the parts it touches, then the location, ids, phase-3 verdict file(s), evidence and fix. "reviewer-reported" means Medium or lower with no phase-3 check.

### Critical (15)

**C1. Go 1.27 (JSON v2) breaks every woven build and balloons the Orchestrion job server to 17-24 GB.** CONFIRMED. Parts: hooks, sink, perf, baseline.
- **Location:** [`iast/encoding/json/orchestrion.yml:28-47`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/encoding/json/orchestrion.yml#L28-L47) (`recv.r`/`&recv.d` at :41). The growth happens in orchestrion [`internal/jobserver/nbt/nbt.go:161-162,252-253`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/jobserver/nbt/nbt.go#L161-L162).
- **Ids:** [base-test-127-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase1/base-test-127.md), [hooks-compile-matrix-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-compile-matrix.md), [hooks-compile-matrix-F6](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-compile-matrix.md), [sink-json-sources-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-json-sources.md).
- **Phase 3:** [fx-base-test-127-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-base-test-127-F1.md), [fx-sink-json-sources-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-sink-json-sources-F1.md).
- **Details:** even a main that imports only `strings` fails, ending in `nats: maximum payload exceeded` (426 MB with nojsonv2).
- **Evidence:** [`evidence/fx-base-test-127-F1/build127-default.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-base-test-127-F1/build127-default.txt).
- **Fix:** gate the Decoder advice with `!goexperiment.jsonv2`, add woven CI builds for every toolchain, and file an upstream bug to bound job-server payloads.

**C2. A released Orchestrion cannot load the aspects, and the pin is an unmerged PR.** CONFIRMED. Parts: hooks, light.
- **Location:** `go.mod:14`, [`iast/propagation/orchestrion.yml:21`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/orchestrion.yml#L21).
- **Ids:** [hooks-compile-matrix-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-compile-matrix.md), [light-deps-license-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-deps-license.md), [hooks-orchestrion-dep-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-orchestrion-dep.md).
- **Phase 3:** [fx-hooks-compile-matrix-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-compile-matrix-F1.md) (Critical). [fx-light-deps-license-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-light-deps-license-F1.md) says Info (a documented prerequisite: keeping the pin builds). The triggers differ, so both can hold.
- **Details:** dd-trace-go `orchestrion/all/v2` v2.11.0-rc.1 requires v1.13.0, and MVS picks it, failing with `unknown injection point type "string-concat"`.
- **Evidence:** [`evidence/fx-hooks-compile-matrix-F1/repro-released-v1.13.0.go1.26.6.log`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-compile-matrix-F1/repro-released-v1.13.0.go1.26.6.log).
- **Fix:** depend on an Orchestrion release with the join points plus the C3-C7 and H14 fixes, and repin all modules.

**C3. Import-free packages crash the weaver (`assignment to entry in nil map`).** CONFIRMED. Parts: hooks.
- **Location:** orchestrion [`internal/toolexec/aspect/oncompile.go:195`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/toolexec/aspect/oncompile.go#L195), [`importcfg/importcfg.go:52-83`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/toolexec/importcfg/importcfg.go#L52-L83), triggered by [`iast/propagation/orchestrion.yml:13-31`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/orchestrion.yml#L13-L31).
- **Ids:** [hooks-yml-operators-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-operators.md), [hooks-orchestrion-dep-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-orchestrion-dep.md), [hooks-compile-matrix-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-compile-matrix.md).
- **Phase 3:** [fx-hooks-yml-operators-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-yml-operators-F3.md), [fx-hooks-orchestrion-dep-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-orchestrion-dep-F3.md), [fx-hooks-compile-matrix-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-compile-matrix-F3.md).
- **Details:** still present in Orchestrion v1.13.0.
- **Evidence:** [`evidence/fx-hooks-orchestrion-dep-F3/run-output.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-orchestrion-dep-F3/run-output.txt).
- **Fix:** upstream, initialize `PackageFile` in `importcfg.parse`, then repin.

**C4. Operator advice evaluates operands Go leaves unevaluated, causing runtime panics and compile breaks even with IAST disabled.** CONFIRMED. Parts: hooks.
- **Location:** [`iast/propagation/orchestrion.yml:12-31,343-370`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/orchestrion.yml#L12-L31); orchestrion [`join/string_concat.go:83-95`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/injector/aspect/join/string_concat.go#L83-L95), [`join/slice_expression.go:63-94`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/injector/aspect/join/slice_expression.go#L63-L94).
- **Ids:** [hooks-yml-operators-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-operators.md), [hooks-orchestrion-dep-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-orchestrion-dep.md).
- **Phase 3:** the falsifiers **disagree**: [fx-hooks-yml-operators-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-yml-operators-F1.md) says Critical, [fx-hooks-orchestrion-dep-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-orchestrion-dep-F1.md) says High. Critical is kept, because the host panics with IAST off.
- **Details:** a concat or slice inside array `len`/`cap`, or inside `range [1]string{s[:hi]}`, becomes a call.
- **Evidence:** [`evidence/fx-hooks-yml-operators-F1/go1266-woven-runtime.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-yml-operators-F1/go1266-woven-runtime.txt).
- **Fix:** skip join points under unevaluated `len`/`cap`/`range` operands of array type.

**C5. Integral float/complex slice bounds (`s[:1e3]`) stop compiling.** CONFIRMED. Parts: hooks.
- **Location:** orchestrion [`join/slice_expression.go:69-77`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/injector/aspect/join/slice_expression.go#L69-L77), [`iast/propagation/operators.go:13-15`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/operators.go#L13-L15).
- **Ids:** [hooks-yml-operators-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-operators.md), [hooks-orchestrion-dep-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-orchestrion-dep.md).
- **Phase 3:** [fx-hooks-yml-operators-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-yml-operators-F2.md), [fx-hooks-orchestrion-dep-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-orchestrion-dep-F2.md).
- **Evidence:** [`evidence/fx-hooks-yml-operators-F2/woven-go1266.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-yml-operators-F2/woven-go1266.txt).
- **Fix:** exclude Float/Complex constant bounds, or emit `int(...)`.

**C6. Method expressions match pointer method-call advice and fail to compile.** CONFIRMED. Parts: hooks.
- **Location:** orchestrion [`join/method_call.go`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/injector/aspect/join/method_call.go) `Matches`; [`iast/propagation/orchestrion.yml:1057-1535`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/orchestrion.yml#L1057-L1535).
- **Ids:** [hooks-yml-strings-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-strings.md), [hooks-fidelity-bytes-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-fidelity-bytes.md).
- **Phase 3:** [fx-hooks-yml-strings-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-yml-strings-F1.md).
- **Evidence:** [`evidence/fx-hooks-yml-strings-F1/woven-go1.26.6.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-yml-strings-F1/woven-go1.26.6.txt).
- **Fix:** reject the match when `typeInfo.Types[selector.X].IsType()`.

**C7. Root-module plugin and c-shared builds fail.** CONFIRMED (phase 3 corrected the root cause). Parts: hooks, sink.
- **Location:** found at [`iast/database/sql/orchestrion.yml:16-31`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/database/sql/orchestrion.yml#L16-L31), but the cause is Orchestrion OnLink resolving link deps from `os.Getwd()` (`$WORK/b001/exe`).
- **Ids:** [hooks-scope-root-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-scope-root.md).
- **Phase 3:** [fx-hooks-scope-root-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-scope-root-F1.md).
- **Evidence:** [`evidence/fx-hooks-scope-root-F1/summary.md`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-scope-root-F1/summary.md).
- **Fix:** upstream, resolve from the module root. Meanwhile, document these build modes as unsupported and fix README:88-90.

**C8. Weak-crypto hooks panic in package init, before `main`.** CONFIRMED. Parts: crash, life, sink, hooks.
- **Location:** `iast/crypto/{hash,cipher}/orchestrion.yml` (linkname), [`internal/vulnerability/report.go:37-52`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/vulnerability/report.go#L37-L52), [`internal/spans/vulnerability.go:18`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/vulnerability.go#L18).
- **Ids:** [crash-panic-static-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-panic-static.md).
- **Phase 3:** [fx-crash-panic-static-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-panic-static-F1.md).
- **Details:** `links:` adds no import, so a customer `init()` that hashes reaches `tracer.StartSpan`'s nil type assertion (exit 2) under the default config.
- **Evidence:** [`evidence/fx-crash-panic-static-F1/initcrash2-default.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-crash-panic-static-F1/initcrash2-default.out.txt).
- **Fix:** route reports through an `atomic.Pointer` callback registered in the crypto package's `init()`, add `recover`, and add a woven init-time `md5.Sum` test.

**C9. SQL comment bodies are never redacted.** CONFIRMED. Parts: crash, sink.
- **Location:** [`internal/taint/redaction/sql.go:83-100`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/redaction/sql.go#L83-L100) (verified at HEAD); `analyzer_test.go:30` enshrines the leak.
- **Ids:** [crash-hostile-input-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-hostile-input.md), [sink-e2e-truepos-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-e2e-truepos.md), [sink-redaction-source-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-redaction-source.md), [crash-fuzz-redaction-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-fuzz-redaction.md).
- **Phase 3:** [fx-crash-hostile-input-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-hostile-input-F1.md), [fx-sink-e2e-truepos-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-sink-e2e-truepos-F1.md).
- **Details:** after `admin' --`, trailing application literals such as a password hash ship verbatim.
- **Evidence:** [`evidence/fx-sink-e2e-truepos-F1/woven-output.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-sink-e2e-truepos-F1/woven-output.txt).
- **Fix:** redact comment bodies in every dialect, fail closed on unclassifiable comments, and use the shared corpus.

**C10. The context-free Oracle q-quote pre-scan desynchronizes all 6 dialect lexers.** CONFIRMED. Parts: crash, sink.
- **Location:** [`internal/taint/redaction/sql.go:27-43,108-151`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/redaction/sql.go#L27-L43).
- **Ids:** [crash-fuzz-redaction-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-fuzz-redaction.md), [sink-redaction-sql-cmd-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-redaction-sql-cmd.md). Folded in: [crash-fuzz-redaction-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-fuzz-redaction.md) and [sink-redaction-sql-cmd-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-redaction-sql-cmd.md) (the fuzz oracle reuses the splitter).
- **Phase 3:** [fx-crash-fuzz-redaction-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-fuzz-redaction-F1.md).
- **Details:** 9/9 sources were exposed.
- **Evidence:** [`evidence/fx-crash-fuzz-redaction-F1/woven_default_config.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-crash-fuzz-redaction-F1/woven_default_config.out.txt).
- **Fix:** use a stateful scan that skips strings and comments, only in the Oracle pass, or fail closed. Make the oracle independent.

**C11. The deterministic redaction pattern can equal the secret.** CONFIRMED. Parts: sink.
- **Location:** [`internal/taint/redaction/source.go:110,213-214,279-293`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/redaction/source.go#L110).
- **Ids:** [sink-redaction-source-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-redaction-source.md).
- **Phase 3:** [fx-sink-redaction-source-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-sink-redaction-source-F1.md).
- **Details:** the password `abc` serializes as `"pattern":"abc"`.
- **Evidence:** [`evidence/fx-sink-redaction-source-F1/woven-e2e-pattern-leak.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-sink-redaction-source-F1/woven-e2e-pattern-leak.out.txt).
- **Fix:** use a content-free mask.

**C12. Eager header tainting replaces the caller-visible `Request.Header` map.** CONFIRMED. Parts: sink, life.
- **Location:** [`iast/net/http/orchestrion.yml:109-119`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/net/http/orchestrion.yml#L109-L119), [`internal/taint/request/http.go:142-155`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/http.go#L142-L155).
- **Ids:** [sink-http-sources-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-http-sources.md).
- **Phase 3:** [fx-sink-http-sources-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-sink-http-sources-F1.md).
- **Details:** handler header mutations no longer reach the caller's aliases.
- **Evidence:** [`evidence/fx-sink-http-sources-F1/controls-go1.26.6.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-sink-http-sources-F1/controls-go1.26.6.txt).
- **Fix:** mutate in place, or drop header provenance.

**C13. Woven ParseForm/ParseMultipartForm advice rewrites form state on every re-parse (a data race, even when sampled out or disabled).** CONFIRMED. Parts: crash, life, sink.
- **Location:** [`iast/net/http/orchestrion.yml:152-162,177-186`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/net/http/orchestrion.yml#L152-L162), [`internal/taint/request/lazy.go:119-141`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/lazy.go#L119-L141).
- **Ids:** [life-lazy-reader-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-lazy-reader.md), [crash-race-hunt-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-race-hunt.md).
- **Phase 3:** the artifacts **disagree**: [fx-life-lazy-reader-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-lazy-reader-F1.md) says Critical, [fx-crash-race-hunt-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-race-hunt-F1.md) says High (identical pointers are written back). Critical is kept, because the multipart and element writes race.
- **Evidence:** [`evidence/fx-life-lazy-reader-F1/repeated-parse-race-go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-lazy-reader-F1/repeated-parse-race-go1.26.6.out.txt), [`evidence/fx-crash-race-hunt-F1/woven_repro.out`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-crash-race-hunt-F1/woven_repro.out).
- **Fix:** skip management if the form was already parsed at entry, and assign only when a map actually changed.

**C14. A late bind resurrects a finished root's annotation, so findings are lost and a second `Finish` races `SetMetaStruct` on the finished span.** CONFIRMED. Parts: crash, life.
- **Location:** [`internal/spans/orchestrion.go:27-46`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/orchestrion.go#L27-L46), [`internal/spans/annotation.go:119-149,184-211`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/annotation.go#L119-L149).
- **Ids:** [life-spans-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-spans.md), [life-spans-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-spans.md), [life-weak-gc-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-weak-gc.md), [crash-unsafe-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-unsafe.md).
- **Phase 3:** [fx-life-spans-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-spans-F2.md), [fx-life-weak-gc-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-weak-gc-F2.md), [fx-crash-unsafe-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-unsafe-F1.md).
- **Details:** 30 DATA RACE reports with a real tracer, and the stale entries hold annotation capacity.
- **Evidence:** [`evidence/fx-life-spans-F2/rerun.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-spans-F2/rerun.out.txt).
- **Fix:** keep a closed tombstone (outside capacity, reaped with its weak key), and return early from `Finished` when the entry is closed.

**C15. Data race on `analysisSlot.index`.** CONFIRMED. Parts: prop, life.
- **Location:** [`internal/taint/request/owner.go:82`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/owner.go#L82) (write, verified at HEAD) vs [`request/http.go:33`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/http.go#L33) (read).
- **Ids:** [prop-owner-isolation-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-owner-isolation.md).
- **Phase 3:** [fx-prop-owner-isolation-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-owner-isolation-F1.md) (it fails only `-race` builds).
- **Evidence:** [`evidence/fx-prop-owner-isolation-F1/woven-detached-query-race-go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-prop-owner-isolation-F1/woven-detached-query-race-go1.26.6.out.txt).
- **Fix:** initialize the index once in `NewManager` (phase 3 verified this).

### High (30: 29 CONFIRMED, 1 DISPUTED)

**Cross-request and stale provenance**

**H1. An unanchored `strings.Builder` view revives stale or cross-request taint after GC address reuse.** CONFIRMED. Parts: crash, store, life, prop.
- **Location:** [`iast/propagation/writer.go:202-205`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/writer.go#L202-L205) (verified); [`internal/taint/store/writer.go:448-462`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/writer.go#L448-L462).
- **Ids:** [store-identity-gc-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-identity-gc.md), [store-writer-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-writer.md), [crash-diff-bytes-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-diff-bytes.md), [life-cross-request-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-cross-request.md).
- **Phase 3:** [fx-store-identity-gc-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-identity-gc-F1.md), [fx-crash-diff-bytes-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-diff-bytes-F1.md).
- **Details:** 88/88 false SQLi reports when the address is reused.
- **Evidence:** [`evidence/fx-crash-diff-bytes-F1/repro-woven-http-sql-go1.26.6.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-crash-diff-bytes-F1/repro-woven-http-sql-go1.26.6.txt).
- **Fix:** anchor like `bufferView` ([`evidence/store-identity-gc/builder-anchor-fix.diff`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/store-identity-gc/builder-anchor-fix.diff)).

**H2. A `bytes.Buffer` view matches across receivers, so B's Buffer over a recycled slice inherits A's source.** CONFIRMED. Parts: store, life.
- **Location:** [`internal/taint/store/writer.go:448-462`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/writer.go#L448-L462).
- **Ids:** [life-cross-request-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-cross-request.md).
- **Phase 3:** [fx-life-cross-request-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-cross-request-F3.md).
- **Details:** deterministic, 3/3.
- **Evidence:** [`evidence/fx-life-cross-request-F3/zz_f3repro_test.go`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-cross-request-F3/zz_f3repro_test.go).
- **Fix:** require receiver identity, or check a content fingerprint.

**H3. A pooled `io.ReadAll` body slice attributes A's body to concurrent request B.** CONFIRMED. Parts: life, sink, store.
- **Location:** [`internal/taint/request/reader.go:67-88,119`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/reader.go#L67-L88), [`store/lookup.go:120-196`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/lookup.go#L120-L196).
- **Ids:** [life-cross-request-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-cross-request.md), [sink-e2e-truepos-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-e2e-truepos.md), [life-cross-request-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-cross-request.md).
- **Phase 3:** [fx-life-cross-request-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-cross-request-F1.md).
- **Evidence:** [`evidence/fx-life-cross-request-F1/run-go1.26.6-count3.log`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-cross-request-F1/run-go1.26.6-count3.log).
- **Fix:** stop adopting application buffers (clone or fingerprint), and refuse foreign-owner hits.

**H4. Reset or pooled reader wrappers keep the old owner's binding.** CONFIRMED. Parts: hooks, store.
- **Location:** [`iast/bufio/orchestrion.yml:15-34`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/bufio/orchestrion.yml#L15-L34), [`request/reader.go:27-39`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/reader.go#L27-L39), [`store/binding.go:95-108`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/binding.go#L95-L108).
- **Ids:** [hooks-io-bufio-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-io-bufio.md) (related: [store-binding-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-binding.md), now Low).
- **Phase 3:** [fx-hooks-io-bufio-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-io-bufio-F1.md).
- **Evidence:** [`evidence/fx-hooks-io-bufio-F1/e2e-go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-io-bufio-F1/e2e-go1.26.6.out.txt).
- **Fix:** hook `Reset` to unbind, and revalidate the underlying reader at `ReadAll`.

**H5. A stale owner handle publishes into the successor during slot reuse.** CONFIRMED. Parts: store, crash.
- **Location:** [`internal/taint/store/owner.go:20-60,127-149`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/owner.go#L20-L60), `binding.go:77-108`.
- **Ids:** [store-concurrency-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-concurrency.md), [store-stress-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-stress.md), [crash-deadlock-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-deadlock.md). Folded in: [store-stress-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-stress.md) and [store-concurrency-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-concurrency.md) (a stale Finish; same fix).
- **Phase 3:** [fx-store-concurrency-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-concurrency-F1.md), [fx-store-stress-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-stress-F1.md). 2x300s woven runs did not hit it.
- **Evidence:** [`evidence/fx-store-concurrency-F1/fx-seam-deterministic.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-store-concurrency-F1/fx-seam-deterministic.txt).
- **Fix:** do the Dead->Active transition under `lifecycleMu`, or use one atomic generation+state word revalidated at publish.

**H6. Writer activity in another request wipes an owner's writer state.** CONFIRMED. Parts: store.
- **Location:** [`internal/taint/store/writer.go:85-96,372-386,412-433`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/writer.go#L85-L96).
- **Ids:** [store-writer-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-writer.md).
- **Phase 3:** [fx-store-writer-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-writer-F1.md).
- **Details:** 220/300 lost vs 0/300.
- **Evidence:** [`evidence/fx-store-writer-F1/fx-woven.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-store-writer-F1/fx-woven.out.txt).
- **Fix:** on a failed TryLock, drop only the current operation.

**H7. URL-query attribution is keyed on `*url.URL` identity, not on `RawQuery` provenance, causing both false positives and false negatives.** CONFIRMED. Parts: life, sink.
- **Location:** [`internal/taint/request/lazy.go:28-46`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/lazy.go#L28-L46), [`request/http.go:69-77`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/http.go#L69-L77).
- **Ids:** [sink-http-sources-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-http-sources.md), [life-async-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-async.md).
- **Phase 3:** [fx-sink-http-sources-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-sink-http-sources-F2.md), [fx-life-async-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-async-F1.md).
- **Evidence:** [`evidence/fx-sink-http-sources-F2/fx_f2_review.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-sink-http-sources-F2/fx_f2_review.out.txt).
- **Fix:** derive query taint from the taint of `RawQuery`.

**False positives on supported paths**

**H8. fmt coarse propagation taints by argument identity, not by what was rendered.** CONFIRMED. Parts: prop, hooks, crash, sink.
- **Location:** [`internal/taint/propagation/string_coarse.go:115-146,175-221`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/string_coarse.go#L115-L146).
- **Ids:** [prop-string-coarse-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-string-coarse.md), [hooks-yml-fmt-strconv-url-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-fmt-strconv-url.md), [crash-diff-strings-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-diff-strings.md), [prop-semantics-parity-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-semantics-parity.md), [prop-string-coarse-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-string-coarse.md), [sink-e2e-truepos-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-e2e-truepos.md), [hooks-yml-fmt-strconv-url-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-fmt-strconv-url.md).
- **Phase 3:** [fx-prop-string-coarse-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-string-coarse-F1.md), [fx-crash-diff-strings-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-diff-strings-F1.md), [fx-prop-semantics-parity-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-semantics-parity-F2.md). The hooks and prop reports split the Stringer and verb variants into separate entries; they are merged here because one fix covers both.
- **Details:** a sanitizing `String()`, `%.0s`, `%T` or a skipped `%[n]` still yields a real SQL_INJECTION.
- **Evidence:** [`evidence/fx-prop-string-coarse-F1/woven-go126.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-prop-string-coarse-F1/woven-go126.txt).
- **Fix:** skip Formatter/Stringer/error arguments and honor verbs and indexes, or taint only when the argument's bytes appear in the output.

**H9. `strings.Map` keeps taint after deleting every tainted rune.** CONFIRMED (documented, but breaks rule 4). Parts: prop.
- **Location:** [`iast/propagation/coarse.go:36-38`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/coarse.go#L36-L38).
- **Ids:** [prop-semantics-parity-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-semantics-parity.md).
- **Phase 3:** [fx-prop-semantics-parity-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-semantics-parity-F3.md).
- **Evidence:** [`evidence/fx-prop-semantics-parity-F3/woven-go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-prop-semantics-parity-F3/woven-go1.26.6.out.txt).
- **Fix:** use an exact per-rune mapper.

**H10. A mixed `io.MultiReader` marks trusted bytes as request body.** CONFIRMED. Parts: life, hooks.
- **Location:** [`internal/taint/request/reader.go:27-45`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/reader.go#L27-L45), [`iast/io/orchestrion.yml:46-68`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/io/orchestrion.yml#L46-L68).
- **Ids:** [life-lazy-reader-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-lazy-reader.md), [hooks-io-bufio-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-io-bufio.md).
- **Phase 3:** [fx-life-lazy-reader-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-lazy-reader-F2.md).
- **Evidence:** [`evidence/fx-life-lazy-reader-F2/go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-lazy-reader-F2/go1.26.6.out.txt).
- **Fix:** bind only when all inputs share one owner, and fix the test that enshrines the current behavior.

**False negatives on supported paths**

**H11. fmt misses tainted data nested in structs, slices or errors.** CONFIRMED. Parts: prop, hooks, light.
- **Location:** `string_coarse.go:115-145,203-219`, `README.md:31-32`.
- **Ids:** [prop-semantics-parity-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-semantics-parity.md), [hooks-yml-fmt-strconv-url-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-fmt-strconv-url.md), [prop-string-coarse-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-string-coarse.md).
- **Phase 3:** [fx-prop-semantics-parity-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-semantics-parity-F1.md).
- **Evidence:** [`evidence/fx-prop-semantics-parity-F1/review_f1_test.go`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-prop-semantics-parity-F1/review_f1_test.go).
- **Fix:** document "direct operands only". Optionally add bounded reflection.

**H12. The Split/Fields window budget counts empty outputs.** CONFIRMED. Parts: prop.
- **Location:** [`internal/taint/propagation/propagation.go:239-246,515-537`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/propagation.go#L239-L246).
- **Ids:** [prop-engine-core-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-engine-core.md), [prop-string-exact-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-string-exact.md), [prop-engine-core-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-engine-core.md).
- **Phase 3:** [fx-prop-engine-core-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-engine-core-F1.md).
- **Evidence:** [`evidence/fx-prop-engine-core-F1/go1.26.6-woven.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-prop-engine-core-F1/go1.26.6-woven.out.txt).
- **Fix:** remove the `outputIndex` break.

**H13. `bytesAlias` bounds by `len` instead of `cap`, so reslices within capacity lose taint.** CONFIRMED. Parts: prop.
- **Location:** [`internal/taint/propagation/propagation.go:53-60`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/propagation.go#L53-L60) (verified).
- **Ids:** [prop-bytes-exact-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-bytes-exact.md).
- **Phase 3:** [fx-prop-bytes-exact-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-bytes-exact-F1.md).
- **Evidence:** [`evidence/fx-prop-bytes-exact-F1/woven-repro-go1.26.6.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-prop-bytes-exact-F1/woven-repro-go1.26.6.txt).
- **Fix:** bound by `cap`, and keep a len variant for JSON.

**H14. Orchestrion core-type resolution drops intersected constraints (silent taint loss).** CONFIRMED. Parts: hooks.
- **Location:** orchestrion [`internal/injector/typed/coretype.go:60-104`](https://github.com/DataDog/orchestrion/blob/23afa71d6dcb/internal/injector/typed/coretype.go#L60-L104).
- **Ids:** [hooks-orchestrion-dep-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-orchestrion-dep.md).
- **Phase 3:** [fx-hooks-orchestrion-dep-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-orchestrion-dep-F4.md).
- **Evidence:** [`evidence/fx-hooks-orchestrion-dep-F4/run-results.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-orchestrion-dep-F4/run-results.txt).
- **Fix:** upstream, intersect all terms first.

**H15. A tainted `Cmd.Path` that differs from `Args[0]` runs uninspected.** CONFIRMED. Parts: sink.
- **Location:** [`iast/os/exec/orchestrion.yml:59-78`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/os/exec/orchestrion.yml#L59-L78), [`iast/os/exec/exec.go:42-60`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/os/exec/exec.go#L42-L60).
- **Ids:** [sink-exec-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-exec.md).
- **Phase 3:** [fx-sink-exec-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-sink-exec-F1.md).
- **Evidence:** [`evidence/fx-sink-exec-F1/fxf1_repro_test.go`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-sink-exec-F1/fxf1_repro_test.go).
- **Fix:** pass `Path` to Report.

**H16. A nested JSON `Bind` claims a freed probe, so `Decoder.Decode` loses its document.** CONFIRMED. Parts: life.
- **Location:** [`internal/taint/jsonbridge/bridge.go:210-224`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/jsonbridge/bridge.go#L210-L224).
- **Ids:** [life-json-decoder-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-json-decoder.md).
- **Phase 3:** [fx-life-json-decoder-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-json-decoder-F1.md).
- **Evidence:** [`evidence/fx-life-json-decoder-F1/head-go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-json-decoder-F1/head-go1.26.6.out.txt).
- **Fix:** scan all probes before claiming one ([`evidence/life-json-decoder/fix-and-diagnostics.diff`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/life-json-decoder/fix-and-diagnostics.diff)).

**H17. A retained finished context disables analysis for later requests.** CONFIRMED. Parts: life.
- **Location:** [`internal/taint/request/scope.go:83-84`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/scope.go#L83-L84).
- **Ids:** [life-owner-scope-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-owner-scope.md).
- **Phase 3:** [fx-life-owner-scope-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-owner-scope-F1.md).
- **Evidence:** [`evidence/fx-life-owner-scope-F1/`](https://github.com/DataDog/dd-iast-go/tree/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-owner-scope-F1).
- **Fix:** reuse only unfinished scopes.

**Lost reports and exceeded bounds**

**H18. Sampled-out requests fill the 2-slot annotation store, so analyzed requests lose all findings.** CONFIRMED. Parts: crash, life, sink.
- **Location:** [`internal/spans/annotation.go:182-214,227-236`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/annotation.go#L182-L214).
- **Ids:** [crash-stress-app-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-stress-app.md), [life-spans-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-spans.md), [life-weak-gc-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-weak-gc.md).
- **Phase 3:** [fx-crash-stress-app-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-stress-app-F1.md), [fx-life-spans-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-spans-F1.md), [fx-life-weak-gc-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-weak-gc-F1.md).
- **Details:** 0/10 reported vs 89/89 in the control.
- **Evidence:** [`evidence/fx-crash-stress-app-F1/annrepro_deterministic.out`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-crash-stress-app-F1/annrepro_deterministic.out).
- **Fix:** use the `nonSampledAnnotation` sentinel for negative decisions, and check capacity before starting orphan spans.

**H19. With the span pool, a recycled root inherits another trace's annotation.** CONFIRMED (not reachable by default). Parts: life.
- **Location:** [`internal/spans/annotation.go:190-197`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/annotation.go#L190-L197).
- **Ids:** [life-weak-gc-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-weak-gc.md).
- **Phase 3:** [fx-life-weak-gc-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-weak-gc-F3.md).
- **Evidence:** [`evidence/fx-life-weak-gc-F3/review_f3_pool_test.go`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-weak-gc-F3/review_f3_pool_test.go).
- **Fix:** compare the stored root span ID (needed together with the C14 fix).

**H20. The annotation capacity check is not atomic with insertion.** CONFIRMED. Parts: store, life, crash.
- **Location:** [`internal/spans/annotation.go:131-143,198-205`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/annotation.go#L131-L143).
- **Ids:** [store-memory-bounds-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-memory-bounds.md), [life-spans-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-spans.md), [crash-unsafe-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-unsafe.md).
- **Phase 3:** [fx-store-memory-bounds-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-memory-bounds-F2.md).
- **Details:** 11 entries vs a cap of 2; 2048 vs 64.
- **Evidence:** [`evidence/fx-store-memory-bounds-F2/01-noPatch-admission.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-store-memory-bounds-F2/01-noPatch-admission.txt).
- **Fix:** reserve capacity with an atomic counter.

**H21. One writer can carry 60 owner records despite the 4-owner limit.** CONFIRMED (not reachable by default). Parts: prop.
- **Location:** [`internal/taint/propagation/writer.go:123-133`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/writer.go#L123-L133).
- **Ids:** [prop-writer-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-writer.md), [store-writer-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-writer.md).
- **Phase 3:** [fx-prop-writer-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-prop-writer-F1.md).
- **Evidence:** [`evidence/fx-prop-writer-F1/go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-prop-writer-F1/go1.26.6.out.txt).
- **Fix:** stop at `MaxSnapshotOwners`.

**H22. Buffer and reader anchors retain arbitrarily large uncharged caller allocations.** CONFIRMED. Parts: hooks, store.
- **Location:** [`iast/propagation/writer.go:213-216`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/writer.go#L213-L216), [`store/writer.go:17-42`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/writer.go#L17-L42), [`store/binding.go:29-35`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/binding.go#L29-L35).
- **Ids:** [hooks-yml-writers-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-writers.md), [store-memory-bounds-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-memory-bounds.md).
- **Phase 3:** the severities **disagree**: [fx-hooks-yml-writers-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-yml-writers-F1.md) says High, [fx-store-memory-bounds-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-memory-bounds-F1.md) says Medium (documented in README:70-77, request-scoped). High is kept.
- **Details:** 128 B charged vs 128 MiB retained.
- **Evidence:** [`evidence/fx-hooks-yml-writers-F1/woven-retention-go1.26.6.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-yml-writers-F1/woven-retention-go1.26.6.txt).
- **Fix:** charge the full backing and cap anchor bytes (a product decision).

**H23. Short evidence parts pin full sink snapshots outside the budget.** CONFIRMED. Parts: store, sink.
- **Location:** [`internal/taint/redaction/source.go:187-207`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/redaction/source.go#L187-L207), [`internal/taint/evidence/evidence.go:293-300`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/evidence/evidence.go#L293-L300).
- **Ids:** [store-memory-bounds-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-memory-bounds.md).
- **Phase 3:** [fx-store-memory-bounds-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-memory-bounds-F3.md).
- **Details:** 5.48x the 24 MiB ceiling.
- **Evidence:** [`evidence/fx-store-memory-bounds-F3/01-independent-sql-retention.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-store-memory-bounds-F3/01-independent-sql-retention.txt).
- **Fix:** clone the parts and charge them.

**H24. A full value shard stays wedged for the process lifetime.** CONFIRMED. Parts: store.
- **Location:** [`internal/taint/store/value.go:147-193,225-227`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/value.go#L147-L193).
- **Ids:** [store-stress-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-stress.md), [store-value-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-value.md).
- **Phase 3:** [fx-store-stress-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-store-stress-F2.md).
- **Evidence:** [`evidence/fx-store-stress-F2/independent-go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-store-stress-F2/independent-go1.26.6.out.txt).
- **Fix:** insert into `firstTombstone`, or compact.

**Host overhead (rule 2)**

**H25. Writer advice and the stdlib `bytes.Buffer` invalidation hook scan 64 owners on every Builder/Buffer operation in the process once any request is active.** CONFIRMED. Parts: perf, crash, prop, store.
- **Location:** [`iast/propagation/writer.go:29-35,104-129`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/writer.go#L29-L35), [`internal/taint/propagation/writer.go:21-25`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/writer.go#L21-L25), [`iast/propagation/orchestrion.yml:1553-1595`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/orchestrion.yml#L1553-L1595), [`store/writer.go:366-432`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/writer.go#L366-L432).
- **Ids:** [perf-hotpath-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-hotpath.md), [crash-stress-app-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-stress-app.md).
- **Phase 3:** [fx-perf-hotpath-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-perf-hotpath-F2.md), [fx-crash-stress-app-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-stress-app-F2.md).
- **Details:** about 50x per op; 6->475 ns.
- **Evidence:** [`evidence/fx-perf-hotpath-F2/bench-woven.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-perf-hotpath-F2/bench-woven.txt), [`evidence/fx-crash-stress-app-F2/default.out`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-crash-stress-app-F2/default.out).
- **Fix:** gate on a writer-state counter or owner bitmask.

**H26. The report path does all its expensive work before the sampling, quota and dedup gates.** CONFIRMED. Parts: perf, crash, life, sink.
- **Location:** [`internal/vulnerability/report.go:41-105`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/vulnerability/report.go#L41-L105), `tainted.go:57-100`, [`iast/database/sql/sql.go:34-49`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/database/sql/sql.go#L34-L49).
- **Ids:** [perf-memory-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-memory.md), [crash-hostile-input-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-hostile-input.md), [life-spans-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-spans.md), [sink-vuln-report-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-vuln-report.md), [perf-allocs-matrix-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-allocs-matrix.md), [perf-allocs-matrix-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-allocs-matrix.md), [sink-vuln-report-F7](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-vuln-report.md), [sink-vuln-report-F8](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-vuln-report.md).
- **Phase 3:** [fx-perf-memory-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-perf-memory-F1.md), [fx-crash-hostile-input-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-crash-hostile-input-F2.md), [fx-life-spans-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-spans-F4.md).
- **Details:** 40 reports processed for 2 committed. 1000 md5 calls produced 1000 orphan spans.
- **Evidence:** [`evidence/fx-crash-hostile-input-F2/quota-repro.log`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-crash-hostile-input-F2/quota-repro.log), [`evidence/fx-life-spans-F4/fx-woven-own.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-spans-F4/fx-woven-own.out.txt).
- **Fix:** hash type+location first, check quota, dedup and sampling, then build. Add process dedup for crypto.

**H27. Woven operator wrappers allocate with IAST inactive (`[]byte`->`string` results and concat operands escape).** CONFIRMED. Parts: perf, hooks, prop.
- **Location:** [`iast/propagation/operators.go:18-26,90-204`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/operators.go#L18-L26), [`propagation/string_exact.go:56`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/string_exact.go#L56), `bytes_exact.go:43`.
- **Ids:** [perf-escape-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-escape.md), [hooks-yml-operators-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-operators.md), [prop-concat-conv-json-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-concat-conv-json.md), [prop-concat-conv-json-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-concat-conv-json.md), [perf-escape-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-escape.md), [perf-escape-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-escape.md), [perf-escape-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-escape.md), [hooks-compile-matrix-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-compile-matrix.md), [hooks-fidelity-strings-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-fidelity-strings.md).
- **Phase 3:** [fx-perf-escape-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-perf-escape-F1.md), [fx-hooks-yml-operators-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-hooks-yml-operators-F4.md). prop-concat-conv-json said "no High"; phase 3 wins.
- **Details:** 1 vs 0 allocs with IAST disabled. slog `TestTextHandlerAlloc` measures 11 vs 0.
- **Evidence:** [`evidence/fx-hooks-yml-operators-F4/woven-go1266.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-hooks-yml-operators-F4/woven-go1266.txt).
- **Fix:** an inlinable non-generic gate ([`evidence/perf-escape/prototype-fix-v3.patch`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/perf-escape/prototype-fix-v3.patch)), and an index loop instead of `copy`.

**H28. The evidence collector rehashes the whole source per range (O(R*S)).** CONFIRMED. Parts: perf, sink.
- **Location:** [`internal/taint/evidence/evidence.go:209-240,277-291`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/evidence/evidence.go#L209-L240).
- **Ids:** [perf-algorithmic-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-algorithmic.md).
- **Phase 3:** [fx-perf-algorithmic-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-perf-algorithmic-F1.md).
- **Evidence:** [`evidence/fx-perf-algorithmic-F1/command-source-output.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-perf-algorithmic-F1/command-source-output.txt).
- **Fix:** cache per collection.

**H29. NUL-delimited source-table hashing lets attacker tuples collide (32,896 probes).** CONFIRMED. Parts: life.
- **Location:** [`internal/taint/request/table.go:130-151,208-220`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/table.go#L130-L151).
- **Ids:** [life-table-lookup-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-table-lookup.md).
- **Phase 3:** [fx-life-table-lookup-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-table-lookup-F1.md).
- **Evidence:** [`evidence/fx-life-table-lookup-F1/independent_go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-table-lookup-F1/independent_go1.26.6.out.txt).
- **Fix:** length-prefix the fields.

**Availability**

**H30. Disconnected but stalled handlers keep their admission permit.** **DISPUTED.** Parts: life, sink, crash, perf.
- **Location:** [`iast/net/http/orchestrion.yml:27-33`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/net/http/orchestrion.yml#L27-L33), [`request/scope.go:79-104,209-222`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/scope.go#L79-L104).
- **Ids:** [life-admission-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-admission.md), [res-digest-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase1/res-digest.md).
- **Phase 3:** `fx-life-admission-F1.json` reads CONFIRMED High. An earlier falsifier REFUTED it, and its file was overwritten, so the reasoning is lost. crash-stress-app never exercised the stalled shape.
- **Details:** at the default limit of 2, two stalled handlers disable analysis until they return.
- **Evidence:** [`evidence/fx-life-admission-F1/fx_repro_go1.26.6.out.txt`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-admission-F1/fx_repro_go1.26.6.out.txt).
- **Fix:** release on context cancellation (`context.AfterFunc`), and get a third verdict before GA.

### Medium (49; reviewer-reported unless marked CONFIRMED)

- M1. Bridges have no panic shield, so injected panics escape readers, leak `lifecycleMu`, or replace host panics. `internal/taint/*bridge/bridge.go`. [hooks-panic-safety-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-panic-safety.md)/F2/F3, [life-bridges-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-bridges.md), [crash-panic-static-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-panic-static.md). CONFIRMED (Critical->Medium). Fix: scoped `recover` and `defer` unlocks.
- M2. Coarse fmt/url/strconv output keeps only the first source over `[0,len)`, and this is undocumented. `propagation.go:721-736`. [hooks-yml-fmt-strconv-url-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-yml-fmt-strconv-url.md), [prop-string-coarse-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-string-coarse.md), [sink-e2e-truepos-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-e2e-truepos.md). Fix: document it.
- M3. Lazy string iterators allocate with no active owner. [`iast/propagation/strings.go:75-119`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/propagation/strings.go#L75-L119). [perf-hotpath-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-hotpath.md). CONFIRMED (High->Medium). Fix: return the native iterator.
- M4. The README's "application root" module boundary is ambiguous. `README.md:38-39`. [hooks-scope-root-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-scope-root.md). Fix: document it.
- M5. `trimStore` runs a blocking full-map sweep above 3/4 capacity. [`spans/annotation.go:34,227-236`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/annotation.go#L34). [crash-stress-app-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-stress-app.md). Fix: rate-limit it.
- M6. Fuzzers never reach the coarse, window, JSON or writer paths, and the oracles are weak. [`propagation/sequence_operations_test.go:18,131`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/sequence_operations_test.go#L18). [crash-fuzz-engine-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-fuzz-engine.md)/F2, [prop-engine-fuzz-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-engine-fuzz.md), [prop-ranges-fuzz-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-ranges-fuzz.md). Fix: upstream the review oracles.
- M7. The README hides the 1-64 clamp on `DD_IAST_VULNERABILITIES_PER_REQUEST`. `README.md:117`. [crash-config-extremes-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-config-extremes.md), [light-config-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-config.md), [light-docs-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-docs.md). Fix: document it.
- M8. `DD_IAST_DB_ROWS_TO_TAINT` is documented but unimplemented. `README.md:125`. [light-docs-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-docs.md). Fix: remove it.
- M9. Accepted plans remain in [`_docs/plans`](https://github.com/DataDog/dd-iast-go/tree/eliottness/taint-tracking-review/_docs/plans) with contradictory status. [light-docs-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-docs.md), [map-design-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase1/map-design.md). Fix: delete them.
- M10. CI has no woven `-race` lane and no SQLi/CMDi system-tests. [`.github/workflows/ci.yml:151-152`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.github/workflows/ci.yml#L151-L152). [light-ci-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-ci.md), [sink-systemtests-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-systemtests.md), [sink-parity-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-parity.md), [sink-systemtests-F8](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-systemtests.md). Fix: add both.
- M11. A middleware-detached context opens a second scope. [`iast/net/http/orchestrion.yml:81-121`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/net/http/orchestrion.yml#L81-L121). [life-async-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-async.md). Fix: find the outer owner.
- M12. A finished or foreign context scope vetoes a live request's taint. [`vulnerability/tainted.go:45-47`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/vulnerability/tainted.go#L45-L47). [life-async-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-async.md). Fix: scope the veto to its owner.
- M13. A concurrent second `Scope.Finish` returns before cleanup finishes. `scope.go:210-223`. [life-owner-scope-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-owner-scope.md). Fix: `sync.Once`.
- M14. The JSON slot hash uses 8 buckets, so effective capacity is 32. [`jsonbridge/bridge.go:210`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/jsonbridge/bridge.go#L210). [life-json-decoder-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-json-decoder.md). Fix: a better hash.
- M15. JSON slot admission ignores relevance. [`jsonbridge/bridge.go:60-72`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/jsonbridge/bridge.go#L60-L72). [life-json-decoder-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-json-decoder.md) (NEEDS-REPRO). Fix: bind only tainted inputs.
- M16. Query and header caps are all-or-nothing, so filler parameters erase all taint. [`request/lazy.go:163-173`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/lazy.go#L163-L173). [perf-memory-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-memory.md). Fix: taint the first N.
- M17. The `sourceMu` TryLock on reads makes concurrent readers miss taint (up to 19.8%). [`request/lookup.go:143-157`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/lookup.go#L143-L157). [perf-contention-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-contention.md). Fix: `TryRLock`.
- M18. Sampled-out requests allocate a 3.2-3.5 KB Annotation. `annotation.go:198-213`. [perf-memory-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-memory.md), [perf-allocs-matrix-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-allocs-matrix.md). Fix: use the sentinel.
- M19. `Finished` calls `weak.Make` on every span, even when disabled. [`spans/orchestrion.go:27-31`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/spans/orchestrion.go#L27-L31). [life-weak-gc-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-weak-gc.md). Fix: gate it.
- M20. Oversized sources are hashed before the 64 KiB check. [`request/owner.go:146`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/owner.go#L146). [life-table-lookup-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-table-lookup.md) (NEEDS-REPRO). Fix: check the length first.
- M21. Coarse adoption stamps `DefaultLimit` 10, overriding `DD_IAST_MAX_RANGE_COUNT`. `propagation.go:415,692`, [`request/reader.go:110`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/reader.go#L110). [prop-ranges-fuzz-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-ranges-fuzz.md), [prop-string-coarse-F6](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-string-coarse.md). Fix: pass the configured limit.
- M22. `http.request.uri` is origin-form, not an absolute URL. [`request/http.go:70`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/request/http.go#L70). [sink-systemtests-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-systemtests.md). Fix: publish the absolute URL.
- M23. No lifecycle or concurrency tests (recycling, post-finish bind, double Finish, soak). [life-spans-F6](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-spans.md), [life-weak-gc-F6](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-weak-gc.md), [life-cross-request-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-cross-request.md), [life-soak-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-soak.md). Fix: adopt the `evidence/fx-life-*` reproducers.
- M24. The unsalted evidence index hash allows crafted collisions. `evidence.go:240-277`. [perf-algorithmic-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-algorithmic.md). CONFIRMED (High->Medium). Fix: `maphash`.
- M25. `Owner.Finish` holds the global `overflowMu` across 512 roots, truncating other requests' publishes. [`store/owner.go:181-203`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/owner.go#L181-L203). [perf-contention-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-contention.md), [store-concurrency-F6](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-concurrency.md), [store-root-F6](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-root.md). Fix: a short critical section.
- M26. Clone-then-adopt paths (for example `Repeat`) clone after the budget is exhausted. `propagation.go:262-297`. [perf-memory-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-memory.md), [prop-engine-fuzz-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-engine-fuzz.md). Fix: pre-check the budget.
- M27. The empty-separator `Join` scan runs before the active gate. `string_exact.go:21-48`. [perf-hotpath-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-hotpath.md), [store-api-misuse-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-api-misuse.md). Fix: gate first.
- M28. Cold builds are 6.9-39x slower and binaries +20.4 MB, mostly the tracer. [perf-binary-compile-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-binary-compile.md)/F2, [base-bootstrap-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase1/base-bootstrap.md). Fix: document it and cache GOCACHE.
- M29. Benchmarks never hit the tainted path (430-6200x costlier), and operator benchmarks run unwoven. [`benchmarks/overhead/overhead_test.go:40`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/benchmarks/overhead/overhead_test.go#L40). [perf-bench-quality-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-bench-quality.md)/F2/F3, [prop-concat-conv-json-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-concat-conv-json.md). Fix: add tainted woven benchmarks.
- M30. Zero-range snapshot entries count as hits. `propagation.go:382-422`, [`store/lookup.go:182-195`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/lookup.go#L182-L195). [prop-engine-core-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-engine-core.md), [store-fuzz-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-fuzz.md), [prop-string-coarse-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-string-coarse.md). Fix: skip empty entries.
- M31. Range truncation is invisible to telemetry. `string_exact.go:82-94`. [prop-ranges-algebra-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-ranges-algebra.md). Fix: record the drop.
- M32. Non-ASCII case conversion collapses the value to the first source. `string_coarse.go:49-67`. [prop-unicode-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-unicode.md). Fix: map per rune.
- M33. Foreign traffic consumes owner A's writer budgets. [`propagation/writer.go:123-133`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/writer.go#L123-L133). [prop-owner-isolation-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-owner-isolation.md). Fix: publish only from the owner's scope.
- M34. `JSONString` reports success when all adoptions failed. [`propagation/json.go:42-69`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/json.go#L42-L69). [store-api-misuse-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-api-misuse.md), [prop-concat-conv-json-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/prop-concat-conv-json.md). Fix: check the adoption results.
- M35. Each `Builder.String()` publishes a new root, so 511 calls exhaust the budget. [`propagation/writer.go:190-237`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/propagation/writer.go#L190-L237). [store-writer-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-writer.md), [hooks-fidelity-bytes-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/hooks-fidelity-bytes.md). Fix: cache it.
- M36. A name-sensitive source keeps its name on the wire. [`redaction/source.go:107-115`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/redaction/source.go#L107-L115). [sink-redaction-source-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-redaction-source.md). CONFIRMED (Critical->Medium). Fix: mask the name.
- M37. Joined command evidence keeps only 4 owners. `evidence.go:339,404-413`. [sink-evidence-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-evidence.md). CONFIRMED (High->Medium). Fix: a separate bound.
- M38. A part past the 250-char truncation has no `value`. [`redaction/source.go:188-208`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/redaction/source.go#L188-L208). [sink-parity-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-parity.md). CONFIRMED (High->Medium). Fix: mark the kept part as truncated.
- M39. The dedup hash (type+location) is unreliable: location-less findings collide, panic-time locations are wrong, and ORM frames are not skipped. `report.go:155-158`. [sink-vuln-report-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-vuln-report.md)/F3/F4. Fix: extend the skip list.
- M40. The hash includes the absolute build path. [`model/vulnerability.go:36-41`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/model/vulnerability.go#L36-L41). [sink-vuln-report-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-vuln-report.md). Fix: use a module-relative path.
- M41. Windows `SysProcAttr.CmdLine` is not inspected. [`iast/os/exec/orchestrion.yml:59-78`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/os/exec/orchestrion.yml#L59-L78). [sink-exec-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-exec.md) (NEEDS-REPRO). Fix: inspect it or document it.
- M42. Sink suites miss risky paths (non-context SQL, exec Path, meta_struct). [`iast/database/sql/testapp/sql_test.go:63-100`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/iast/database/sql/testapp/sql_test.go#L63-L100). [sink-sql-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-sql.md), [sink-exec-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-exec.md), [sink-e2e-truepos-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-e2e-truepos.md). Fix: promote the reviewer tests.
- M43. The source telemetry counters are never incremented. [`telemetry/telemetry.go:25,38`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/instrumentation/telemetry/telemetry.go#L25). [sink-systemtests-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-systemtests.md). Fix: increment them.
- M44. The system-tests manifest enables weak-cipher stack tests for all Go weblogs. `manifests/golang.yml:201-204`. [sink-systemtests-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-systemtests.md). Fix: mark them `missing_feature`.
- M45. Stale same-key slots use up Lookup's 4-owner window. [`store/lookup.go:117-139`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/lookup.go#L117-L139). [store-lookup-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-lookup.md), [store-fuzz-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-fuzz.md), [store-value-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-value.md). CONFIRMED (High->Medium). Fix: validate first.
- M46. A contended `rollbackRoot` leaks a root slot and its charge. [`store/root.go:370-375`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/root.go#L370-L375). [store-root-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-root.md), [store-stress-F4](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-stress.md). Fix: a blocking Lock.
- M47. The address-reuse test usually skips. [`store/identity_test.go:30-65`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/identity_test.go#L30-L65). [store-tests-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-tests.md), [store-identity-gc-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-identity-gc.md), [light-test-determinism-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-test-determinism.md). Fix: make it deterministic.
- M48. The Finish-blocking assertion can pass too early. [`store/lifecycle_test.go:14-35`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/lifecycle_test.go#L14-L35). [store-tests-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-tests.md) (NEEDS-REPRO). Fix: signal from a test seam.
- M49. Binding-kind transitions are untested. [`store/binding.go:166-202`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/binding.go#L166-L202). [store-tests-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-tests.md). Fix: add tests.

**Not counted:** [perf-contention-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-contention.md) (owner-lock TryLock drops admissions despite free capacity, [`store/owner.go:24-27`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/store/owner.go#L24-L27)) was REFUTED in phase 3, which rated it Info as a documented allowance ([fx-perf-contention-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-perf-contention-F1.md)). [life-weak-gc-F5](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-weak-gc.md) (Medium), [crash-race-hunt-F2](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-race-hunt.md) (Low) and part-store M5 rate the same root cause higher; the phase-3 verdict governs.

### Low and Info

Phase 2 raised 79 Low and 43 Info findings before dedup. Phase 3 then set [store-binding-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/store-binding.md) to Low and [light-deps-license-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/light-deps-license.md) and [perf-contention-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/perf-contention.md) to Info. See §3 of each `phase4/part-*.md`. Examples:
- A `Join` with more than 16 elements silently goes coarse.
- Go 1.27 `CutLast` and `To*Special` are unhooked, although the README says they are.
- Patterns are sized in bytes, not runes.
- There is one flaky test.
- Tracer auto-start is enabled silently.

## 5. Correctness verdict per part

These are each part's own counts before cross-part dedup, so they overlap.

| Part | Verdict | Crit | High | Med |
|---|---|---|---|---|
| crash | Not acceptable: an init panic and form races. Fidelity, fuzzing and bounds are excellent. | 5 | 8 (1 DISPUTED) | 5 |
| hooks | Not shippable: 8 build breaks, mostly in the pinned Orchestrion. | 8 | 8 | 4 |
| life | Not ready: races, and provenance fails when requests overlap. No leak. | 5 | 14 (1 DISPUTED) | 15 |
| light | No runtime defect. The Critical is the pin. | 1 | 0 | 5 |
| perf | Not acceptable: three ungated paths. Memory is bounded. | 1 | 4 | 15 |
| prop | Range algebra is correct; 10 provenance and cost Highs plus 1 race. | 1 | 10 | 12 |
| sink | Detection is sound (39/39), but there are redaction leaks, source races and a Go 1.27 break. | 7 | 6 + 1 DISPUTED | 15 |
| store | Crash-safe and race-free, but not provenance-safe under reuse or concurrency. | 0 | 9 | 13 |

## 6. Performance verdict

**Not acceptable for production as-is** ([`phase4/perf-verdict.md`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase4/perf-verdict.md)). The cheap gates work: at 0% sampling, all 25 propagation benchmarks are within noise. But H25, H26 and H27 slow the host regardless of the sampling rate. Figures below are from `evidence/bench/overhead-s100|s0/comparison.txt` (go1.26.6, cpu=1) and were verified against those files.

| Workload | s100 | s0 |
|---|---|---|
| `BytesBufferCopies/write` | +10675.34% | +10476.16% |
| `BytesBufferCopies/active-unrelated` | +3688% | n/a |
| `WeakHashActiveSpan` | +248% | n/a |
| `WeakHashNoActiveSpan` | +122.91% (0->4 allocs) | +124.88% |
| `HTTPRoundTrip` | +31.66% (414->510 allocs) | +3.73% |
| Geomean (40 workloads) | +48.45% | +40.54% |

- **Allocations:** a sampled typical request allocates 4.1x plain (+25.4 KB), 71% of it report work that dedup later discards. A sampled-out request adds +3.4 KB (M18).
- **The table understates tainted-request cost:** the tainted path is 430-6200x costlier, and no benchmark exercises it (M29).
- **Build:** 6.9-39x cold build and +20.4 MB binaries. Peak RSS is 1.33 GiB on go1.26.6 vs 24.1 GB on go1.27 (C1).
- **Top fixes:** H25, H26, H27, H28 together with M24, then M18.

## 7. Code-quality notes

- **Tests enshrine defects:** [`redaction/analyzer_test.go:30`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/internal/taint/redaction/analyzer_test.go#L30) (C9), the MultiReader test (H10), and the fuzz oracle that shares the production splitter (C10).
- **Weak tooling:** checklocks is inert in the store. There are 2 production `unparam` issues ([base-static-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase1/base-static.md)/F2).
- **Panic hygiene:** silent `_ = recover()`, and manual unlocks that would leak after a recovered panic ([life-bridges-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-bridges.md), [crash-panic-static-F3](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/crash-panic-static.md)).
- **Determinism is good:** no sleeps or `t.Parallel` in 139 test files, and 91.5% store coverage. There is one flaky test and one test that usually skips (M47).
- **Dead or test-only production code:** `ranges.Canonicalize` (unused, 29 KiB frame), the `forceCollision` seam, `PublishBytesMutation`, `Counters()`.
- **Repo hygiene:** a tracked `.DS_Store`, and CI tracks a mutable system-tests branch ([sink-systemtests-F11](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/sink-systemtests.md)).

## 8. Comparison with the Orchestrion research (PR #858)

Condensed from [`phase4/research-comparison.md`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase4/research-comparison.md).

**dd-iast-go is better on:**
- Hard fixed-array bounds with drop counters, and no saturation latch.
- Per-request owner isolation with generations.
- No process-lifetime pinning.
- Cheap gates and non-blocking TryLock.
- A stock toolchain, instead of a forked darwin-only runtime.

**Where it falls short:**
- The research's two reproduced failure modes both reappear as CONFIRMED Highs: stale taint on reused memory (H1-H4) and unobserved in-place mutation (`append`/`copy` are unhooked, which is documented).
- The research treated conservative over-taint as acceptable; here it becomes false positives (H8, H9).
- Redaction is not safe on every exit (C9-C11).
- The join-point contract is broken (C2-C7, H14).

**The research covers, and dd-iast-go does not:** free alias resolution, builtin hooks, and scalar, map and channel tracking. These are documented trade-offs.

**Errors in research-comparison.md:** it lists the ParseForm race as "Critical->High", but [fx-life-lazy-reader-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase3/fx-life-lazy-reader-F1.md) says Critical. It cites `fx-prop-owner-isolation-F1` as evidence for [life-cross-request-F1](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase2/life-cross-request.md); the correct directory is [`evidence/fx-life-cross-request-F1/`](https://github.com/DataDog/dd-iast-go/tree/eliottness/taint-tracking-review/.omo/review/evidence/fx-life-cross-request-F1).

## 9. Recommended fix order

**Blockers before any customer exposure:**
1. **Builds:** C1, then an Orchestrion release carrying the C2, C3, C5-C7 and H14 fixes and the C4 matcher change, plus a repin.
2. **Host safety:** C8, C4, C12, C13, C14 (with H19), C15.
3. **Redaction:** C9, C10, C11, M36.
4. **Cross-request bleed and false positives:** H1-H10.
5. **Silent report loss:** H18, H17.
6. **Rule 2:** H25, H26 and H27, plus the woven `-race` and tainted-hit CI lanes (M10, M29).

**Next:**
- The remaining Highs: H11-H13, H15, H16, H20-H24, H28, H29, and a third verdict on H30.
- M1.
- The provenance Mediums: M11-M13, M16, M17, M21, M30, M33.
- The doc Mediums: M2, M4, M7-M9.
- The test gaps: M6, M23, M42, M47-M49. Adopt the phase-3 reproducers as regression tests.

## 10. Appendix: artifact index

- `BRIEF.md`.
- Phase 1: [`phase1/00-architecture.md`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase1/00-architecture.md), [`phase1/01-design-intent.md`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase1/01-design-intent.md), `phase1/base-{test-126,test-127,race,static,bootstrap}.{md,log,findings.json}`, `phase1/map-*.md`, `phase1/res-*.md`, `phase1/research/*.md`.
- Phase 2: `phase2/<part>-<lane>.{md,findings.json}` (92 lanes, 290 findings).
- Phase 3: `phase3/fx-<id>.{md,json}` (78 files, 91 entries; `fx-life-admission-F1.json` was overwritten).
- Phase 4: `phase4/part-{crash,hooks,life,light,perf,prop,sink,store}.md`, [`phase4/perf-verdict.md`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase4/perf-verdict.md), [`phase4/research-comparison.md`](https://github.com/DataDog/dd-iast-go/blob/eliottness/taint-tracking-review/.omo/review/phase4/research-comparison.md).
- Evidence: `evidence/<node-id>/`, `evidence/fx-<id>/`, [`evidence/bench/`](https://github.com/DataDog/dd-iast-go/tree/eliottness/taint-tracking-review/.omo/review/evidence/bench) (`micro-benchstat.txt`, `overhead-{s0,s100}/comparison.txt`, `metadata.txt`).

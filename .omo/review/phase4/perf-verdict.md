# perf-verdict: Performance verdict for dd-iast-go (romain.marcadier/taint-tracking @ 2e23b46)

**Verdict: NOT acceptable for customer production use as-is.** The cheap-gate design works — at 0% sampling nearly every workload is statistically unchanged — but three ungated paths (writer-state owner scans, the vulnerability report path, and `[]byte`→`string` conversion allocation) break the "never slow the host more than strictly necessary" rule regardless of sampling, and the captured table itself understates real tainted-request cost because the benchmark suite almost never exercises the hit path (perf-bench-quality-F1, Medium, reviewer-reported).

Source: `benchmarks/overhead` runner on a quiet machine, go1.26.6, Apple M4 Max, `cpu=1`; s100 = `count=10 benchtime=500ms`, s0 = `count=6 benchtime=300ms`; control vs Orchestrion-woven IAST binary (`evidence/bench/overhead-s100|s0/comparison.txt`). All percentages copied verbatim from comparison.txt.

## 1. Headline table — sec/op overhead per workload (vs control)

| Workload | 100% sampling | 0% sampling |
|---|---:|---:|
| BytesBufferCopies/write (tainted hit) | **+10675.34%** | +10476.16% |
| BytesBufferCopies/active-unrelated | **+3688.43%** | +3755.26% |
| BytesBufferCopies/read | **+1984.61%** | +2001.05% |
| WeakHashActiveSpan | **+248.08%** | +26.35% |
| WeakCipherActiveSpan | **+232.52%** | +22.21% |
| WeakHashNoActiveSpan | **+122.91%** | +124.88% |
| WeakCipherNoActiveSpan | **+18.13%** | +20.06% |
| HTTPRoundTrip | **+31.66%** | +3.73% |
| RequestProcessingParallel | +2.18% | ~ |
| RequestProcessing / Health | ~ | ~ |
| All 25 remaining propagation benches (StringsBuilder, BytesBuffer, Clone/Split/Join/Repeat/Replace/ToLower/Map, Strings*, FmtSprintf, URLQueryEscape, StrconvQuote, PropagationActiveUntainted/*) | ~ (noise) | ~ (noise) |
| **geomean (40 workloads)** | **+48.45%** | **+40.54%** |

The geomean stays +40.54% at 0% sampling because the BytesBufferCopies rows (explicitly tainted state, not request-sampled) and the ungated weak-crypto report path dominate it.

Package micro-benchmarks (`micro-benchstat.txt`, woven vs plain, n=8): B/op and allocs/op identical everywhere ("all samples are equal"); sec/op deltas: `OperatorSlicesInactive` **+107.58%** (1.768n→3.670n, ~2 ns absolute), json `LiteralInactive` +10.24% / `LiteralActiveClean` +10.94%, propagation geomean +21.40%; ranges/redaction/evidence/bridges/sql/exec geomeans −0.50% to +10.59% or noise. `ReportActiveClean` and `HasValuesClean` gates are ~1.7–6.5 ns, 0 allocs.

## 2. Allocation deltas (B/op and allocs/op, vs control)

| Workload | 100% | 0% |
|---|---|---|
| HTTPRoundTrip | +23.19% allocs (414→510), +20.37% B (33.16Ki→39.91Ki) | +2.17% allocs (414→423), +11.69% B (33.16Ki→37.04Ki) |
| WeakHashActiveSpan | +81.48% allocs (54→98), +268.66% B (5.272Ki→19.438Ki) | +11.11% allocs, +65.25% B |
| WeakCipherActiveSpan | +76.79% allocs (56→99), +262.37% B | +8.93% allocs, +63.68% B |
| WeakHash/CipherNoActiveSpan | 0→4 allocs / 128 B; +400% allocs, +100% B (cipher) | same |
| BytesBufferCopies/read · write | +1 alloc (1→2); B 8→56 (+600.00%) · 16→64 (+300.00%) | identical |
| Everything else (incl. RequestProcessing 47 allocs, Health 19) | ~ | ~ |

`DD_IAST_ENABLED=false` restores control allocation counts exactly (perf-allocs-matrix, checked). A sampled typical request allocates 4.1x plain (5.5x when reporting), +25.4 KB/req, 71% of it report work later discarded by dedup (perf-memory-F1).

## 3. Build-time and binary-size overhead

- **Cold woven build: 6.9x–39x wall** (bootstrap 167.8 s vs 4.3 s plain, 39.0x; overhead test binary 78.7 s vs 11.4 s, 6.9x) vs the brief's 5x threshold. dd-iast-go's own increment over a tracer-only Orchestrion control: 3.8x wall / 1.8x CPU (bootstrap), ~noise (overhead). Warm rebuilds: 6.7 s no-op, 13.8 s after touching one file. Peak build RSS ≤1.09 GB. (perf-binary-compile-F1, Medium, reviewer-reported; single samples, shared host.)
- **Binary size: 12.69x (+20.4 MB) for a trivial `main`** (1,749,218 → 22,194,578 bytes) vs the 2x threshold; ~19.35 MB of that is the bundled dd-trace-go tracer, dd-iast-go's own increment is +1.10 MB (1.05x). Realistic binaries: 1.01x (+0.14 MB) to 1.11x (+2.04 MB). 63 stdlib weave sites in every woven binary (36 in `bytes`). (perf-binary-compile-F2/F3, Medium/Info, reviewer-reported; base-bootstrap-F1 measured the same +20.4 MB as Info — same root cause, deduplicated here.)
- GOCACHE cost: ~0.9–0.94 GB woven vs ~0.36 GB plain.

## 4. Worst hot-path costs and root causes (deduplicated)

**4.1 Writer-state gate scans the whole owner table on every stdlib `bytes.Buffer`/`Builder` mutation** — contributing ids: **perf-hotpath-F2, crash-stress-app-F2**; location: `iast/propagation/writer.go:29-35,104-129` (gate is `WriterActive()` = any sampled request, `internal/taint/propagation/writer.go:21-25`), `iast/propagation/orchestrion.yml:1553-1595` (woven stdlib `bytes` advice), `internal/taint/writerbridge/bridge.go:75-96`, `internal/taint/store/writer.go:366-432` (`InvalidateBuffer` loops all 64 owners; `LookupWriterValue` at `internal/taint/store/writer.go:75-113` walks 64 owner slots even with zero writer states; `updateWriter` zeroes a 6312-byte Snapshot). This is the root cause of the BytesBufferCopies rows (write **+10675.34%**) and of unrelated `json.Marshal` slowing 9x–78x process-wide while any writer state exists. Severity: **High (CONFIRMED in phase 3, both fx-perf-hotpath-F2 and fx-crash-stress-app-F2)**. Evidence: `evidence/bench/overhead-s100/comparison.txt`, `evidence/fx-perf-hotpath-F2/bench-woven.txt`, `evidence/fx-crash-stress-app-F2/default.out`. Fix: store-level atomic bitmask of owners with `writerCount>0` plus a cheap tracked-pointer filter; return the native writer op when both the value counter and writer-state counter are zero.

**4.2 Ungated vulnerability report path pays UUID + stack capture + model build before the only dedup/quota check** — contributing ids: **perf-allocs-matrix-F1, perf-memory-F1, perf-allocs-matrix-F3** (orphan span started before the sampling check); location: `internal/vulnerability/report.go:44-52,56-105`, `internal/vulnerability/tainted.go:57,76,90-100` (dedup `set.Check` only at tainted.go:93), `iast/database/sql/sql.go:37-45`, `internal/model/vulnerability.go:24-43` (hash uses only type+location). Root cause of all WeakHash/WeakCipher rows and of the steady-state cost: 1000 `md5.Sum` calls publish 1 finding yet each pays 28 allocs / ~7 µs (119 ns → 6767–9380 ns, 57–79x); a deduplicated SQLi site costs ~17.9 KB/req (8.5 KB stack capture). Severity: **High (CONFIRMED in phase 3, both fx-perf-allocs-matrix-F1 and fx-perf-memory-F1)**. Evidence: `evidence/fx-life-spans-F4/fx-woven-own.out.txt`, `evidence/fx-perf-memory-F1/`. Fix: compute the hash from type+location first and consult a `WouldDrop(hash)` under RLock before any capture; move `NewOrphanVulnerabilitySpan` below the `Sampled` check.

**4.3 Every woven `[]byte`→`string` conversion heap-allocates, even with IAST disabled or sampled out** — contributing ids: **perf-escape-F1** (root cause), perf-escape-F2/F3/F4 (same never-inlined generic gate family; F3's `copy()` also leaks concat/Join operands); location: `iast/propagation/operators.go:197-204` (`BytesToString` cost 131 > inline budget 80, result escapes before the `HasValues()` gate), `iast/propagation/orchestrion.yml:327-341`, `internal/taint/propagation/string_exact.go:56` / `bytes_exact.go:43` (`copy()` leak). 0→1 alloc (+3–24 B) per conversion in customer code. Severity: **High (CONFIRMED in phase 3, fx-perf-escape-F1)**. Evidence: `evidence/fx-perf-escape-F1/`. Fix: non-generic inlinable gate (`BytesToStringValue` with `//go:noinline` slow path), replace the two `copy()` calls with an index loop; a verified prototype exists (`prototype-fix-v3.patch`).

**4.4 Evidence collector re-hashes the full source for every reported range; unsalted index allows collision-quadratic probes** — contributing ids: **perf-algorithmic-F1, perf-algorithmic-F2**; location: `internal/taint/evidence/evidence.go:209-240,277-291` (per-range full-source hash, 47.78% of samples in `sourceHash`) and `evidence.go:240-277` (unsalted FNV % 512 linear probe; 256 crafted sources → 32640 slot comparisons). Attacker-influenced O(R·S) up to ~29 ms per collection. Severity: **High (CONFIRMED, fx-perf-algorithmic-F1)** / **Medium (F2 CONFIRMED, adjusted High→Medium by phase 3)**. Evidence: `evidence/fx-perf-algorithmic-F1/command-source-output.txt`, `evidence/fx-perf-algorithmic-F2/`. Fix: per-collection source-index cache; process-seeded keyed hash.

**4.5 Sampled-out requests allocate a full Annotation instead of the existing sentinel** — contributing ids: **perf-allocs-matrix-F2, perf-memory-F2**; location: `internal/spans/annotation.go:198-213` (`BindScope` closure allocates `&Annotation{Sampled:false}`, 3200–3456 B) vs the `nonSampledAnnotation` sentinel at `annotation.go:27-29` used by three other sites. ~70% of requests at default 30% sampling pay +3.4 KB. Visible as the s0 residual (+9 allocs HTTPRoundTrip, 8.09% of sampled-out bytes). Severity: Medium (no phase-3 check — reviewer-reported). Evidence: `evidence/perf-allocs-matrix/runner-sampling0/`, `evidence/perf-memory/summary.txt`. Fix: return `nonSampledAnnotation` in the `LoadOrCompute` closure.

Also relevant, lower rank: perf-hotpath-F1 (escaping lazy iterator +32 B/+1 alloc; High→**Medium** after phase 3, CONFIRMED), perf-memory-F3 (`strings.Repeat` clones after budget exhaustion, `internal/taint/propagation/propagation.go:262-316`, Medium, reviewer-reported), perf-contention-F1 (`ownerMu` try-lock drops 15–70% of permitted requests at `internal/taint/store/owner.go:24-61` — **REFUTED** as a defect in phase 3, adjusted Info: store-contention losses are a documented design allowance), crash-stress-app-F3 (`trimStore` lock convoy, Medium, reviewer-reported), crash-stress-app-F4 (woven stress app ~4x lower throughput at 100% sampling, Info).

**Contradictions/caveats between artifacts:** (a) base-bootstrap-F1 rated the +20.4 MB size delta Info while perf-binary-compile-F2 rated the same measurement Medium with tracer attribution — same root cause, the Medium attribution stands here. (b) perf-bench-quality-F1 (Medium, reviewer-reported) shows the headline table understates production cost: nearly every "Active" benchmark measures only the `MayContain` miss path; the genuine hit path is 2–4 orders of magnitude dearer (`sql.Report` clean 15.13 ns vs tainted 93,713 ns, ~6200x; exec ~1900x; tainted Concat4 ~430x). (c) The benchstat micro deltas like `OperatorSlicesInactive` +107.58% are ~2 ns absolute.

## 5. Acceptability for customer production

- **0% sampling (DD_IAST_REQUEST_SAMPLING=0)**: acceptable *for the sampled propagation surface* — all string/bytes/fmt/strconv/url workloads are within noise; HTTPRoundTrip +3.73% sec / +2.17% allocs. NOT acceptable while weak crypto is called (WeakHashNoActiveSpan +122.91%, +4 allocs — ungated report path 4.2) or any request holds writer state (BytesBufferCopies rows unchanged at s0 — 4.1).
- **DD_IAST_ENABLED=false**: restores control allocation counts exactly (verified) except the static conversion allocation (4.3) and writer-receiver escape, which persist in every woven binary.
- **Default 30% sampling / MaxConcurrentRequests=2**: the blend of the above plus ~18 KB per sampled reporting request (4.2), +3.4 KB per sampled-out request (4.5), and the process-wide writer slowdown (4.1) makes current defaults unsuitable for latency-sensitive production services until 4.1–4.3 are fixed. The stress harness measured ~4x lower end-to-end throughput at 100% sampling (crash-stress-app-F4).
- **Build/deploy**: cold-build 6.9x–39x and +20.4 MB on small binaries are documentable fixed costs (cache GOCACHE in CI; warm rebuilds are 6.7 s), not blockers.

## 6. Top 5 perf fixes ranked by impact

1. **Gate writer-state work** (4.1): owners-with-writers bitmask + cheap tracked-pointer filter before any owner-table scan. Removes the only 100x–10000x class regression, and it hits process-wide stdlib `bytes` users.
2. **Early dedup/quota check in the report path** (4.2): hash-then-`WouldDrop` before UUID/stack/model/orphan span. Removes ~28 allocs + ~7 µs per already-recorded call — the steady-state cost of every production service.
3. **Inlinable non-generic conversion gate + copy-loop fix** (4.3): removes an unconditional heap allocation on one of the most common Go idioms, in every woven binary even with IAST off. Prototype v3 already verified.
4. **Evidence-collector source-index cache + seeded hash** (4.4): removes attacker-controlled O(R·S)/quadratic report cost.
5. **`nonSampledAnnotation` sentinel for sampled-out scopes** (4.5): −3.4 KB and −1 alloc-class churn on ~70% of requests at default sampling.

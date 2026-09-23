# perf-binary-compile: compile-time and binary-size overhead of weaving dd-iast-go
Verdict: Every woven build succeeded on go1.26.6. dd-iast-go itself adds only 1-5% binary size (+0.14 to +1.1 MB) and one fixed set of 63 stdlib weave sites. The whole woven pipeline (Orchestrion plus the required dd-trace-go tracer plus dd-iast-go) breaks the brief's thresholds on cold builds: up to 39x wall time and 12.7x size for a trivial `main`. Most of that cost comes from Orchestrion and the tracer, not from dd-iast-go.
Scope covered: `iast/integration/testapp` (`./cmd/bootstrap` binary and the package test binary) and `benchmarks/overhead` (the package test binary, which the runner builds). I built a plain variant, a tracer-only Orchestrion "control" variant (for bootstrap and overhead; `orchestrion.tool.go` with the dd-iast-go imports removed, the same method as `benchmarks/overhead/runner/main.go:476-497`), and the full dd-iast-go variant, each from a fresh empty `GOCACHE`. I also timed a cold self-build of the Orchestrion tool and a warm no-op and one-file-touch rebuild. Woven call sites were counted from the `-work` directories (`$WORK/**/orchestrion/src/**`).

All numbers come from single samples on a shared machine (load average 27-110; see the `loadavg before` column), with `GOFLAGS=-p=4` and `GOTOOLCHAIN=go1.26.6`. Treat wall times as rough and prefer CPU (user+sys) and size, which are stable. The full raw log is `.omo/review/evidence/perf-binary-compile/builds.log` and the tables are in `.omo/review/evidence/perf-binary-compile/summary.md`.

| build | wall s | user+sys s | max RSS MB | binary bytes |
|---|---:|---:|---:|---:|
| bootstrap plain | 4.3 | 3.7 | 302 | 1,749,218 |
| bootstrap control (tracer only) | 44.4 | 156.4 | 916 | 21,098,994 |
| bootstrap full (dd-iast-go) | 167.8 | 283.2 | 966 | 22,194,578 |
| testapp test plain | 116.4 | 86.2 | 397 | 19,921,106 |
| testapp test full | 148.5 | 284.6 | 1090 | 20,065,122 |
| overhead test plain | 11.4 | 57.7 | 383 | 18,273,618 |
| overhead test control | 90.1 | 278.3 | 894 | 19,951,154 |
| overhead test full | 78.7 | 258.4 | 927 | 20,313,298 |
| overhead full, warm no-op rebuild | 6.7 | 16.1 | 410 | 20,313,298 |
| overhead full, warm rebuild after touching `buffer.go` | 13.8 | 17.4 | 412 | 20,313,298 |
| Orchestrion tool self-build (cold) | 120.0 | 111.6 | 983 | 52,836,898 |

| ratio | size | wall | CPU |
|---|---:|---:|---:|
| bootstrap full / plain | **12.69x** (+20.4 MB) | **39.0x** | 75.7x |
| bootstrap full / control (dd-iast-go increment) | 1.05x (+1.10 MB) | 3.8x | 1.8x |
| testapp test full / plain (plain already links dd-iast-go and the tracer) | 1.01x (+0.14 MB) | 1.3x | 3.3x |
| overhead test full / plain | 1.11x (+2.04 MB) | **6.9x** | 4.5x |
| overhead test full / control (dd-iast-go increment) | 1.02x (+0.36 MB) | 0.9x | 0.9x |

Woven call sites (from `.omo/review/evidence/perf-binary-compile/sites-*.txt`):
- bootstrap full: 17 woven files. 10 of them reference dd-iast-go and hold 63 IAST helper call expressions, all in the stdlib: `bytes` 36 (18 `writerbridge.Active` + 18 `writerbridge.Invalidate`), `net/http` 14, `encoding/json` 7, `io` 4, `bufio` 1, `net/url` 1. The `main` package gets the sink bootstrap imports.
- testapp test full: 24 woven files with 78 expressions: the same 63 stdlib sites, plus 13 app-root propagation sites in `chains.go`, `json_chain.go`, and `command_chain.go`, plus 2 in `_test` files.
- overhead test full: 32 woven files with 72 expressions: the 63 stdlib sites, 7 app-root sites (`Buffer*`), and 2 in dd-trace-go (`httptrace`, `contrib/net/http` `BindStartSpan`). `crypto/{md5,sha1,des,rc4}` are also woven through `__dd__iast_ReportWeak*__` linkname stubs, which the alias regex does not count.

## Findings
### perf-binary-compile-F1: A cold woven build takes 6.9x-39x longer than a plain `go build` (brief threshold 5x)
- Severity: Medium
- Category: perf
- Location: iast/integration/testapp/orchestrion.tool.go:11-22; benchmarks/overhead/orchestrion.tool.go:11-16; orchestrion.tool.go:13-27
- Claim: With an empty `GOCACHE`, `go tool orchestrion go build` of the integration bootstrap took 167.8 s wall / 283 CPU-s, against 4.3 s / 3.7 CPU-s for `go build` (39x wall). The overhead benchmark test binary took 78.7 s against 11.4 s (6.9x wall, 4.5x CPU). Most of this is fixed pipeline cost that any dd-iast-go user pays but that dd-iast-go does not cause. The Orchestrion tool must first build itself (about 112 CPU-s cold). The tracer-only control is already 10.3x (bootstrap) and 7.9x (overhead) the plain wall time. dd-iast-go's own increment over the control is 3.8x wall / 1.8x CPU (+127 CPU-s) on bootstrap and within noise on overhead (0.9x). The bootstrap increment is plausibly caused by the `bytes`/`net/http`/`encoding/json`/`io` stdlib weaves, which force the woven stdlib packages and their dependents to recompile against the bridge packages; this cause is not profiled. Warm incremental builds are cheap: 6.7 s for a no-op rebuild and 13.8 s after touching one app file. Peak RSS stayed at or below 1.09 GB, under the brief's 4 GB flag. Note that `/usr/bin/time -l` reports the largest single process, not the sum. The cost is paid by every cold CI build, and customers who build in fresh containers pay it every time.
- Evidence: `.omo/review/evidence/perf-binary-compile/builds.log` (exact commands, stderr tails, and a `RESULT` JSON per build) and `.omo/review/evidence/perf-binary-compile/summary.md`. Command: `cd iast/integration/testapp && GOCACHE=$(mktemp -d) GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l go tool orchestrion go build -work -o bootstrap ./cmd/bootstrap` gives `167.82 real 200.16 user 83.06 sys`, and the same command with plain `go build` gives `4.30 real`. These are single samples at load average 46-110, and the overhead full-vs-control 0.9x shows the noise band.
- Fix: No code fix in dd-iast-go is indicated. Document the expected cold-build cost, and recommend caching `GOCACHE` (which holds the Orchestrion tool binary and the woven stdlib) in customer CI. To reduce the dd-iast-go share, consider narrowing the `bytes` writer-invalidation weave (36 of the 63 stdlib sites) to methods that expose mutable aliases. Add a CI job that records cold woven build CPU time so regressions become visible, because `benchmarks/overhead/README.md:5-6` deliberately excludes compile time.

### perf-binary-compile-F2: A woven small binary is 12.7x (+20.4 MB) larger than plain; dd-iast-go's own share is 1-5%
- Severity: Medium
- Category: perf
- Location: orchestrion.tool.go:26; iast/integration/testapp/orchestrion.tool.go:21
- Claim: The integration bootstrap (`func main() {}`) grows from 1,749,218 to 22,194,578 bytes (12.69x, above the brief's 2x threshold). 19.35 MB of that comes from the dd-trace-go tracer integration, which the dd-iast-go aggregate tool set requires (`orchestrion.tool.go:26`); the tracer-only control is already 21,098,994 bytes. dd-iast-go adds 1,095,584 bytes on top (1.05x). About 160 KB of that is dd-iast-go symbols (`go tool nm -size`); the rest is plausibly stdlib code pulled in by the bridges and sinks (not attributed further). In realistic binaries the ratio falls below the threshold: overhead test 1.11x vs plain (+2.04 MB) and 1.02x vs control (+0.36 MB); testapp test 1.01x (+0.14 MB). The >2x case therefore hits only small binaries that do not already link dd-trace-go (small CLIs and sidecars). It is a fixed cost of about 20 MB that dd-iast-go makes unavoidable by bundling the tracer integration. Earlier node `base-bootstrap-F1` reported the same size delta as Info; this finding adds the attribution.
- Evidence: `.omo/review/evidence/perf-binary-compile/builds.log` and `.omo/review/evidence/perf-binary-compile/summary.md` (the `size_bytes` of each build and the nm totals). Command: as in F1; the sizes are `os.path.getsize` of the `-o` outputs.
- Fix: Document the fixed cost of about 20 MB per executable and that about 95% of it is the tracer. Nothing further is needed in dd-iast-go unless the tracer dependency could become optional, which it cannot under the current span-reporting design.

### perf-binary-compile-F3: 63 stdlib IAST weave sites are compiled into every woven binary, regardless of use
- Severity: Info
- Category: perf
- Location: iast/propagation/orchestrion.yml (bytes writer invalidation); iast/net/http/orchestrion.yml:16-355; iast/encoding/json/orchestrion.yml:12-123; iast/io/orchestrion.yml:13-85
- Claim: The stdlib weave set is identical across all three targets: 63 bridge call expressions in `bytes` (36), `net/http` (14), `encoding/json` (7), `io` (4), `bufio` (1), and `net/url` (1). App-root propagation sites scale with the application's own code (13 in the testapp, 7 in the benchmark). This is by design, and each site is gated by a cheap bridge check, but the 36 `bytes` sites are the largest single contributor to woven-stdlib recompilation.
- Evidence: `.omo/review/evidence/perf-binary-compile/sites-itapp-bootstrap-full.txt`, `.omo/review/evidence/perf-binary-compile/sites-itapp-test-full.txt`, `.omo/review/evidence/perf-binary-compile/sites-overhead-test-full.txt` (per-package and per-helper counts from grepping `$WORK/**/orchestrion/src/**/*.go` for `__orchestrion_*iast*`/`*propagation*` alias calls).
- Fix: None required. This is a data point for F1.

## Checked and found correct
- Every build exited 0 on go1.26.6 with the pinned Orchestrion `23afa71d6dcb`: plain, control, and full variants, test binaries, and warm rebuilds. No compile break (`builds.log`, `rc` field).
- Build-time memory: the peak single-process RSS was at most 1,143,406,592 bytes (testapp test full), well under the brief's 4 GB flag. I did not reproduce the roughly 40 GB peak reported elsewhere for these targets at `-p=4`.
- Warm incremental woven builds are fast (6.7 s no-op, 13.8 s after touching one file), so Orchestrion's cache reuse works and the cost is concentrated in cold builds.
- The cold `GOCACHE` footprint is about 0.9-0.94 GB for woven builds against about 0.36 GB for plain ones (a 2.6x disk cost per cache).
- Woven app-root call sites match the README propagation surface used by the fixtures (`StringsJoin`, `StringsTrimSpace`, `StringsReplace`, `FmtSprintf`, `BytesJoin`, `Builder*`/`Buffer*`, `StringSliceHigh`). No weaving leaked into `internal/**` or `iast/propagation` (none of those packages appear in the woven-file lists).

## Not covered / open questions
- These are single samples on a loaded shared machine. The wall-time ratios can be off by about 2x (compare overhead full vs control, 0.9x). A quiet machine with 5+ repetitions is needed before quoting firm numbers.
- The go1.27.0 toolchain (the machine default and a likely customer choice) was not measured.
- I did not profile where dd-iast-go's +127 CPU-s cold increment on bootstrap goes (Orchestrion aspect resolution vs recompiling woven stdlib dependents). `go build -debug-actiongraph` would answer that.
- The crypto weave sites were not counted numerically (linkname-stub pattern). They appear in the overhead woven-file list only.

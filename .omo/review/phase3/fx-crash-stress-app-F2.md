# fx-crash-stress-app-F2: process-wide bytes.Buffer mutation cost

## Verdict per finding

**crash-stress-app-F2 — CONFIRMED.** At HEAD `2e23b46`, a native `bytes.Buffer` mutation of an untracked object in code without request context scans the writer-owner table whenever *any* owner holds writer state. The important qualification is that an active request **without** writer state does not trigger this slow path. The finder's exact `json.Marshal` ratios were not independently benchmarked; the mechanism and large effect were reproduced with a different workload and real woven HTTP requests.

## Reproduction

Source: `.omo/review/evidence/fx-crash-stress-app-F2/fxwriter_main.go` (place it at `iast/integration/testapp/cmd/fxwriter/main.go` in the private copy). The handler holds sampled requests after `URL.Query().Get("q")` and `Buffer.WriteString(q)` have produced checked taint; the main goroutine calls a **clean**, preallocated `bytes.Buffer.WriteByte` by method value, bypassing the application call-site wrapper. A channel acknowledges handler readiness before each measurement; three samples are sorted and the median printed.

```
cd /tmp/ddiast-review/wt/fx-crash-stress-app-F2/iast/integration/testapp
export GOFLAGS=-p=4
/usr/bin/time -l env GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -o fxwriter ./cmd/fxwriter
GOMAXPROCS=2 ./fxwriter 2
GOMAXPROCS=2 DD_IAST_REQUEST_SAMPLING=100 DD_IAST_MAX_CONCURRENT_REQUESTS=64 ./fxwriter 64
```

Build exited 0 (maximum resident set 435,388,416 bytes, below the 4 GiB reporting threshold). Captured output: `.omo/review/evidence/fx-crash-stress-app-F2/default.out` and `max64.out`. Key lines (ns per clean `WriteByte`, median of three):

| Configuration | No request | Active without writer | One tracked writer | Max tracked writers | After finish |
| --- | ---: | ---: | ---: | ---: | ---: |
| Default 30% sampling, two permits | 6 | 4 | 475 | 227 (two) | 3 |
| Configured 100% sampling, 64 permits | 5 | 5 | 173 | 1,838 (64) | 5 |

The first run's two-owner median falling below its one-owner median shows shared-machine noise; its smallest tracked-writer sample (175 ns) still exceeds its largest baseline sample (13 ns). The 64-owner run had 5 ns/op baseline, 173 ns/op with one writer, and 1,838 ns/op with 64. Ratios are specific to this tiny mutation, not application throughput.

## Reachability

**Yes, with defaults.** `config.go:74-75` defaults to 30% sampling and two concurrent analyses. Ordinary sampled HTTP requests can taint a query value and write it to a buffer; the harness observed `woven=true`, tainted input and output, and `writerActive=true` while an unrelated goroutine did clean writes. Both runs returned `writerActive=false` after owners finished. Go 1.26.6 is the declared supported toolchain. Go 1.27.0 was not benchmarked: the already reported `phase1/base-test-127-F1` encoding/json weave compile break prevents the integration application from running; it is separate from this performance defect.

**Not a documented limitation.** README's propagation coverage explains conservative native invalidation and accepts writer stack escape, not a global scan on clean mutations. The README development-status note does not remove the `AGENTS.md`/`CONTRIBUTING.md` cheap-gate performance rule.

## Adjusted severity

**High (unchanged):** the unnecessary native hot-path work is several times larger than necessary under the default, reachable configuration, and scales with active writer owners; no crash, memory-bound breach, or provenance failure was found here.

## Root cause (file:line)

`iast/propagation/orchestrion.yml:1553-1595` inserts the callback into stdlib `Buffer.Write*`, `Grow`, and `ReadFrom`, independent of the caller's request. `internal/taint/writerbridge/bridge.go:44-49,75-96` gates only on process-global `activeStates` and probes up to four expectation slots before calling the store. `internal/taint/store/writer.go:366-432` checks all 64 owners; each active nonmatching owner reads up to two version words plus eight pointer/start/end triples (26 atomic loads), on top of its active-state load: about 1,728 atomic owner-table loads with 64 active owners.

There is only one finding in this assignment, so no within-list duplicate. `perf-hotpath-F2` shares the costly owner-lookup pattern but concerns *direct application-call wrappers even without a tracked writer*; this finding is the native stdlib hook affecting indirect/library calls only when writer state exists.

## Minimal fix

Keep a bounded, conservative receiver/backing-overlap membership filter that returns immediately for definitely untracked mutations before expectation probes and owner traversal; uncertain or colliding entries must use the existing path to preserve alias invalidation. An atomic owners-with-writers bitset can also skip empty owner records, but **alone** cannot remove the one-writer cost or the 64-writer scan. Preserve publication/removal ordering so the fast negative test can never miss a tracked alias.

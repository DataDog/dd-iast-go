# fx-perf-algorithmic-F2: predictable evidence-index collisions

Reviewed at HEAD `2e23b46` using a private copy, Go 1.26.6 and Go 1.27.0.

## Verdict per finding

- **perf-algorithmic-F2: CONFIRMED.** Distinct attacker-chosen source values can have the same starting slot in the evidence collector. Inserting N such sources makes N(N-1)/2 occupied-slot comparisons, in addition to N empty-slot probes. The original High rating overstates the demonstrated whole-collector impact; adjusted severity is **Medium**.

## Reproduction

Own reproducer: `.omo/review/evidence/fx-perf-algorithmic-F2/review_collision_independent_test.go`; captured command output: `.omo/review/evidence/fx-perf-algorithmic-F2/repro-output.txt`. It independently calculates collision values, checks the actual runtime slots, manages cookie sources via the HTTP source callback, and calls the command sink's `evidence.CollectJoinedStrings`. The `occupiedComparisonsByIndex` log field is arithmetic from the verified probe sequence, **not** an instrumented comparison counter.

To rerun, from the repository root:

```sh
mkdir -p /tmp/ddiast-review/wt
rsync -a --exclude .git --exclude .omo ./ /tmp/ddiast-review/wt/fx-perf-algorithmic-F2/
cp .omo/review/evidence/fx-perf-algorithmic-F2/review_collision_independent_test.go /tmp/ddiast-review/wt/fx-perf-algorithmic-F2/internal/taint/evidence/
cd /tmp/ddiast-review/wt/fx-perf-algorithmic-F2
env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test -mod=readonly -run '^TestReviewCollision' -v -bench '^BenchmarkReviewIndependent(CommandCollectionLong|IndexOnly)$' -benchmem -benchtime=300ms -count=2 -cpu=1 -timeout 5m ./internal/taint/evidence
env GOFLAGS=-p=4 GOTOOLCHAIN=go1.27.0 go test -mod=readonly -run '^TestReviewCollision' -v -count=1 -timeout 5m ./internal/taint/evidence
```

Key output: `count=256 firstSlot=0 occupiedComparisonsByIndex=32640 sources=256 parts=511 args=256 defaultMaxRanges=10`; a distinct-slot control has `occupiedComparisonsByIndex=0` and the same source/part counts. The 100-byte common-prefix case collects a 27,647-byte command value, within the 32 KiB analyzer limit. The 247-byte case collects 65,279 bytes, within the collector's 64 KiB limit. Both tests pass on both Go versions. At 256 sources with a 100-byte common prefix, the full collector measured 619,832/669,694 ns/op with collisions versus 254,159/351,291 ns/op without; isolated index insertion measured 287,047/274,751 versus 53,240/46,765 ns/op. The shared host makes absolute timing noisy; the exact probe count does not depend on timing.

## Reachability

**Reachable with default configuration when a request is sampled.** `Request.Cookies()` advice visits every returned cookie (`iast/net/http/orchestrion.yml:303-328`), and `request.ManageCookie` admits separate values with the same one-byte cookie name (`internal/taint/request/lazy.go:141-159`). `Cmd.Start` reports attempted process starts through `iast/os/exec/exec.go:42-70`, which passes up to 256 arguments to `CollectJoinedStrings`. Each managed cookie occupies one range, so the default ten-range-per-value limit does not prevent this path. IAST is enabled by default with 30% sampling and two analysis permits; the test sets **only sampling to 100%** to make admission deterministic. The test exercises the real internal callbacks and collector, not a woven executable or an actual process start.

**Not a documented limitation.** The README notes unstable performance, and the design documents fixed source/range limits, but neither accepts a predictable collision set at report time. The extra comparisons violate the product rule to minimize host-path overhead even though the bound is respected.

## Adjusted severity

**Medium (original: High):** the worst case is fixed at 256 distinct report sources and 512 probe slots, requires many same-name attacker-controlled cookie values to reach one large command report, and produced roughly 2× full-collector cost in the repeatable 27 KiB example. It does not change application behavior, exceed a memory bound, or establish a several-fold increase in the complete sink call. The isolated index alone was roughly 5–6× slower.

## Root cause

`internal/taint/evidence/evidence.go:240-291`: `sourceHash` is unsalted FNV, `sourceIndex` uses `hash % 512`, and linear probing compares each occupied source's full identity. At most 256 sources are inserted, but an offline-constructed same-slot set forces the quadratic sequence. The request source table uses a randomized `maphash` seed (`internal/taint/request/table.go:194-219`), so it does not prevent the **separate** evidence-index collision. Only F2 was submitted here; F1's repeated full-value hashing is a distinct cost at the same collector seam, not a duplicate of F2.

## Minimal fix

Seed the evidence index with a process-random `hash/maphash` seed, preserving 512 fixed slots, the 256-source limit, and exact `(origin, name, value)` equality on probes. Keep the cheap collection eligibility gate. A keyed starting slot prevents offline collision construction without changing report identities or memory bounds.

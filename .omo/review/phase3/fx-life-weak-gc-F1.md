# fx-life-weak-gc-F1: sampled-out spans exhaust reporting capacity

Verdict: **CONFIRMED**. An admitted HTTP analysis can have no annotation or reporting fallback while the only occupied annotation slots belong to sampled-out requests. This node tests one finding; there are no duplicate IDs to consolidate.

## Verdict per finding

### life-weak-gc-F1 — CONFIRMED

At HEAD `2e23b46`, `BindScope` inserts `&Annotation{Sampled: active}` even when `scope.Active()` is false. Two live sampled-out roots fill the default two-entry allowance. The next sampled request gets a real analysis owner, but `BindScope` returns nil because `trimStore` evicts only collected keys. `ExistingForOwner` and `ExistingForSpan` cannot find a reporting annotation, and `NewOrphanTaintedSpan` fails the same capacity check. `selectTaintedAnnotation` then offers neither a bound span nor an orphan; `ReportTainted` returns false. The request continues paying analysis cost but cannot emit findings.

## Reproduction

Independent reproducer: `.omo/review/evidence/fx-life-weak-gc-F1/review_independent_starvation_test.go`; captured runs: `.omo/review/evidence/fx-life-weak-gc-F1/review-independent-output.txt`. Place the test in `internal/spans/` of an isolated checkout, then run from its root:

```sh
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -count=1 -timeout 12m -run '^TestIndependentActiveRequestKeepsItsReportingSlot$' -v ./internal/spans/
GOTOOLCHAIN=go1.27.0 GOFLAGS=-p=4 go test -count=1 -timeout 12m -run '^TestIndependentActiveRequestKeepsItsReportingSlot$' -v ./internal/spans/
```

Both commands exit 1 **because the regression assertion fails**, not because of build errors. Key output on each:

```text
default capacity=2 negative roots=2 active=true annotation=false ownerBound=false spanBound=false orphanAnnotation=false
admitted active analysis has neither a bound reporting annotation nor orphan reporting capacity
--- FAIL: TestIndependentActiveRequestKeepsItsReportingSlot
```

The test checks the actual loaded defaults (`enabled=true`, sampling `30`, maximum concurrent analyses `2`), then temporarily sets sampling to `0` for two rejected but live HTTP scopes and to `100` for the admitted third scope. This forces a possible default-rate outcome deterministically rather than relying on random draws. An independent enumeration of sampling outcomes under default 30% with two slots gives expected lost/admitted analyses of 31.3%, 45.9%, 64.4%, and 69.6% at 3, 4, 8, and 16 in-flight requests respectively, consistent with the originating report's approximate rates. These percentages describe this ordered, overlapping-request model, **not measured production traffic**.

## Reachability

Ordinary instrumented HTTP requests can reach this sequence. The HTTP aspect creates a scope at `iast/net/http/orchestrion.yml:16-45`; the tracing call and handler advice bind its span at lines 50-122. `request.BeginServerContext` makes the 30% decision independently of span annotation admission. The default capacity of two and sampling of 30% are in `internal/config/config.go:73-74` and the README Runtime Configuration table. Go 1.26.6 and 1.27.0 both reproduce through the internal scope/span API; this verifier did not run a woven HTTP build.

The README Cost Control section and the design-intent map document *sampling* and dropping provenance on genuine capacity exhaustion, **not** allowing sampled-out requests to consume the capacity promised to concurrently admitted analyses. Negative span-decision caching is intentional in `annotation.go` and tested in `annotation_sampling_test.go`, but this particular starvation is not a documented, accepted limitation. Even treating it as an intentional capacity trade-off would violate the stated accurate-provenance rule for admitted supported paths.

## Adjusted severity

**High (unchanged):** complete false-negative reporting for admitted, supported HTTP requests under ordinary default concurrency; the observed behavior is not a crash, unbounded memory use, or universal permanent disablement.

## Root cause (file:line)

`internal/spans/annotation.go:198-212` inserts negative scope decisions into the same bounded map as positive decisions; `annotation.go:227-236` removes only dead weak keys and measures **all** entries against `MaxConcurrentRequests`. `internal/spans/vulnerability.go:21-33` applies the same limit to orphans, and `internal/vulnerability/tainted.go:99-118` drops the resulting unbound report.

## Minimal fix

Reserve `MaxConcurrentRequests` admission capacity for positive/request-active annotations. Preserve negative root decisions in separate, bounded storage or a span-associated decision so a context-free later sink cannot resample a rejected root; negative occupancy must not prevent an admitted analysis from binding. Add a regression test with two live sampled-out roots followed by one admitted request, asserting a bound annotation and an emitted report.

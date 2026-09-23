# fx-prop-engine-core-F1: empty split fields and the window budget

Verdict: Both reports are CONFIRMED. They describe the same supported-path false negative.

Scope covered: `internal/taint/propagation/propagation.go`, direct `strings.Split`/`bytes.Split` weaving rules and wrappers, README/design limits, and a private-copy woven reproducer.

## Verdict per finding

### prop-engine-core-F1: CONFIRMED

`StringWindows` and `ByteWindows` document a cap of 32 non-empty published windows, but their loops break on `outputIndex >= maxWindows` before ignoring empty outputs. With 32 leading commas, index 32 is the first non-empty alias (`"attack"`) and is never derived. The independent woven reproducer observes it as clean for both string and byte paths.

### prop-string-exact-F1: CONFIRMED

This is the string-only instance of `prop-engine-core-F1`, with the same condition and same root cause. It is a duplicate, not a separate defect.

## Reproduction

Private copy: `/tmp/ddiast-review/wt/fx-prop-engine-core-F1`.

```sh
GOWORK=off GOTOOLCHAIN=go1.26.6 GOFLAGS='-p=4' \
  /usr/bin/time -l go -C /tmp/ddiast-review/wt/fx-prop-engine-core-F1 \
  tool orchestrion go test ./iast/propagation \
  -run '^TestReviewFxSplitKeepsFirstNonEmptyAfterEmptyPrefix$' \
  -count=1 -timeout=5m -v
```

The new reproducer invokes ordinary direct calls in the root test app (`strings.Split` and `bytes.Split`) under Orchestrion, with request-scoped public taint sources. It fails:

```text
string part[32]="attack" tainted=false
bytes part[32]="attack" tainted=false
--- FAIL: TestReviewFxSplitKeepsFirstNonEmptyAfterEmptyPrefix
```

Reproducer and captured output: `.omo/review/evidence/fx-prop-engine-core-F1/reproducer_test.go` and `.omo/review/evidence/fx-prop-engine-core-F1/go1.26.6-woven.out.txt`.

The attempted Go 1.27.0 woven run did not reach this test: pinned Orchestrion generated `encoding/json` code referencing missing `Decoder.r` and `Decoder.d` fields. That independent toolchain build failure is recorded in `go1.27.0-woven-build.out.txt` and is not used to establish this verdict.

## Reachability

Reachable under default configuration on a sampled request: IAST defaults to enabled, 30% request sampling, and two concurrent analyses. `Split*` is explicitly advertised for string and byte windows, and the weaving rules replace direct root-application calls to `strings.Split` and `bytes.Split`. An HTTP-derived value containing 32 leading delimiters can therefore lose its first non-empty field before a supported SQL or command sink.

This is not a documented limitation. README and design intent specify 32 **published windows** and state empty results are untainted; neither says empty output positions consume the non-empty budget.

## Adjusted severity

Both findings remain **High**: this loses provenance on documented, woven string/byte Split paths and can suppress a vulnerability report with a small customer-controlled input.

## Root cause

Same root cause for both: `internal/taint/propagation/propagation.go:239-253` and `:522-536`. Each loop tests the raw output index against `maxWindows` before `len(output) == 0` is skipped, despite the contract and counter naming requiring a non-empty-window limit.

## Minimal fix

For both helpers, iterate outputs until 32 eligible non-empty alias windows have been derived; do not use the raw slice index as the cap. On encountering a 33rd eligible window, call `recordDropped()` and stop. This preserves the publication bound while scanning only until the first actually dropped contribution; a managed input is already bounded to the root-size limit.

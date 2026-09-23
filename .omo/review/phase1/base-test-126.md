# base-test-126: Go 1.26.6 instrumented and plain test matrix
Verdict: PASS — all six required suites exited 0 with Go 1.26.6; no failing packages, and no instrumentation-dependent test skipped under Orchestrion.
Scope covered: private copy `/tmp/ddiast-review/wt/base-test-126`; required root and nested-module test commands; verbose audit reruns used only to capture shuffle seeds and test-level skip events.

## Findings

None.

## Checked and found correct

- Toolchain: `GOTOOLCHAIN=go1.26.6 go version` reported
  `go version go1.26.6 darwin/arm64`.
- Root instrumented command:
  `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -shuffle=on -timeout 20m ./...`
  exited 0. Package outcomes: PASS 36, FAIL 0, test SKIP 0, no-test-files 3.
  The 36 per-package shuffle seeds from the verbose audit were:
  `1790157516506662000`, `1790157527414445000`, `1790157529309524000`,
  `1790157529884121000`, `1790157530300212000`, `1790157530842607000`,
  `1790157531399141000`, `1790157532104424000`, `1790157532592639000`,
  `1790157533104762000`, `1790157533605565000`, `1790157534209505000`,
  `1790157534695743000`, `1790157553048086000`, `1790157553664370000`,
  `1790157554894953000`, `1790157554402428000`, `1790157555248707000`,
  `1790157553608100000`, `1790157556110150000`, `1790157554496465000`,
  `1790157556531404000`, `1790157556892163000`, `1790157557466568000`,
  `1790157558414752000`, `1790157557925705000`, `1790157558806810000`,
  `1790157559254013000`, `1790157558889933000`, `1790157560083551000`,
  `1790157563620571000`, `1790157564666289000`, `1790157564321032000`,
  `1790157565501655000`, `1790157564761748000`, `1790157565427521000`.
- Root plain command:
  `GOTOOLCHAIN=go1.26.6 go test -shuffle=on -timeout 20m ./...`
  exited 0. Package outcomes: PASS 36, FAIL 0, test SKIP 77, no-test-files 3.
  The plain-suite skips are expected instrumentation-dependent tests. Its 36
  per-package shuffle seeds were:
  `1790157650405717000`, `1790157654842254000`, `1790157655421898000`,
  `1790157656548899000`, `1790157655918634000`, `1790157655530667000`,
  `1790157657817088000`, `1790157660741861000`, `1790157656770523000`,
  `1790157658366972000`, `1790157657108756000`, `1790157657987424000`,
  `1790157659255972000`, `1790157659094084000`, `1790157659892402000`,
  `1790157659512700000`, `1790157661110468000`, `1790157661216872000`,
  `1790157661671023000`, `1790157662010561000`, `1790157662331439000`,
  `1790157662724012000`, `1790157663106234000`, `1790157663572930000`,
  `1790157663921045000`, `1790157664626505000`, `1790157664790758000`,
  `1790157665050554000`, `1790157665419237000`, `1790157665875866000`,
  `1790157666203821000`, `1790157666573828000`, `1790157667303985000`,
  `1790157667424560000`, `1790157667774033000`, `1790157668295218000`.
- Nested instrumented commands all exited 0:
  - `iast/database/sql/testapp`: PASS 1, FAIL 0, test SKIP 0,
    no-test-files 1; seed `1790157697764077000`.
  - `iast/os/exec/testapp`: PASS 1, FAIL 0, test SKIP 0,
    no-test-files 1; seed `1790157717577119000`.
  - `iast/integration/testapp`: PASS 1, FAIL 0, test SKIP 0,
    no-test-files 2; seed `1790157764006103000`.
  - `benchmarks/overhead`: PASS 2, FAIL 0, test SKIP 2; seeds
    `1790157889853598000`, `1790157891469806000`. The two skips were
    `TestWovenVariant` and `TestControlVariant`; both explicitly state that
    variant validation belongs to the overhead benchmark runner, so neither is
    an instrumentation-dependent test skipped under Orchestrion.
- No package failed in any required command. Failure classification reruns were
  therefore not applicable.
- Raw required-command output and relevant verbose-audit output are captured in
  `base-test-126.log`.

## Not covered / open questions

- This node ran only the requested instrumented/plain test matrix. It did not
  run race tests, static analysis, benchmarks, or manual benchmark-runner
  validation.

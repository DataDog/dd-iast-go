# base-race: repeated race-detector baseline
Verdict: No data races or test timing flakiness were observed in the mandated plain and Orchestrion-instrumented repeated test runs.
Scope covered: Private copy `/tmp/ddiast-review/wt/base-race`; the root module and `iast/integration/testapp`, `iast/database/sql/testapp`, and `iast/os/exec/testapp` nested modules, all with `GOTOOLCHAIN=go1.26.6`.

## Findings

No findings.

## Checked and found correct

- Plain root suite: `GOTOOLCHAIN=go1.26.6 go test -race -count=3 -shuffle=on -timeout 25m ./...` exited 0. The repeated run completed without `WARNING: DATA RACE`, failed tests, timeout output, or other timing-flakiness signals.
- Root instrumented suite: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -race -count=2 -shuffle=on -timeout 25m ./...` exited 0. No race report or failed/timed-out package appeared.
- Instrumented integration testapp suite: the mandated command in `iast/integration/testapp` exited 0; `testapps/integration` completed in 241.271s without a race report.
- Instrumented SQL testapp suite: the mandated command in `iast/database/sql/testapp` exited 0; `testapps/database-sql` completed in 2.667s without a race report.
- Instrumented command-execution testapp suite: the mandated command in `iast/os/exec/testapp` exited 0; `testapps/os-exec` completed in 19.576s without a race report.
- Raw captured terminal output and exact commands are recorded in `base-race.log`.

## Not covered / open questions

- This execution-based review does not establish absence of races outside the exercised test paths.

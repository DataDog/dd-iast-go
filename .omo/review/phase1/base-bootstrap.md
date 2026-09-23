# base-bootstrap: CI executable bootstrap symbol checks for nested testapps

Verdict: PASS — all three bootstrap fixtures build with the pinned orchestrion injector on go1.26.6, and every symbol declared in `cmd/bootstrap/symbols.txt` is present in the woven binaries; no missing-symbol (High) findings.

Scope covered: `.github/workflows/ci.yml` ("Sink executable bootstrap tests" step); `iast/database/sql/testapp`, `iast/os/exec/testapp`, `iast/integration/testapp` (`cmd/bootstrap/symbols.txt`, `go.mod`); woven and plain builds of each `./cmd/bootstrap` with `go tool nm` symbol verification, binary sizes, and single-sample build timings.

## Findings

### base-bootstrap-F1: Woven bootstrap binaries are ~12.7x larger than plain builds (~20.4 MB overhead each)
- Severity: Info
- Category: perf
- Location: iast/database/sql/testapp/cmd/bootstrap/symbols.txt:1-2 (all three testapps affected)
- Claim: Weaving adds ~20.4 MB of static binary size per executable (woven ~22.1 MB vs plain ~1.75 MB; overhead 20,390,608 / 20,387,984 / 20,445,360 bytes for sql / exec / integration). This static size increase is consistent across all three fixtures. The observed woven build times were 6.410 / 230.515 / 92.342 seconds and plain build times were 1.314 / 1.369 / 0.392 seconds, respectively. These are single observations on a shared machine and are not representative benchmarks.
- Evidence: `.omo/review/evidence/base-bootstrap/measurements.log` contains the exact build commands, successful exits, measured sizes, timings, and `go tool nm` matches.
- Fix: None required; record the per-executable size overhead in the docs so customers can budget for it. Revisit if the weaver can dead-strip IAST code paths unused by the woven app.

## Checked and found correct
- Mirrored the CI step exactly for each of the three modules with `cmd/bootstrap/symbols.txt`: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -o <bin> ./cmd/bootstrap`, then `go tool nm <bin>` and `grep -F -- <symbol>` per line of `symbols.txt`. All checks exited 0.
- sql testapp: `github.com/DataDog/dd-iast-go/iast/database/sql.init.0` (0x100548c40, T) and `github.com/DataDog/dd-iast-go/internal/spans.Finished` (0x10053d310, T) both present.
- exec testapp: `github.com/DataDog/dd-iast-go/iast/os/exec.init.0` (0x100547530, T) and `spans.Finished` (0x10053da30, T) both present.
- integration testapp: all four expected symbols present (`iast/database/sql.init.0`, `iast/encoding/json.init.0`, `iast/os/exec.init.0`, `internal/spans.Finished`), confirming the integration fixture pulls all three sink/decoder weaves into one binary.
- `spans.Finished` resolves to real text symbols with deferwrap helpers, i.e. the sink report path is linked, not dropped by the linker.
- Woven builds compile cleanly (exit 0, no warnings) on go1.26.6 with the pinned orchestrion pseudo-version — no compile/link failure on the fixtures.

## Not covered / open questions
- Behavior of the produced binaries at runtime (whether the woven sinks actually fire end-to-end) is out of scope here; the integration test suite and later phases cover it.
- Timings are single samples on a machine shared with other agents; only the size overhead is treated as a stable measurement.
- An earlier untimed SQL woven build completed during recovery; its reported 6.410-second timing is from the subsequent measured invocation and may reflect a warm Go build cache.
- Cleanup blocker: mid-session the host runtime applied a seatbelt sandbox that forbids writes outside its own tmp dir, so `rm -rf /tmp/ddiast-review/wt/base-bootstrap` fails with "Operation not permitted". The private copy therefore still exists (it contains only copies of read-only repo content plus build artifacts; nothing in the main checkout was touched — `git status --porcelain` is empty outside `.omo/`). Remove it manually with: `rm -rf /tmp/ddiast-review/wt/base-bootstrap`.

# Review brief: dd-iast-go taint-tracking branch (applies to every review node)

## Target
- Repository (MAIN CHECKOUT, READ-ONLY): /Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go
- Branch: romain.marcadier/taint-tracking (HEAD 2e23b46). Merge-base with origin/main: 1135a291dcb3c424c870ce1978c3ede6dbd1470b
  - Branch diff: `git -C <repo> diff 1135a291dcb3c424c870ce1978c3ede6dbd1470b -- <path>`
  - Pre-existing (non-branch) code is also in scope. The user asked to review the whole repo.
- What the code does: this is Datadog IAST (Interactive Application Security Testing) for Go. It is woven into CUSTOMER applications at compile time by Orchestrion (github.com/DataDog/orchestrion) through the `orchestrion.yml` files under `iast/` and `taint/`. HTTP request data (sources) is tainted. Taint ranges propagate through strings, `[]byte`, `strings`/`bytes`/`fmt`/`strconv`/`net/url` calls, operators (`+`, slicing, conversions), `strings.Builder`/`bytes.Buffer` writers, and `encoding/json` decoding. Vulnerabilities are reported when tainted data reaches the `database/sql` (SQLi) or `os/exec` (CMDi) sinks. Evidence and sources are redacted, and results are attached to dd-trace-go spans.
- Status: a PROOF OF CONCEPT that WILL reach customers. CORRECTNESS IS THE TOP PRIORITY.

## Non-negotiable product rules (from AGENTS.md / CONTRIBUTING.md)
1. NEVER break the host application: no panic, no deadlock, no behavior change in wrapped stdlib calls, no compile failure on valid customer code.
2. NEVER slow the host more than strictly necessary. Expensive work is gated behind cheap checks.
3. NEVER leak memory. All storage has a hard maximum footprint, and data is dropped when saturated.
4. ALWAYS keep accurate provenance: no false taint, no lost taint on supported paths, and no cross-request taint bleed.

## Toolchain facts
- go.mod declares `go 1.26.6`. The plan targets exactly Go 1.26.6 (`GOTOOLCHAIN=go1.26.6`, already in the module cache). The machine default is go1.27.0, which customers will also use.
- Orchestrion is pinned to a pseudo-version `v1.12.2-0.20260828141217-23afa71d6dcb` from the UNMERGED orchestrion branch `romain.marcadier/iast-operator-join-points`. A clone is at /Users/eliott.bouhana/go/src/github.com/DataDog/orchestrion; use `git -C` on it and do not check out branches there, only `git show <rev>:<path>` or `git diff`.
- Instrumented tests: `go tool orchestrion go test ./...`. Plain tests: `go test ./...`. Instrumentation-dependent tests skip without orchestrion.
- Nested modules with their own go.mod: iast/database/sql/testapp, iast/os/exec/testapp, iast/integration/testapp, benchmarks/overhead.
- Static checks used by CI: gofmt, `go tool checklocks ./...`, `go vet ./...`.
- Many sibling repos are cloned at /Users/eliott.bouhana/go/src/github.com/DataDog/ (dd-trace-go, dd-trace-java, dd-trace-js, dd-trace-py, system-tests). Use them for cross-language IAST semantics.

## HARD RULES for every node
- NEVER modify, create, or delete anything in the main checkout except under `.omo/review/`. No git commits, no branch switches, no `go mod tidy` there, and no fuzz runs there, since fuzzing writes testdata.
- For ANY command that builds, tests, fuzzes, benchmarks, or needs scratch files, create a PRIVATE COPY:
  `mkdir -p /tmp/ddiast-review/wt && rsync -a --exclude .git --exclude .omo /Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/ /tmp/ddiast-review/wt/<NODE_ID>/`
  Work there. Put reproducer tests and harnesses there. Before you finish, copy every reproducer and captured output you rely on into `.omo/review/evidence/<NODE_ID>/`. Then `rm -rf /tmp/ddiast-review/wt/<NODE_ID>` and confirm it is gone.
- The machine is shared with up to 15 other agents. Bound every command with a timeout (for example `go test -timeout 15m`) and do not run commands that take more than 25 minutes. Do not run wall-clock benchmarks unless your task says so, because timings are noisy while other agents compile.
- MACHINE LOAD: the machine hit a load average above 200, and one woven build peaked near 40 GB of memory. Run ONE heavy build, test, or fuzz command at a time, never several in parallel. Export `GOFLAGS=-p=4` for builds and tests, and use `-parallel=2` for fuzzing. Wrap woven (orchestrion) builds in `/usr/bin/time -l` and note the peak RSS if it exceeds 4 GB. That is itself a finding (build-time memory).
- YOUR NODE ENDS THE MOMENT YOU REPLY WITHOUT A TOOL CALL. NEVER end your turn while a background command, fuzz run, or test is still running. Run long commands in the FOREGROUND with an explicit timeout of up to 1800s. If a command detaches into a background session anyway, keep reading its output with bash_output until it exits, and only then continue. A phase-1 wave lost four nodes this way.
- Evidence standard: every finding rated Critical or High MUST include a REPRODUCER, meaning a test file, fuzz input, program, or exact command, plus the CAPTURED OUTPUT that shows the failure. If you cannot reproduce a suspected Critical or High issue, rate it at most Medium with `Evidence: static reasoning only`, give the exact line-level argument, and tag it `NEEDS-REPRO`.
- Do not re-report documented, deliberate limitations (README "Propagation coverage", "Sink coverage", and the plan docs) as bugs. You MAY challenge a documented trade-off when it breaks one of the four product rules, as severity Medium or higher with the argument.
- Be concrete: file:line references against HEAD 2e23b46, with minimal code quotes.

## Severity scale
- Critical: crash or panic or deadlock reachable from customer code; data race in production code; wrapped stdlib call returning a different result or side effect than uninstrumented Go; unbounded memory growth; compile or link failure on valid customer code; sensitive data leaving the process unredacted.
- High: wrong provenance on a SUPPORTED path (false-positive or false-negative vulnerability, taint bleeding across requests or owners, stale taint on reused memory); a bound that can be exceeded by a large factor; a permanent IAST self-disable (for example a leaked admission slot); a hot-path overhead regression several times larger than necessary.
- Medium: an incorrect edge case with limited impact; a missing guard for unlikely input; a significant test gap on a risky path; a misleading doc about behavior.
- Low: code quality, naming, dead code, minor inefficiency.
- Info: an observation or suggestion.

## Report contract (EVERY node)
Write exactly two files:
1. `.omo/review/<PHASE_DIR>/<NODE_ID>.md`, at most about 5k tokens:
```
# <NODE_ID>: <title>
Verdict: <one line: overall correctness verdict for your scope>
Scope covered: <files/functions actually read or run>
## Findings
### <NODE_ID>-F1: <short title>
- Severity: Critical|High|Medium|Low|Info
- Category: crash|race|deadlock|leak|memory-bound|provenance|false-positive|false-negative|cross-request|behavior-change|compile-break|perf|redaction|quality|test-gap|doc|config|ci
- Location: path/to/file.go:LINE[-LINE]
- Claim: <what is wrong, precisely>
- Evidence: <reproducer path under .omo/review/evidence/<NODE_ID>/ + exact command + key captured output lines> | static reasoning only (NEEDS-REPRO)
- Fix: <suggested minimal fix>
## Checked and found correct
<bullets: what you verified is correct, and how>
## Not covered / open questions
<bullets>
```
2. `.omo/review/<PHASE_DIR>/<NODE_ID>.findings.json`: a JSON array with one object per finding, with keys `id`, `severity`, `category`, `location`, `title`, `claim`, `evidence_path` (string or null), `repro_command` (string or null), and `needs_repro` (bool). Use `[]` when there are no findings. It MUST parse: verify with `python3 -m json.tool <file> >/dev/null`.

## Shared context produced in phase 1 (read these first once they exist)
- `.omo/review/phase1/00-architecture.md`: component map, data flow, and invariants
- `.omo/review/phase1/01-design-intent.md`: the plans' intended design and documented limitations
- `.omo/review/phase1/research/00-digest.md`: lessons from the Orchestrion research PR (DataDog/orchestrion#858)
- `.omo/review/phase1/base-*.md`: baseline test, race, static, and toolchain results

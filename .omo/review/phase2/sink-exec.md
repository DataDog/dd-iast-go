# sink-exec: command-injection sink (iast/os/exec, commandbridge, redaction/command.go)
Verdict: The Start-attempt boundary, the context and owner fallback, Start-twice handling, Env/Dir exclusion, and joined range mapping are correct and preserve host behavior. There is one reproduced High false negative: a tainted `Cmd.Path` that differs from `Args[0]` is executed but never inspected.
Scope covered: iast/os/exec/{exec.go,orchestrion.yml,exec_test.go,orchestrion.tool.go}, iast/os/exec/testapp/{exec_test.go,source_shape_test.go,cmd/bootstrap}, internal/taint/commandbridge/{bridge.go,bridge_test.go}, internal/taint/redaction/{command.go,analyzer.go,analyzer_test.go,source.go}, internal/taint/evidence/evidence.go (CollectJoinedStrings, matchesJoin, canonicalize/buildParts), internal/vulnerability/{tainted.go,report.go SkipWhile}, and the stdlib os/exec/exec.go for Go 1.26.6 and 1.27.0 (Command, CommandContext, argv, Start). I ran 9 new instrumented reproducers plus the existing testapp suite with `go tool orchestrion go test` on Go 1.26.6 and on Go 1.27.0.

## Findings
### sink-exec-F1: A tainted Cmd.Path is not evidence when it differs from Args[0]
- Severity: High
- Category: false-negative
- Location: iast/os/exec/orchestrion.yml:59-78; iast/os/exec/exec.go:42-60
- Claim: The advice receives `__dd_iast_path` (`lp`, which is `c.Path` on Unix), the binary that `os.StartProcess` actually executes. It forwards only `__dd_iast_argv` (`c.argv()` = `c.Args`) to `__dd__iast_ReportCommand__`. `Report`, `mayContainArgument`, `AnalyzeCommand`, and `CollectJoinedStrings` look only at argv, so they never see the executed path. Setting `cmd.Path = userInput` after `exec.Command`, or building `&exec.Cmd{Path: userInput, Args: []string{"name", ...}}`, runs an attacker-chosen executable without a report. Detection works only when `Args` is nil (argv() falls back to `[]string{c.Path}`) or when `Args[0]` shares the tainted string. On Windows, `lp` comes from `lookExtensions` and is a fresh untainted string, so the fix must read `c.Path` rather than `lp`.
- Evidence: .omo/review/evidence/sink-exec/review_sinkexec_test.go (TestReviewTaintedPathWithCleanArgs). Command: `cp .omo/review/evidence/sink-exec/review_sinkexec_test.go iast/os/exec/testapp/ && cd iast/os/exec/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-mod=mod go tool orchestrion go test -count=1 -v -run 'TestReview' .`. Output (.omo/review/evidence/sink-exec/go1.26.6-output.txt, and the same in go1.27.0-output.txt): `run err=fork/exec /definitely/not/a/real/attacker-binary: no such file or directory path="/definitely/not/a/real/attacker-binary" args=["ls"]`, `FINDINGS=0`, `--- FAIL: TestReviewTaintedPathWithCleanArgs`. The control case TestReviewTaintedPathNilArgs (Args nil) reports `FINDINGS=1`.
- Fix: Pass `{{ .Function.Receiver }}.Path` into the bridge: `Report(ctx, path, argv)`. In `Report`, also gate on `MayContain(StringKey(path))`. When `path != argv[0]` and the path may be tainted, analyze and collect over `[]string{path, argv[1:]...}`, which is the executed command line and matches `Cmd.String()`. Otherwise keep the current argv behavior, so an untainted LookPath result never displaces a tainted `Args[0]`. Add a testapp case for `cmd.Path = tainted` with a clean `Args`.

### sink-exec-F2: Windows SysProcAttr.CmdLine bypasses the argv evidence
- Severity: Medium
- Category: false-negative
- Location: iast/os/exec/orchestrion.yml:59-78; iast/os/exec/exec.go:42
- Claim: On Windows, `syscall.StartProcess` uses `attr.Sys.CmdLine` verbatim when it is non-empty and ignores argv (`syscall/exec_windows.go:346-351` in Go 1.27.0). Go's own `exec.Command` docs recommend `CmdLine` for `cmd.exe` and batch files, so `cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: "cmd /c " + input}` is the standard way to shell out on Windows. The sink never inspects `__dd_iast_attr.Sys`, so the tainted command line is not reported, and when argv is tainted the evidence does not match what actually runs. README "Sink coverage" does not mention this limit.
- Evidence: static reasoning only (NEEDS-REPRO); Windows is not available on this host.
- Fix: Put the CmdLine check in a `windows`-only file, such as a build-tagged helper that reads `attr.Sys.CmdLine`. When it is non-empty, collect evidence from it with `CollectString` and command redaction. Otherwise document the limit in README Sink coverage.

### sink-exec-F3: Existing tests miss the risky exec boundary cases
- Severity: Low
- Category: test-gap
- Location: iast/os/exec/testapp/exec_test.go
- Claim: No committed test covers `Cmd.Path` diverging from `Args[0]` (F1), nil `Args`, a second `Start`, tainted `Env` or `Dir` (must not report), a canceled `CommandContext` (no attempt), or offset mapping with several tainted arguments, empty arguments, and arguments containing spaces. All but F1 behave correctly today (see below), but none is pinned by a test.
- Evidence: .omo/review/evidence/sink-exec/review_sinkexec_test.go, cases R2-R9, all passing on Go 1.26.6 and 1.27.0.
- Fix: Move the reviewer cases, minus the logging, into testapp/exec_test.go.

### sink-exec-F4: Joined evidence does not show argument boundaries
- Severity: Info
- Category: quality
- Location: iast/os/exec/exec.go:52-56; internal/taint/redaction/command.go:25
- Claim: Evidence joins argv with a single ASCII space and no quoting. `["--","x y",tainted]` and `["--","x","y",tainted]` produce the same evidence string (TestReviewJoinedRangeMapping part[0] `"... -- x y "`). This matches the Java and Python tracers, which also space-join, and redaction hides everything after argv[0] by default. Only an unredacted view is ambiguous.
- Evidence: .omo/review/evidence/sink-exec/go1.26.6-output.txt (TestReviewJoinedRangeMapping).
- Fix: None required. Optionally document the behavior.

### sink-exec-F5: A tainted argv[0], or the command after sudo/doas, is emitted with its full source value
- Severity: Info
- Category: redaction
- Location: internal/taint/redaction/command.go:27-33; internal/taint/redaction/source.go:62-66
- Claim: Only bytes after the preserved command are sensitive. A tainted executable (argv[0], or argv[1] after sudo/doas) is sent as a clear value part, and its whole source value is sent unless the name/value patterns match (R2: `value="/definitely/not/a/real/attacker-binary" redacted=false`; R8: `value="rmrf" redacted=false`). This is intended and matches Java's command tokenizer. It is listed so the redaction reviewer knows that the full source value, not just the used window, leaves the process in this case.
- Evidence: .omo/review/evidence/sink-exec/go1.26.6-output.txt (TestReviewTaintedPathNilArgs, TestReviewSudoPreservesTaintedCommand, TestReviewLookPathBareTaintedName).
- Fix: None required.

## Checked and found correct
- **Start attempt only.** In Go 1.26.6 and 1.27.0, `Cmd.Start` has exactly one `os.StartProcess`, at exec.go:733 and :744 respectively. Validation failures (`c.Err`, `lookPathErr`, an empty Path), a context canceled before start, and I/O setup errors all return before it (TestCommandValidationFailureDoesNotReport; R7 `err=context canceled`, `FINDINGS=0`). A failed process attempt still reports (TestCommandStartProcessErrorStillReports; R1/R2/R8 report after `fork/exec ... no such file`).
- **Start twice.** `atomic.SwapInt32(&c.startCalled,1)` returns `exec: already started` before any attempt, and there is exactly one finding (R3).
- **Evaluation order and results.** The IIFE reads only the side-effect-free `c.ctx` first, evaluates `lp`, `c.argv()`, and `&os.ProcAttr{...}` once each in their original order, calls the host `os.StartProcess` directly, and returns its `(*os.Process, error)` unchanged. Callback panics are recovered in `commandbridge.Report` (bridge_test TestReportGateAndPanicShield). The bridge dependency closure excludes os/exec and the tracer.
- **Go 1.27.0 compatibility.** The only relevant 1.27 diff in os/exec is in `String()`, now `c.argv()[1:]`. The shape test and the whole suite pass under the go1.27.0 toolchain (.omo/review/evidence/sink-exec/go1.27.0-output.txt).
- **LookPath.** For a bare tainted name, `Path` becomes the untainted LookPath result while `Args[0]` keeps the tainted string, and the report fires (R6: `path=".../gnubin/true" args=["true"]`, `FINDINGS=1`).
- **CommandContext and plain Command.** A nil `c.ctx` becomes Background, and an unrelated context (`context.Background()`) falls back to the owner binding through `selectTaintedAnnotation` (TestCommandWithoutContextUsesOwnerBinding; R9 `FINDINGS=1`).
- **Env and Dir are not evidence.** A tainted `Env` entry and a tainted `Dir` with clean argv give `FINDINGS=0` (R4).
- **Range mapping into joined evidence.** `CollectJoinedStrings` checks `result == strings.Join(values, " ")` (`matchesJoin`) and advances the offset by `len(value)+len(sep)` even for skipped or empty arguments. With two sources, a repeated argument, and empty and space-containing arguments, the parts concatenate to the exact join, and the tainted parts land at `AAAA@a, b b@b, AAAA@a` (R5).
- **Bounds.** Compile-time asserts tie `MaxCommandArguments` to `MaxJoinedValues` (256). Argv over 32 KiB takes the fully redacted `boundedJoin` path, capped at 64 KiB. More than 256 args, or more than 64 KiB, drops the report (existing testapp tests pass). `ReportTainted` requires `analysis.Value == snapshot.Value()` unless the status is non-OK.
- **Redaction.** Everything after argv[0], or after one command following sudo/doas (basename also matches `/` and `\`), is sensitive. Empty-argument edges are covered by analyzer_test. The redacted payload never contains the secret (TestCommandPayloadEncodings).
- **Location skipping.** Namespace matching uses `==` or the prefix plus `/`, so `os` does not swallow unrelated `os*` user packages.
- **Hot path.** The `commandbridge.Active()` atomic gate, then `mayContainArgument` over at most 256 `StringKey`/`MayContain` probes, runs before any allocation. This is negligible next to fork/exec.

## Not covered / open questions
- `os.StartProcess`, `syscall.ForkExec`, and `syscall.Exec` called directly by customer code are not sinks. This is out of the documented scope, and other tracers do cover `os.spawn`/`execve` equivalents.
- `ExecutedSink.CommandInjection` counts only while some analysis is active, because of the bridge gate. SQL does the same, so I left it as is.
- I did not re-review source-value redaction or the owner and span selection internals; the redaction, report, and span nodes cover them.
- Windows behavior (F2 and `lookExtensions`) was not exercised.

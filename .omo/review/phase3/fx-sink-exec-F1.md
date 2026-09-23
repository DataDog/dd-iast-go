# fx-sink-exec-F1: verification of sink-exec-F1 (tainted Cmd.Path not inspected)

## Verdict per finding
- **sink-exec-F1: CONFIRMED.** Original severity High, adjusted severity **High**. An attacker-chosen executable given by a tainted `Cmd.Path`, with a clean `Args[0]`, is actually executed, and no command-injection finding is recorded. This reproduces on Go 1.26.6 and Go 1.27.0 with an independent woven reproducer.

## Reproduction
I wrote my own reproducer, independent of the finder's file: `.omo/review/evidence/fx-sink-exec-F1/fxf1_repro_test.go`. It is placed in `iast/os/exec/testapp/` and reuses that package's `newCommandFixture` (real `request.Begin` scope, mocktracer span, `spans.BindScope`) and `TestHelperProcess`. The tainted value is a request-parameter source (`taint.TaintString`) whose value is `os.Args[0]`, a **real** binary. That way the attacker-selected program demonstrably runs: its stdout echoes `ran-attacker-binary`. This is stronger than the finder's reproducer, which used a nonexistent path and only showed a failed `fork/exec` attempt.

Command, run in a private rsync copy with the main checkout untouched:
```
cd iast/os/exec/testapp
GOFLAGS='-mod=mod -p=4' GOTOOLCHAIN=go1.26.6 /usr/bin/time -l go tool orchestrion go test -timeout 15m -count=1 -v -run 'TestFxF1|TestCommandExecutionBoundaries' .
GOFLAGS='-mod=mod -p=4' GOTOOLCHAIN=go1.27.0 /usr/bin/time -l go tool orchestrion go test -timeout 15m -count=1 -v -run 'TestFxF1' .
```
Key output from Go 1.26.6 (`go1.26.6-output.txt`; `go1.27.0-output.txt` is identical in substance):
```
--- PASS: TestCommandExecutionBoundaries            (existing suite: weaving active, sink works)
FXF1 case=control-exec.Command(tainted) err=<nil> stdout="ran-attacker-binary" path_tainted=true args0_tainted=true FINDINGS=1 want=1
--- PASS: TestFxF1ControlCommandTaintedName
FXF1 case=cmd.Path=tainted err=<nil> stdout="ran-attacker-binary" path_tainted=true args0_tainted=false FINDINGS=0 want=1
--- FAIL: TestFxF1PathReassigned
FXF1 case=&Cmd{Path:tainted,Args:clean} err=<nil> stdout="ran-attacker-binary" path_tainted=true args0_tainted=false FINDINGS=0 want=1
--- FAIL: TestFxF1StructLiteral
```
In the control case, the same tainted value reports when it flows through `exec.Command` (it lands in `Args[0]`). Both divergent-Path shapes execute it silently. Peak RSS for the woven build was about 354 MB on 1.26.6 and 355 MB on 1.27.0, well under 4 GB.

## Reachability
- **Default configuration, supported toolchains:** yes. The build is a plain `go tool orchestrion go test` with the package's normal config, with no special flags, and it fails the same way on 1.26.6 and 1.27.0. Both stdlib versions do `lp := c.Path` and `os.StartProcess(lp, c.argv(), ...)` (1.26.6 `os/exec/exec.go:670,733`; 1.27.0 `:681,744`). `argv()` returns `c.Args` whenever it is non-empty (1.26.6 `:524-529`).
- **Customer shapes:** `cmd := exec.Command("worker", ...); cmd.Path = userValue`, or `&exec.Cmd{Path: userValue, Args: []string{"worker", ...}}`, which is a documented, idiomatic way to set a conventional argv[0] distinct from the binary path. These are less common than `exec.Command(userValue, ...)`, which is detected, but they are ordinary public API usage.
- **Documented limitation?** No. README "Sink coverage" (README.md:84) claims "Process attempts made by `exec.Cmd.Start`, including `Run`, `Output`, and `CombinedOutput`". These cases are exactly such process attempts. Neither `01-design-intent.md` nor the README mentions that `Cmd.Path` is excluded. This violates product rule 4 (no lost taint on supported paths).

## Adjusted severity
**High (unchanged).** This is a false negative on a documented-supported sink path (a `Cmd.Start` process attempt), and the missed data is the most dangerous CMDi component, the executable itself. It is not raised to Critical because there is no crash, no behavior change, and no data leak, and it is not lowered because the trigger is ordinary public API usage, not an exotic edge.

## Root cause (file:line)
- `iast/os/exec/orchestrion.yml:63-72`: the wrap-expression IIFE receives `__dd_iast_path` (`lp`, the executed binary) but calls `__dd__iast_ReportCommand__(__dd_iast_ctx, __dd_iast_argv)`. The path is dropped.
- `iast/os/exec/orchestrion.yml:45`: the bridge signature `func(context.Context, []string)` cannot carry the path.
- `iast/os/exec/exec.go:42-60`: `Report` gates (`mayContainArgument`, `:62-77`), analyzes (`redaction.AnalyzeCommand(argv)`), and collects (`evidence.CollectJoinedStrings(argv, ...)`) over argv only.
- The finder's location citation is accurate.

## Minimal fix
1. Change the bridge to `Report(ctx context.Context, path string, argv []string)`, both in the YAML linkname declaration and in `commandbridge`. Pass `{{ .Function.Receiver }}.Path`, not `lp`. On Windows, `lp` may be a fresh untainted `lookExtensions` result, and `.Receiver.ctx` already shows the receiver is addressable in the template.
2. In `Report`, when `path != argv[0]` and `store.StringKey(path)` may be contained in the active store, run analysis and collection over `append([]string{path}, argv[1:]...)`, which is the executed command line and matches `Cmd.String()`'s intent. Otherwise keep the current argv-only behavior, so an untainted LookPath-resolved `Path` never displaces a tainted `Args[0]` (the existing LookPath case keeps reporting). The 256-value and byte bounds are unchanged because the slice length is the same.
3. Add testapp cases for `cmd.Path = tainted` and `&exec.Cmd{Path: tainted, Args: clean}`. The two tests in `fxf1_repro_test.go` can be lifted directly after removing the logging.

# Plan: Configure the Overhead Runner with Go Flags

## Goal

Replace the overhead benchmark runner's `BENCH_*` environment-variable
configuration with an idiomatic Go command-line interface. Reuse `go test` flag
names where the runner has the same concept, and confine benchmark artifact I/O
to a rooted filesystem so artifact names cannot traverse outside the selected
output directory.

## Delivery Gate

This plan is the current deliverable. Implementation will not begin until the
user approves it; the approved plan will then be committed separately as
`wip(plan): configure overhead runner with Go flags`. After implementation has
been delivered and accepted, this plan will be removed so it remains in change
history without becoming permanent repository documentation.

## Scope

### Included

- Replace `BENCH_SAMPLES`, `BENCH_TIME`, `BENCH_CPU`, `BENCH_REGEX`, and
  `BENCH_OUTPUT_DIR` with command-line flags.
- Update the benchmark CI job and local documentation to use those flags.
- Store the opened output directory as an `*os.Root` and perform artifact I/O
  through that root rather than repeatedly constructing host paths from an
  output-directory string.
- Add focused tests for flag parsing and filesystem-based result inspection.
- Ensure the benchmark runner's own tests are explicitly run in CI; the runner
  is in a nested module and is not covered by the repository-root `./...`.

### Excluded

- Changes to benchmark workloads, benchmark defaults, variant construction, or
  statistical comparison behavior.
- Changes to the environment variables intentionally supplied to the benchmark
  subprocesses for IAST configuration and `GOMAXPROCS`; those configure the
  programs being measured rather than the runner CLI.
- A general filesystem abstraction for source-tree copying or temporary build
  trees. The traversal concern and requested representation apply to generated
  output artifacts.

## Command-Line Interface

Parse arguments with a dedicated `flag.FlagSet` using
`flag.ContinueOnError`, rather than package-global flags. Keep parsing pure:
`parseFlags(args []string)` returns plain option values, while a separate
configuration constructor discovers the module, creates or resolves the output
directory, and opens its filesystem root. This avoids filesystem side effects,
temporary-directory leaks, and open descriptors in table-driven parser tests.

Use these flags:

| Flag | Default | Meaning |
|---|---:|---|
| `-bench` | `.` | Benchmark selection expression, matching `go test -bench` |
| `-benchtime` | `500ms` | Time or iteration budget, matching `go test -benchtime` |
| `-count` | `10` | Independent process samples per variant, analogous to `go test -count` but deliberately preserving fresh-process isolation |
| `-cpu` | `1` | Fixed positive `GOMAXPROCS` and `-test.cpu` value, matching the existing single-CPU runner behavior |
| `-outputdir` | empty | Artifact directory, matching `go test -outputdir`; an empty value creates a temporary directory |

The flag names intentionally drop the `test.` prefix because users invoke the
runner through `go run`; the runner continues to pass the corresponding
`-test.*` flags to the compiled benchmark binaries.

Reject positional arguments; non-positive `-count` or `-cpu` values; an empty
or syntactically invalid `-bench` expression; and a `-benchtime` value that is
neither a positive Go duration nor the positive `Nx` iteration syntax accepted
by `go test`. Benchmark-expression validation will mirror `testing` by splitting
on unbracketed `/` separators and compiling each regular-expression component,
so malformed expressions fail before source copying or compilation. The result
comparison will also reject result sets containing no benchmark lines, catching
valid expressions that match nothing rather than producing a successful empty
comparison.

The usage text and README will explicitly say that `-cpu` accepts one positive
integer, rather than the comma-separated list supported by `go test`, because
the runner intentionally pins each fresh process to one `GOMAXPROCS` value.
`-cpu` and `-count` will be parsed as strings and validated after flag parsing
(or use an equivalent custom `flag.Value`) so invalid-value errors describe the
single-positive-integer restriction rather than exposing a raw `strconv` parse
error.

`run` will accept an argument slice and `main` will supply `os.Args[1:]`. The
flag set will use a stable command name. Its automatic output will be discarded
so parse failures are returned and reported exactly once by `main`; a dedicated
usage writer will render defaults to an injected `io.Writer`. On
`flag.ErrHelp`, `main` will send that usage to stdout and exit successfully.
Tests will capture the writer to verify useful help without coupling parsing to
process-global streams. Other parse and configuration failures retain the
existing non-zero exit behavior.
The configuration constructor will discover the benchmark module and source
repository, create the selected output directory when needed, resolve it to an
absolute path *before* calling `os.OpenRoot`, and retain that root. Errors will
include the relevant flag name and invalid value where useful.

## Rooted Output Filesystem

Represent the output directory in `configuration` as `*os.Root`, not a string
and not `os.DirFS`:

- `io/fs.FS` is read-only and therefore cannot represent all required artifact
  operations.
- `os.DirFS` is not a symlink-safe confinement boundary.
- `os.Root` supplies read, create, truncate, and append operations while
  rejecting names that escape its directory, including through symlinks.

Open the root once during configuration, close it from `run`, and use constant,
root-relative artifact names (`control.txt`, `iast.txt`, `comparison.txt`, and
`metadata.txt`) thereafter. Initialization, sample appends, metadata writes,
comparison output, and benchmark-name reads will all operate through the root.

Narrow read-only helpers such as benchmark-name collection and result-set
comparison to `fs.FS` where practical. This preserves confinement and allows
those helpers to be tested with `fstest.MapFS`. Helpers that create or append
files will accept `*os.Root` because the standard library has no common writable
filesystem interface.

Only external process arguments that inherently require host paths will derive
paths from `Root.Name()`, which is guaranteed to be absolute because the
configuration constructor resolves the selected directory before opening it:

- `go tool benchstat` receives absolute paths for the two raw result files;
- source-copy exclusion compares the walked path with the selected output root
  so an output directory inside the benchmark module is not copied recursively;
- the final informational message prints the selected directory.

No artifact file will be opened through those derived host paths. The current
path-sensitive operations include output opens at `main.go:132` and
`main.go:361`, plus source-tree operations at `main.go:228`, `main.go:236`,
`main.go:249`, and `main.go:265` (line numbers before this refactor). The rooted
artifact design removes the output-path findings. The source-tree operations
are not derived from the output setting and remain outside this change; they
will be distinguished explicitly when reviewing analyzer output rather than
being mistaken for regressions in artifact handling.

## File Changes

### `benchmarks/overhead/runner/main.go`

1. Add a plain `options` type, pure `parseFlags`, benchmark-expression and
   duration/iteration validation, and explicit help handling.
2. Replace environment-backed `loadConfiguration` with a separate configuration
   constructor that performs module discovery and filesystem setup.
3. Replace the output string with `*os.Root`, establish clear ownership and
   closure, and remove `environmentOr` and `positiveInteger`.
4. Introduce constants for artifact names and route all artifact reads/writes
   through the root.
5. Change `runSample`, `writeMetadata`, `compareResultSets`, and
   `benchmarkNames` signatures to consume a rooted or read-only filesystem and
   relative artifact names. Make result comparison fail when no benchmarks ran.
6. Keep full host paths only at the source-copy and `benchstat` subprocess
   boundaries described above.
7. Explicitly close the comparison file and join any close error so a full disk
   cannot yield a successful but truncated published report.
8. Align metadata option keys with the CLI (`count`, `bench`, `benchtime`, and
   `cpu`); the artifact filenames and raw benchmark stream formats remain
   unchanged.

### `benchmarks/overhead/runner/main_test.go`

1. Add table-driven tests for pure flag parsing, covering defaults, every
   override, positional arguments, invalid positive integers, invalid/zero
   duration and iteration budgets, empty and malformed benchmark expressions,
   the single-value `-cpu` restriction, and help behavior.
2. Exercise read-only result helpers with `fstest.MapFS`, including mismatched
   result sets and the no-benchmarks case.
3. Add a focused configuration test with `t.TempDir()` that verifies the opened
   root name is absolute and is closed by its owner.
4. Route a traversal attempt through the runner's own rooted artifact helper and
   verify it is rejected, rather than testing `os.Root` directly.
5. Retain the tracer-integration rewrite test, which concerns a temporary source
   tree rather than output artifacts.

### `benchmarks/overhead/README.md` and historical benchmark plan

Replace the README's environment-variable prose, table, and examples with the
five flags, including examples such as:

```console
go -C benchmarks/overhead run ./runner -count=2 -benchtime=100ms
```

Document that `-count` starts a fresh process for every sample and that
`-outputdir` defaults to a temporary directory. Update the stale smoke command
in `_docs/plans/overhead-benchmarks.md` so no in-repository guidance silently
uses removed `BENCH_*` configuration while that historical plan remains in the
current stack.

### `.github/workflows/ci.yml`

1. Remove the runner-facing `BENCH_*` environment block. Keep one CI-only
   `BENCHMARK_OUTPUT_DIR` variable as the single source of truth shared by the
   runner invocation, summary step, and artifact upload; the runner does not
   read it implicitly and is still configured through `-outputdir`.
2. Retain the output-directory preparation step so failures before runner
   configuration can still leave an uploadable diagnostics directory.
3. Invoke the runner with explicit smoke flags:

```console
go -C benchmarks/overhead run ./runner \
  -outputdir="$BENCHMARK_OUTPUT_DIR" \
  -count=2 -benchtime=100ms -cpu=1
```

4. Use the same CI wiring variable when generating the summary and uploading
   artifacts; retain the existing failure behavior.
5. Add `go -C benchmarks/overhead test -shuffle=on ./runner` to the regular test
   job so nested-module runner tests fail quickly and independently of the
   benchmark job.

## Validation

Before committing the plan and, after approval, before committing the
implementation:

1. Format modified Go files with `gofmt`.
2. Run runner unit tests and vet in the nested benchmark module:

   ```console
   go -C benchmarks/overhead test -shuffle=on ./runner
   go -C benchmarks/overhead vet ./runner
   ```

3. Run repository checks (which cover the root module but not the nested
   benchmark module):

   ```console
   go tool checklocks ./...
   go tool orchestrion go test -shuffle=on ./...
   ```

4. Run full smoke benchmarks with both a relative output path and an absolute
   output path containing spaces:

   ```console
   go -C benchmarks/overhead run ./runner \
     -outputdir=./benchmark-results \
     -count=2 -benchtime=100ms -cpu=1
   go -C benchmarks/overhead run ./runner \
     -outputdir="$(mktemp -d)/results with spaces" \
     -count=2 -benchtime=100ms -cpu=1
   ```

5. Verify help succeeds, while invalid values, malformed expressions,
   expressions matching no benchmarks, and positional arguments fail with
   actionable errors; parse-time failures must occur before benchmark variants
   are built.
6. Inspect the four generated artifacts and confirm both raw result files have
   matching benchmark/sample sets.
7. Re-run the path-traversal analyzer that produced the original warning (or,
   when that analyzer is external to this checkout, reproduce the equivalent
   gosec G304 check). Confirm findings for output opens formerly at
   `main.go:132` and `main.go:361` are gone, and report source-tree findings
   separately because they are outside this output-filesystem change.
8. Inspect `jj diff` for unintended generated files or unrelated changes.

## Acceptance Criteria

- Runner behavior is configured exclusively through documented command-line
  flags rather than `BENCH_*` environment variables.
- Relevant options use the familiar `go test` names: `-bench`, `-benchtime`,
  `-count`, `-cpu`, and `-outputdir`.
- CI passes all benchmark settings explicitly on the runner command line.
- The selected artifact directory is retained as an `*os.Root`; artifact helper
  APIs no longer pass an output-directory string around or open constructed
  artifact paths with package-level `os` functions.
- Attempts to use escaping artifact names through runner helpers are rejected by
  the filesystem root.
- Existing benchmark defaults, fresh-process sampling, four artifact filenames,
  raw benchmark stream formats, and comparison semantics remain unchanged;
  metadata option keys are renamed to match the CLI.
- A syntactically valid `-bench` expression that selects no benchmarks fails
  rather than publishing an empty successful comparison.

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command runner builds and compares the overhead benchmark variants.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	benchmarkPackage = "."

	controlResultsFile = "control.txt"
	iastResultsFile    = "iast.txt"
	activeResultsFile  = "active.txt"
	comparisonFile     = "comparison.txt"
	gateFile           = "gate.txt"
	gateTableFile      = "gate.tsv"
	minGateCount       = 4
	metadataFile       = "metadata.txt"

	// activeEnvironment makes the HeapBits workloads taint data (the
	// "active" variant: the IAST binary with this variable);
	// inertEnvironment makes sure that the other variants do not, also
	// when the caller exported the variable (the last value wins).
	activeEnvironment = "DD_IAST_BENCH_HEAPBITS=active"
	inertEnvironment  = "DD_IAST_BENCH_HEAPBITS="

	// taintLiveEnvironment selects the "taint live elsewhere" variant of the
	// workloads (see support_test.go). The runner does not set it: a child
	// process inherits it from the caller, and the metadata records it. The
	// only valid values are "" and taintLiveOn, and taintLiveOn needs
	// sampling 100 (else the live request is not sampled, and has no taint).
	taintLiveEnvironment = "DD_IAST_BENCH_TAINT_LIVE"
	taintLiveOn          = "1"

	// expectEnvironment tells the workloads which variant runs (control or
	// iast). With taint live elsewhere, the IAST variant fails when the live
	// value is not tainted.
	expectEnvironment = "DD_IAST_BENCH_EXPECT"

	// treeEnvironment tells the sink validation which tree it checks: the
	// expected evidence ranges differ between the trees (the shared
	// workload files are the same in both trees).
	treeEnvironment = "DD_IAST_BENCH_TREE=heapbits"

	// heapBitsPrefix is the prefix of the only workloads that the active
	// variant changes.
	heapBitsPrefix = "HeapBits"
)

type options struct {
	outputDir string
	count     int
	benchtime string
	cpu       int
	benchmark string
	sampling  int
	buildDir  string
	rotation  int
	evaluate  bool
	gate      bool
	// countSet and samplingSet tell whether the flag is on the command line
	// (-evaluate compares them with metadata.txt).
	countSet, samplingSet bool
}

type flagValues struct {
	outputDir string
	count     string
	benchtime string
	cpu       string
	benchmark string
	sampling  string
	buildDir  string
	rotation  string
	evaluate  bool
	gate      bool
}

type configuration struct {
	repository string
	module     string
	output     *os.Root
	count      int
	benchtime  string
	cpu        int
	benchmark  string
	sampling   int
	buildDir   string
	rotation   int
	evaluate   bool
	gate       bool
	// taintLive is the value of DD_IAST_BENCH_TAINT_LIVE of the run (from
	// metadata.txt with -evaluate).
	taintLive             string
	countSet, samplingSet bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(os.Stdout)
			return
		}
		fmt.Fprintln(os.Stderr, "overhead benchmark:", err)
		os.Exit(1)
	}
}

func run(arguments []string) (err error) {
	opts, err := parseFlags(arguments)
	if err != nil {
		return err
	}
	cfg, err := newConfiguration(opts)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, cfg.output.Close())
	}()
	if cfg.evaluate {
		return evaluate(cfg)
	}
	if err := validateTaintLive(cfg.taintLive, cfg.sampling); err != nil {
		return err
	}
	if err := initializeArtifacts(cfg.output, controlResultsFile, iastResultsFile, activeResultsFile, comparisonFile, gateFile, gateTableFile, metadataFile); err != nil {
		return err
	}

	buildRoot, reuse, cleanup, err := prepareBuildRoot(cfg.buildDir)
	if err != nil {
		return err
	}
	defer cleanup()

	controlSource := filepath.Join(buildRoot, "control-source")
	iastSource := filepath.Join(buildRoot, "iast-source")
	controlBinary := filepath.Join(buildRoot, "control.test")
	iastBinary := filepath.Join(buildRoot, "iast.test")
	if !reuse {
		if err := buildAndValidate(cfg, buildRoot, controlSource, iastSource, controlBinary, iastBinary); err != nil {
			return err
		}
		if cfg.buildDir != "" {
			if err := os.WriteFile(filepath.Join(buildRoot, builtMarker), nil, 0o644); err != nil {
				return err
			}
		}
	}

	if err := writeMetadata(cfg, metadataFile); err != nil {
		return err
	}

	// The active variant changes only the HeapBits workloads: without them,
	// it is a copy of the IAST variant, and the runner does not run it.
	active, err := selectsHeapBits(iastSource, iastBinary, cfg.benchmark)
	if err != nil {
		return err
	}
	if !active {
		fmt.Println("The -bench expression selects no HeapBits workload: the active variant is not run.")
	}
	for sample := 1; sample <= cfg.count; sample++ {
		fmt.Printf("Running sample %d/%d...\n", sample, cfg.count)
		variants := []variant{
			{controlSource, controlBinary, controlResultsFile, []string{expectEnvironment + "=control"}},
			{iastSource, iastBinary, iastResultsFile, []string{expectEnvironment + "=iast"}},
		}
		if active {
			variants = append(variants, variant{iastSource, iastBinary, activeResultsFile, []string{expectEnvironment + "=iast", activeEnvironment}})
		}
		// Rotate the order of the variants between samples.
		for range (sample + cfg.rotation) % len(variants) {
			variants = append(variants[1:], variants[0])
		}
		for _, v := range variants {
			if err := runSample(cfg, v); err != nil {
				return err
			}
		}
	}

	if err := compareResultSets(cfg.output.FS(), controlResultsFile, iastResultsFile); err != nil {
		return err
	}
	files := []string{controlResultsFile, iastResultsFile}
	if active {
		if err := compareResultSets(cfg.output.FS(), controlResultsFile, activeResultsFile); err != nil {
			return err
		}
		files = append(files, activeResultsFile)
	}
	if err := compareAndGate(cfg, files); err != nil {
		return err
	}
	fmt.Println("Benchmark artifacts:", cfg.output.Name())
	return nil
}

// validateTaintLive checks the value of DD_IAST_BENCH_TAINT_LIVE.
func validateTaintLive(value string, sampling int) error {
	switch {
	case value != "" && value != taintLiveOn:
		return fmt.Errorf("%s must be empty or %s, got %q", taintLiveEnvironment, taintLiveOn, value)
	case value == taintLiveOn && sampling != 100:
		return fmt.Errorf("%s=%s needs -sampling=100 (the live request must be sampled to hold a tainted value), got %d", taintLiveEnvironment, taintLiveOn, sampling)
	}
	return nil
}

// selectsHeapBits reports whether the -bench expression selects a HeapBits
// workload of the binary.
func selectsHeapBits(directory, binary, bench string) (bool, error) {
	var out strings.Builder
	if err := executeWithWriters(directory, []string{inertEnvironment}, &out, os.Stderr, binary, "-test.list=^Benchmark"+heapBitsPrefix); err != nil {
		return false, fmt.Errorf("list the HeapBits workloads: %w", err)
	}
	for _, name := range strings.Fields(out.String()) {
		if strings.HasPrefix(name, "Benchmark"+heapBitsPrefix) && selectsTopLevel(bench, strings.TrimPrefix(name, "Benchmark")) {
			return true, nil
		}
	}
	return false, nil
}

// selectsTopLevel reports whether the -bench expression of go test selects the
// top-level benchmark name (without "Benchmark"): go test separates the
// top-level alternatives ("|"), and matches the first slash-separated element
// of each alternative with the name.
func selectsTopLevel(bench, name string) bool {
	for _, alternative := range splitTopLevel(bench, '|') {
		first := splitTopLevel(alternative, '/')[0]
		if matched, err := regexp.MatchString(first, "Benchmark"+name); err == nil && matched {
			return true
		}
	}
	return false
}

// builtMarker is the file that marks a -builddir directory as built.
const builtMarker = "built"

// prepareBuildRoot returns the build directory. Without -builddir, it is a
// temporary directory that cleanup removes. With -builddir, the directory is
// kept, and reuse is true when an earlier run built it.
func prepareBuildRoot(buildDir string) (root string, reuse bool, cleanup func(), err error) {
	if buildDir == "" {
		root, err = os.MkdirTemp("", "dd-iast-overhead-build-*")
		if err != nil {
			return "", false, nil, fmt.Errorf("create build directory: %w", err)
		}
		return root, false, func() { os.RemoveAll(root) }, nil
	}
	root, err = filepath.Abs(buildDir)
	if err != nil {
		return "", false, nil, err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", false, nil, fmt.Errorf("create build directory: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, builtMarker)); err == nil {
		fmt.Println("Reusing the binaries of", root)
		return root, true, func() {}, nil
	}
	return root, false, func() {}, nil
}

// buildAndValidate copies the module twice, builds the 2 binaries and checks
// the variants.
func buildAndValidate(cfg configuration, buildRoot, controlSource, iastSource, controlBinary, iastBinary string) error {
	if err := copyModule(cfg.module, controlSource, cfg.output); err != nil {
		return fmt.Errorf("prepare control source: %w", err)
	}
	if err := copyModule(cfg.module, iastSource, cfg.output); err != nil {
		return fmt.Errorf("prepare IAST source: %w", err)
	}
	if err := retainTracerIntegration(filepath.Join(controlSource, "orchestrion.tool.go")); err != nil {
		return err
	}
	for _, source := range []string{controlSource, iastSource} {
		replacement := "github.com/DataDog/dd-iast-go=" + cfg.repository
		if err := execute(source, nil, "go", "mod", "edit", "-replace="+replacement); err != nil {
			return fmt.Errorf("point benchmark module at current dd-iast-go source: %w", err)
		}
		if err := execute(source, nil, "go", "mod", "download"); err != nil {
			return fmt.Errorf("download benchmark dependencies: %w", err)
		}
	}

	if err := buildVariant("control", controlSource, controlBinary); err != nil {
		return err
	}
	if err := buildVariant("IAST", iastSource, iastBinary); err != nil {
		return err
	}

	fmt.Println("Validating benchmark variants...")
	validationEnvironment := []string{
		"DD_IAST_ENABLED=true",
		"DD_IAST_REQUEST_SAMPLING=100",
		"DD_IAST_DEDUPLICATION_ENABLED=false",
		inertEnvironment,
	}
	if err := execute(controlSource, append(validationEnvironment, "DD_IAST_BENCH_EXPECT=control"), controlBinary, "-test.run=^TestControlVariant$"); err != nil {
		return fmt.Errorf("validate control variant: %w", err)
	}
	if err := execute(iastSource, append(validationEnvironment, "DD_IAST_BENCH_EXPECT=iast"), iastBinary, "-test.run=^TestWovenVariant$"); err != nil {
		return fmt.Errorf("validate IAST variant: %w", err)
	}
	if err := execute(iastSource, append(validationEnvironment, "DD_IAST_BENCH_EXPECT=iast", activeEnvironment), iastBinary, "-test.run=^TestWovenVariant$"); err != nil {
		return fmt.Errorf("validate active variant: %w", err)
	}
	// The sink workloads: exactly 1 vulnerability for each tainted call, with
	// the expected evidence ranges and source of this tree. Redaction is off,
	// so that the test can compare the values of the ranges.
	if err := execute(iastSource, append(validationEnvironment, "DD_IAST_BENCH_EXPECT=iast", "DD_IAST_REDACTION_ENABLED=false", treeEnvironment), iastBinary, "-test.run=^(TestRequestActive|TestSinkWorkloads)$"); err != nil {
		return fmt.Errorf("validate sink workloads: %w", err)
	}
	return nil
}

// compareAndGate writes comparison.txt (benchstat over files) and the gate
// reports.
func compareAndGate(cfg configuration, files []string) error {
	if err := execute(cfg.module, nil, "go", "mod", "download", "golang.org/x/perf"); err != nil {
		return fmt.Errorf("download benchstat: %w", err)
	}
	paths := make([]string, len(files))
	for i, file := range files {
		paths[i] = filepath.Join(cfg.output.Name(), file)
	}
	arguments := append([]string{"tool", "benchstat"}, paths...)
	comparison, err := cfg.output.OpenFile(comparisonFile, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open comparison: %w", err)
	}
	comparisonErr := executeWithWriters(cfg.module, nil, io.MultiWriter(os.Stdout, comparison), os.Stderr,
		"go", arguments...)
	closeErr := comparison.Close()
	if err := errors.Join(comparisonErr, closeErr); err != nil {
		return fmt.Errorf("compare results: %w", err)
	}
	return checkGates(cfg)
}

// evaluate compares the results that an earlier run (or a driver that merged
// the samples of several runs) left in the output directory.
func evaluate(cfg configuration) error {
	cfg, err := applyMetadata(cfg)
	if err != nil {
		return err
	}
	var files []string
	for _, name := range []string{controlResultsFile, iastResultsFile, activeResultsFile} {
		info, err := cfg.output.Stat(name)
		if err != nil || info.Size() == 0 {
			if name == activeResultsFile {
				// For example the results of the tree of PR #39, or a
				// run with no HeapBits workload (checkGates rejects a
				// HeapBits workload with no active variant).
				continue
			}
			return fmt.Errorf("-evaluate needs %s in %s", name, cfg.output.Name())
		}
		files = append(files, name)
	}
	for _, name := range files[1:] {
		if err := compareResultSets(cfg.output.FS(), controlResultsFile, name); err != nil {
			return err
		}
	}
	if err := initializeArtifacts(cfg.output, comparisonFile, gateFile, gateTableFile); err != nil {
		return err
	}
	if err := compareAndGate(cfg, files); err != nil {
		return err
	}
	fmt.Println("Benchmark artifacts:", cfg.output.Name())
	return nil
}

// applyMetadata reads the sampling, the count and the taint-live value of the
// run from metadata.txt. A flag on the command line (or a non-empty
// DD_IAST_BENCH_TAINT_LIVE) must agree with it.
func applyMetadata(cfg configuration) (configuration, error) {
	contents, err := cfg.output.ReadFile(metadataFile)
	if err != nil {
		return cfg, fmt.Errorf("-evaluate needs %s: %w", metadataFile, err)
	}
	metadata, err := parseMetadata(string(contents))
	if err != nil {
		return cfg, err
	}
	sampling, err := percentage("sampling of "+metadataFile, metadata["sampling"])
	if err != nil {
		return cfg, err
	}
	if cfg.samplingSet && cfg.sampling != sampling {
		return cfg, fmt.Errorf("-sampling=%d does not agree with sampling=%d of %s", cfg.sampling, sampling, metadataFile)
	}
	count, err := positiveInteger("count of "+metadataFile, metadata["count"])
	if err != nil {
		return cfg, err
	}
	if cfg.countSet && cfg.count != count {
		return cfg, fmt.Errorf("-count=%d does not agree with count=%d of %s", cfg.count, count, metadataFile)
	}
	quoted, ok := metadata["taint_live"]
	if !ok {
		return cfg, fmt.Errorf("%s has no taint_live", metadataFile)
	}
	taintLive, err := strconv.Unquote(quoted)
	if err != nil {
		return cfg, fmt.Errorf("taint_live of %s: %q: %w", metadataFile, quoted, err)
	}
	if cfg.taintLive != "" && cfg.taintLive != taintLive {
		return cfg, fmt.Errorf("%s=%q does not agree with taint_live=%q of %s", taintLiveEnvironment, cfg.taintLive, taintLive, metadataFile)
	}
	if err := validateTaintLive(taintLive, sampling); err != nil {
		return cfg, fmt.Errorf("%s: %w", metadataFile, err)
	}
	cfg.sampling, cfg.count, cfg.taintLive = sampling, count, taintLive
	return cfg, nil
}

// parseMetadata parses the "key=value" lines of metadata.txt.
func parseMetadata(contents string) (map[string]string, error) {
	metadata := map[string]string{}
	for line := range strings.Lines(contents) {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid line of %s: %q", metadataFile, line)
		}
		if _, seen := metadata[key]; seen {
			return nil, fmt.Errorf("%s has 2 values for %s", metadataFile, key)
		}
		metadata[key] = value
	}
	return metadata, nil
}

func parseFlags(arguments []string) (options, error) {
	values := defaultFlagValues()
	flags := newFlagSet(&values)
	if err := flags.Parse(arguments); err != nil {
		return options{}, fmt.Errorf("%w (run with -help for usage)", err)
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}

	count, err := positiveInteger("-count", values.count)
	if err != nil {
		return options{}, err
	}
	// With 3 samples or fewer, benchstat never finds a significant
	// difference (p >= 0.1): an enforced gate would always pass.
	if values.gate && !values.evaluate && count < minGateCount {
		return options{}, fmt.Errorf("-gate needs -count=%d or more, got %d", minGateCount, count)
	}
	cpu, err := positiveInteger("-cpu", values.cpu)
	if err != nil {
		return options{}, err
	}
	sampling, err := percentage("-sampling", values.sampling)
	if err != nil {
		return options{}, err
	}
	rotation, err := nonNegativeInteger("-rotation", values.rotation)
	if err != nil {
		return options{}, err
	}
	if values.evaluate && values.outputDir == "" {
		return options{}, errors.New("-evaluate needs -outputdir")
	}
	if values.benchmark == "" {
		return options{}, errors.New("-bench must not be empty")
	}
	for _, expression := range splitRegexp(values.benchmark) {
		if _, err := regexp.Compile(expression); err != nil {
			return options{}, fmt.Errorf("invalid -bench expression %q: %w", expression, err)
		}
	}
	if err := validateBenchtime(values.benchtime); err != nil {
		return options{}, err
	}

	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return options{
		countSet:    set["count"],
		samplingSet: set["sampling"],
		outputDir:   values.outputDir,
		count:       count,
		benchtime:   values.benchtime,
		cpu:         cpu,
		benchmark:   values.benchmark,
		sampling:    sampling,
		buildDir:    values.buildDir,
		rotation:    rotation,
		evaluate:    values.evaluate,
		gate:        values.gate,
	}, nil
}

func defaultFlagValues() flagValues {
	return flagValues{
		count:     "10",
		benchtime: "500ms",
		cpu:       "1",
		benchmark: ".",
		sampling:  "100",
		rotation:  "0",
	}
}

func newFlagSet(values *flagValues) *flag.FlagSet {
	flags := flag.NewFlagSet("runner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&values.benchmark, "bench", values.benchmark, "run only benchmarks matching `regexp`")
	flags.StringVar(&values.benchtime, "benchtime", values.benchtime, "run each benchmark for duration `d` or N iterations with Nx")
	flags.StringVar(&values.count, "count", values.count, "run `n` independent process samples per variant")
	flags.StringVar(&values.cpu, "cpu", values.cpu, "use one positive GOMAXPROCS `value`")
	flags.StringVar(&values.outputDir, "outputdir", values.outputDir, "write artifacts to `directory` (default: temporary directory)")
	flags.StringVar(&values.sampling, "sampling", values.sampling, "set DD_IAST_REQUEST_SAMPLING from 0 to 100")
	flags.StringVar(&values.buildDir, "builddir", values.buildDir, "build in `directory` and keep it; a later run with the same directory reuses the binaries (same source only)")
	flags.StringVar(&values.rotation, "rotation", values.rotation, "start the rotation of the variants `n` samples later (for drivers that run one sample at a time)")
	flags.BoolVar(&values.evaluate, "evaluate", values.evaluate, "do not build or run: compare the results of -outputdir (control.txt, iast.txt, active.txt if it exists) and write comparison.txt, gate.txt and gate.tsv")
	flags.BoolVar(&values.gate, "gate", values.gate, "fail when a regression gate of the HeapBits workloads is exceeded (use on a stable machine)")
	return flags
}

func printUsage(output io.Writer) {
	values := defaultFlagValues()
	flags := newFlagSet(&values)
	flags.SetOutput(output)
	fmt.Fprintln(output, "Usage: runner [flags]")
	flags.PrintDefaults()
}

func percentage(name, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer from 0 to 100: %q: %w", name, value, err)
	}
	if parsed < 0 || parsed > 100 {
		return 0, fmt.Errorf("%s must be an integer from 0 to 100: %q", name, value)
	}
	return parsed, nil
}

func nonNegativeInteger(name, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a single non-negative integer: %q: %w", name, value, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be a single non-negative integer: %q", name, value)
	}
	return parsed, nil
}

func positiveInteger(name, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a single positive integer: %q: %w", name, value, err)
	}
	if parsed < 1 {
		return 0, fmt.Errorf("%s must be a single positive integer: %q", name, value)
	}
	return parsed, nil
}

// splitRegexp separates the slash-delimited expressions and top-level
// alternatives interpreted independently by go test. Delimiters in character
// classes and parentheses do not separate benchmark name components.
func splitRegexp(expression string) []string {
	return splitAt(expression, "/|")
}

// splitTopLevel separates expression at the separator, outside character
// classes and parentheses.
func splitTopLevel(expression string, separator byte) []string {
	return splitAt(expression, string(separator))
}

func splitAt(expression, separators string) []string {
	var parts []string
	start := 0
	characterClassDepth := 0
	parenthesisDepth := 0
	for i := 0; i < len(expression); i++ {
		switch expression[i] {
		case '[':
			characterClassDepth++
		case ']':
			if characterClassDepth > 0 {
				characterClassDepth--
			}
		case '(':
			if characterClassDepth == 0 {
				parenthesisDepth++
			}
		case ')':
			if characterClassDepth == 0 {
				parenthesisDepth--
			}
		case '\\':
			i++
		case '/', '|':
			if characterClassDepth == 0 && parenthesisDepth == 0 && strings.IndexByte(separators, expression[i]) >= 0 {
				parts = append(parts, expression[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, expression[start:])
}

func validateBenchtime(value string) error {
	if strings.HasSuffix(value, "x") {
		iterations, err := strconv.ParseInt(strings.TrimSuffix(value, "x"), 10, 0)
		if err != nil {
			return fmt.Errorf("-benchtime must be a positive duration or iteration count such as 100x: %q: %w", value, err)
		}
		if iterations > 0 {
			return nil
		}
	} else {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("-benchtime must be a positive duration or iteration count such as 100x: %q: %w", value, err)
		}
		if duration > 0 {
			return nil
		}
	}
	return fmt.Errorf("-benchtime must be a positive duration or iteration count such as 100x: %q", value)
}

func newConfiguration(opts options) (configuration, error) {
	module, err := findModule()
	if err != nil {
		return configuration{}, err
	}
	repository := filepath.Clean(filepath.Join(module, "..", ".."))
	if _, err := os.Stat(filepath.Join(repository, "go.mod")); err != nil {
		return configuration{}, fmt.Errorf("find dd-iast-go source tree: %w", err)
	}

	output, err := openOutputRoot(opts.outputDir)
	if err != nil {
		return configuration{}, err
	}
	moduleInfo, err := os.Stat(module)
	if err != nil {
		output.Close()
		return configuration{}, fmt.Errorf("inspect benchmark module: %w", err)
	}
	outputInfo, err := output.Stat(".")
	if err != nil {
		output.Close()
		return configuration{}, fmt.Errorf("inspect output directory: %w", err)
	}
	if os.SameFile(moduleInfo, outputInfo) {
		output.Close()
		return configuration{}, errors.New("-outputdir must not be the benchmark module directory")
	}

	return configuration{
		repository:  repository,
		module:      module,
		output:      output,
		count:       opts.count,
		benchtime:   opts.benchtime,
		cpu:         opts.cpu,
		benchmark:   opts.benchmark,
		sampling:    opts.sampling,
		buildDir:    opts.buildDir,
		rotation:    opts.rotation,
		evaluate:    opts.evaluate,
		gate:        opts.gate,
		taintLive:   os.Getenv(taintLiveEnvironment),
		countSet:    opts.countSet,
		samplingSet: opts.samplingSet,
	}, nil
}

func openOutputRoot(directory string) (*os.Root, error) {
	var err error
	if directory == "" {
		directory, err = os.MkdirTemp("", "dd-iast-overhead-results-*")
		if err != nil {
			return nil, fmt.Errorf("create results directory: %w", err)
		}
	} else if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return nil, fmt.Errorf("resolve output directory: %w", err)
	}
	output, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open output directory: %w", err)
	}
	return output, nil
}

func findModule() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("could not find repository root")
		}
		directory = parent
	}
}

func initializeArtifacts(output *os.Root, names ...string) error {
	for _, name := range names {
		if err := output.WriteFile(name, nil, 0o644); err != nil {
			return fmt.Errorf("initialize %s: %w", name, err)
		}
	}
	return nil
}

func copyModule(source, destination string, output *os.Root) error {
	outputInfo, err := output.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if os.SameFile(info, outputInfo) || entry.Name() == ".git" {
				return filepath.SkipDir
			}
		}
		if path == source {
			return os.MkdirAll(destination, 0o755)
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			input.Close()
			return err
		}
		outputFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(outputFile, input)
		inputCloseErr := input.Close()
		closeErr := outputFile.Close()
		return errors.Join(copyErr, inputCloseErr, closeErr)
	})
}

func retainTracerIntegration(path string) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read control integrations: %w", err)
	}
	lines := strings.Split(string(contents), "\n")
	removed := 0
	kept := lines[:0]
	for _, line := range lines {
		if strings.Contains(line, `"github.com/DataDog/dd-iast-go"`) ||
			strings.Contains(line, `"github.com/DataDog/dd-iast-go/`) {
			removed++
			continue
		}
		kept = append(kept, line)
	}
	if removed == 0 {
		return errors.New("control build did not remove any dd-iast-go integrations")
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o644); err != nil {
		return fmt.Errorf("write control integrations: %w", err)
	}
	return nil
}

func buildVariant(name, source, binary string) error {
	fmt.Printf("Building %s benchmark binary with Orchestrion...\n", name)
	environment := []string{"GOFLAGS="}
	if err := execute(source, environment, "go", "tool", "orchestrion", "go", "test", "-c", "-o", binary, benchmarkPackage); err != nil {
		return fmt.Errorf("build %s variant: %w", name, err)
	}
	return nil
}

// variant is one benchmark binary run: its module directory, its binary, its
// results file and its extra environment.
type variant struct {
	directory, binary, results string
	environment                []string
}

func runSample(cfg configuration, v variant) error {
	file, err := cfg.output.OpenFile(v.results, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	environment := append([]string{
		"GOMAXPROCS=" + strconv.Itoa(cfg.cpu),
		"DD_IAST_ENABLED=true",
		"DD_IAST_REQUEST_SAMPLING=" + strconv.Itoa(cfg.sampling),
		"DD_IAST_DEDUPLICATION_ENABLED=false",
		inertEnvironment,
	}, v.environment...)
	runErr := executeWithWriters(v.directory, environment, file, os.Stderr, v.binary,
		"-test.run=^$",
		"-test.bench="+cfg.benchmark,
		"-test.benchmem",
		"-test.benchtime="+cfg.benchtime,
		"-test.cpu="+strconv.Itoa(cfg.cpu),
	)
	return errors.Join(runErr, file.Close())
}

func writeMetadata(cfg configuration, name string) error {
	revision, err := commandOutput(cfg.repository, "git", "rev-parse", "HEAD")
	if err != nil {
		// For example a secondary jj workspace, which has no .git directory.
		revision = "unknown (" + err.Error() + ")"
	}
	goVersion, err := commandOutput(cfg.repository, "go", "version")
	if err != nil {
		return err
	}
	metadata := fmt.Sprintf("revision=%s\ngo_version=%s\ngoos=%s\ngoarch=%s\ncpu_count=%d\ncount=%d\nbenchtime=%s\ncpu=%d\nbench=%s\nsampling=%d\ntaint_live=%q\ntree=%s\n",
		revision, goVersion, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), cfg.count, cfg.benchtime, cfg.cpu, cfg.benchmark, cfg.sampling, cfg.taintLive, strings.TrimPrefix(treeEnvironment, "DD_IAST_BENCH_TREE="))
	if err := cfg.output.WriteFile(name, []byte(metadata), 0o644); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

func commandOutput(directory, command string, arguments ...string) (string, error) {
	cmd := exec.Command(command, arguments...)
	cmd.Dir = directory
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("run %s: %w", command, err)
	}
	return strings.TrimSpace(string(output)), nil
}

func compareResultSets(fsys fs.FS, control, iast string) error {
	controlNames, err := benchmarkNames(fsys, control)
	if err != nil {
		return err
	}
	iastNames, err := benchmarkNames(fsys, iast)
	if err != nil {
		return err
	}
	if len(controlNames) == 0 {
		return errors.New("benchmark expression matched no benchmarks")
	}
	if strings.Join(controlNames, "\n") != strings.Join(iastNames, "\n") {
		return fmt.Errorf("control and IAST benchmark result sets differ:\ncontrol: %v\nIAST: %v", controlNames, iastNames)
	}
	return nil
}

func benchmarkNames(fsys fs.FS, path string) ([]string, error) {
	file, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var names []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && strings.HasPrefix(fields[0], "Benchmark") {
			names = append(names, fields[0])
		}
	}
	sort.Strings(names)
	return names, scanner.Err()
}

func execute(directory string, environment []string, command string, arguments ...string) error {
	return executeWithWriters(directory, environment, os.Stdout, os.Stderr, command, arguments...)
}

func executeWithWriters(directory string, environment []string, stdout, stderr io.Writer, command string, arguments ...string) error {
	cmd := exec.Command(command, arguments...)
	cmd.Dir = directory
	cmd.Env = append(os.Environ(), environment...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

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
	comparisonFile     = "comparison.txt"
	metadataFile       = "metadata.txt"
)

type options struct {
	outputDir string
	count     int
	benchtime string
	cpu       int
	benchmark string
}

type flagValues struct {
	outputDir string
	count     string
	benchtime string
	cpu       string
	benchmark string
}

type configuration struct {
	repository string
	module     string
	output     *os.Root
	count      int
	benchtime  string
	cpu        int
	benchmark  string
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
	if err := initializeArtifacts(cfg.output, controlResultsFile, iastResultsFile, comparisonFile, metadataFile); err != nil {
		return err
	}

	buildRoot, err := os.MkdirTemp("", "dd-iast-overhead-build-*")
	if err != nil {
		return fmt.Errorf("create build directory: %w", err)
	}
	defer os.RemoveAll(buildRoot)

	controlSource := filepath.Join(buildRoot, "control-source")
	iastSource := filepath.Join(buildRoot, "iast-source")
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

	controlBinary := filepath.Join(buildRoot, "control.test")
	iastBinary := filepath.Join(buildRoot, "iast.test")
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
	}
	if err := execute(controlSource, append(validationEnvironment, "DD_IAST_BENCH_EXPECT=control"), controlBinary, "-test.run=^TestControlVariant$"); err != nil {
		return fmt.Errorf("validate control variant: %w", err)
	}
	if err := execute(iastSource, append(validationEnvironment, "DD_IAST_BENCH_EXPECT=iast"), iastBinary, "-test.run=^TestWovenVariant$"); err != nil {
		return fmt.Errorf("validate IAST variant: %w", err)
	}

	if err := writeMetadata(cfg, metadataFile); err != nil {
		return err
	}

	for sample := 1; sample <= cfg.count; sample++ {
		fmt.Printf("Running sample %d/%d...\n", sample, cfg.count)
		variants := [][3]string{{controlSource, controlBinary, controlResultsFile}, {iastSource, iastBinary, iastResultsFile}}
		if sample%2 == 0 {
			variants[0], variants[1] = variants[1], variants[0]
		}
		for _, variant := range variants {
			if err := runSample(cfg, variant[0], variant[1], variant[2]); err != nil {
				return err
			}
		}
	}

	if err := compareResultSets(cfg.output.FS(), controlResultsFile, iastResultsFile); err != nil {
		return err
	}
	if err := execute(cfg.module, nil, "go", "mod", "download", "golang.org/x/perf"); err != nil {
		return fmt.Errorf("download benchstat: %w", err)
	}
	comparison, err := cfg.output.OpenFile(comparisonFile, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open comparison: %w", err)
	}
	comparisonErr := executeWithWriters(cfg.module, nil, io.MultiWriter(os.Stdout, comparison), os.Stderr,
		"go", "tool", "benchstat",
		filepath.Join(cfg.output.Name(), controlResultsFile),
		filepath.Join(cfg.output.Name(), iastResultsFile))
	closeErr := comparison.Close()
	if err := errors.Join(comparisonErr, closeErr); err != nil {
		return fmt.Errorf("compare results: %w", err)
	}
	fmt.Println("Benchmark artifacts:", cfg.output.Name())
	return nil
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
	cpu, err := positiveInteger("-cpu", values.cpu)
	if err != nil {
		return options{}, err
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

	return options{
		outputDir: values.outputDir,
		count:     count,
		benchtime: values.benchtime,
		cpu:       cpu,
		benchmark: values.benchmark,
	}, nil
}

func defaultFlagValues() flagValues {
	return flagValues{
		count:     "10",
		benchtime: "500ms",
		cpu:       "1",
		benchmark: ".",
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
	return flags
}

func printUsage(output io.Writer) {
	values := defaultFlagValues()
	flags := newFlagSet(&values)
	flags.SetOutput(output)
	fmt.Fprintln(output, "Usage: runner [flags]")
	flags.PrintDefaults()
}

func positiveInteger(name, value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be a single positive integer: %q", name, value)
	}
	return parsed, nil
}

// splitRegexp separates the slash-delimited expressions and top-level
// alternatives interpreted independently by go test. Delimiters in character
// classes and parentheses do not separate benchmark name components.
func splitRegexp(expression string) []string {
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
			if characterClassDepth == 0 && parenthesisDepth == 0 {
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
		if err == nil && iterations > 0 {
			return nil
		}
	} else if duration, err := time.ParseDuration(value); err == nil && duration > 0 {
		return nil
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
		repository: repository,
		module:     module,
		output:     output,
		count:      opts.count,
		benchtime:  opts.benchtime,
		cpu:        opts.cpu,
		benchmark:  opts.benchmark,
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

func runSample(cfg configuration, directory, binary, destination string) error {
	file, err := cfg.output.OpenFile(destination, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	environment := []string{
		"GOMAXPROCS=" + strconv.Itoa(cfg.cpu),
		"DD_IAST_ENABLED=true",
		"DD_IAST_REQUEST_SAMPLING=100",
		"DD_IAST_DEDUPLICATION_ENABLED=false",
	}
	runErr := executeWithWriters(directory, environment, file, os.Stderr, binary,
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
		return err
	}
	goVersion, err := commandOutput(cfg.repository, "go", "version")
	if err != nil {
		return err
	}
	metadata := fmt.Sprintf("revision=%s\ngo_version=%s\ngoos=%s\ngoarch=%s\ncpu_count=%d\ncount=%d\nbenchtime=%s\ncpu=%d\nbench=%s\n",
		revision, goVersion, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), cfg.count, cfg.benchtime, cfg.cpu, cfg.benchmark)
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

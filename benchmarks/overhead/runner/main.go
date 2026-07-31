// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command runner builds and compares the overhead benchmark variants.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const benchmarkPackage = "."

type configuration struct {
	repository string
	module     string
	output     string
	samples    int
	benchtime  string
	cpu        int
	benchmark  string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "overhead benchmark:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfiguration()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.output, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
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

	controlResults := filepath.Join(cfg.output, "control.txt")
	iastResults := filepath.Join(cfg.output, "iast.txt")
	for _, path := range []string{controlResults, iastResults, filepath.Join(cfg.output, "comparison.txt")} {
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			return fmt.Errorf("initialize %s: %w", path, err)
		}
	}
	if err := writeMetadata(cfg, filepath.Join(cfg.output, "metadata.txt")); err != nil {
		return err
	}

	for sample := 1; sample <= cfg.samples; sample++ {
		fmt.Printf("Running sample %d/%d...\n", sample, cfg.samples)
		variants := [][3]string{{controlSource, controlBinary, controlResults}, {iastSource, iastBinary, iastResults}}
		if sample%2 == 0 {
			variants[0], variants[1] = variants[1], variants[0]
		}
		for _, variant := range variants {
			if err := runSample(cfg, variant[0], variant[1], variant[2]); err != nil {
				return err
			}
		}
	}

	if err := compareResultSets(controlResults, iastResults); err != nil {
		return err
	}
	if err := execute(cfg.module, nil, "go", "mod", "download", "golang.org/x/perf"); err != nil {
		return fmt.Errorf("download benchstat: %w", err)
	}
	comparison := filepath.Join(cfg.output, "comparison.txt")
	file, err := os.OpenFile(comparison, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open comparison: %w", err)
	}
	defer file.Close()
	if err := executeWithWriters(cfg.module, nil, io.MultiWriter(os.Stdout, file), os.Stderr,
		"go", "tool", "benchstat", controlResults, iastResults); err != nil {
		return fmt.Errorf("compare results: %w", err)
	}
	fmt.Println("Benchmark artifacts:", cfg.output)
	return nil
}

func loadConfiguration() (configuration, error) {
	module, err := findModule()
	if err != nil {
		return configuration{}, err
	}
	repository := filepath.Clean(filepath.Join(module, "..", ".."))
	if _, err := os.Stat(filepath.Join(repository, "go.mod")); err != nil {
		return configuration{}, fmt.Errorf("find dd-iast-go source tree: %w", err)
	}
	output := os.Getenv("BENCH_OUTPUT_DIR")
	if output == "" {
		output, err = os.MkdirTemp("", "dd-iast-overhead-results-*")
		if err != nil {
			return configuration{}, fmt.Errorf("create results directory: %w", err)
		}
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return configuration{}, fmt.Errorf("resolve output directory: %w", err)
	}
	samples, err := positiveInteger("BENCH_SAMPLES", 10)
	if err != nil {
		return configuration{}, err
	}
	cpu, err := positiveInteger("BENCH_CPU", 1)
	if err != nil {
		return configuration{}, err
	}
	return configuration{
		repository: repository,
		module:     module,
		output:     output,
		samples:    samples,
		benchtime:  environmentOr("BENCH_TIME", "500ms"),
		cpu:        cpu,
		benchmark:  environmentOr("BENCH_REGEX", "."),
	}, nil
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

func positiveInteger(name string, fallback int) (int, error) {
	value := environmentOr(name, strconv.Itoa(fallback))
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return parsed, nil
}

func environmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func copyModule(source, destination, output string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == source {
			return os.MkdirAll(destination, 0o755)
		}
		if entry.IsDir() && (entry.Name() == ".git" || path == output) {
			return filepath.SkipDir
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
	file, err := os.OpenFile(destination, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	environment := []string{
		"GOMAXPROCS=" + strconv.Itoa(cfg.cpu),
		"DD_IAST_ENABLED=true",
		"DD_IAST_REQUEST_SAMPLING=100",
		"DD_IAST_DEDUPLICATION_ENABLED=false",
	}
	return executeWithWriters(directory, environment, file, os.Stderr, binary,
		"-test.run=^$",
		"-test.bench="+cfg.benchmark,
		"-test.benchmem",
		"-test.benchtime="+cfg.benchtime,
		"-test.cpu="+strconv.Itoa(cfg.cpu),
	)
}

func writeMetadata(cfg configuration, path string) error {
	revision, err := commandOutput(cfg.repository, "git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	goVersion, err := commandOutput(cfg.repository, "go", "version")
	if err != nil {
		return err
	}
	metadata := fmt.Sprintf("revision=%s\ngo_version=%s\ngoos=%s\ngoarch=%s\ncpu_count=%d\nsamples=%d\nbenchtime=%s\ncpu=%d\nbenchmark=%s\n",
		revision, goVersion, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), cfg.samples, cfg.benchtime, cfg.cpu, cfg.benchmark)
	if err := os.WriteFile(path, []byte(metadata), 0o644); err != nil {
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

func compareResultSets(control, iast string) error {
	controlNames, err := benchmarkNames(control)
	if err != nil {
		return err
	}
	iastNames, err := benchmarkNames(iast)
	if err != nil {
		return err
	}
	if strings.Join(controlNames, "\n") != strings.Join(iastNames, "\n") {
		return fmt.Errorf("control and IAST benchmark result sets differ:\ncontrol: %v\nIAST: %v", controlNames, iastNames)
	}
	return nil
}

func benchmarkNames(path string) ([]string, error) {
	file, err := os.Open(path)
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

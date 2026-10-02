// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      options
		wantError string
	}{
		{
			name: "defaults",
			want: options{count: 10, benchtime: "500ms", cpu: 1, benchmark: ".", sampling: 100},
		},
		{
			name: "overrides",
			arguments: []string{
				"-outputdir=results",
				"-count=3",
				"-benchtime=2s",
				"-cpu=4",
				"-bench=Hash/.+",
				"-sampling=0",
			},
			want: options{outputDir: "results", count: 3, benchtime: "2s", cpu: 4, benchmark: "Hash/.+", sampling: 0},
		},
		{
			name:      "iteration benchtime",
			arguments: []string{"-benchtime=100x"},
			want:      options{count: 10, benchtime: "100x", cpu: 1, benchmark: ".", sampling: 100},
		},
		{name: "positional argument", arguments: []string{"extra"}, wantError: "unexpected positional arguments"},
		{name: "zero count", arguments: []string{"-count=0"}, wantError: "-count must be a single positive integer"},
		{name: "invalid count", arguments: []string{"-count=many"}, wantError: "-count must be a single positive integer"},
		{name: "zero CPU", arguments: []string{"-cpu=0"}, wantError: "-cpu must be a single positive integer"},
		{name: "negative sampling", arguments: []string{"-sampling=-1"}, wantError: "-sampling must be an integer from 0 to 100"},
		{name: "high sampling", arguments: []string{"-sampling=101"}, wantError: "-sampling must be an integer from 0 to 100"},
		{name: "CPU list", arguments: []string{"-cpu=1,2"}, wantError: `-cpu must be a single positive integer: "1,2"`},
		{name: "empty benchtime", arguments: []string{"-benchtime="}, wantError: "-benchtime must be a positive duration"},
		{name: "zero duration", arguments: []string{"-benchtime=0s"}, wantError: "-benchtime must be a positive duration"},
		{name: "zero iterations", arguments: []string{"-benchtime=0x"}, wantError: "-benchtime must be a positive duration"},
		{name: "invalid benchtime", arguments: []string{"-benchtime=soon"}, wantError: "-benchtime must be a positive duration"},
		{name: "empty benchmark", arguments: []string{"-bench="}, wantError: "-bench must not be empty"},
		{name: "invalid benchmark", arguments: []string{"-bench=["}, wantError: "invalid -bench expression"},
		{name: "invalid benchmark element", arguments: []string{"-bench=A/*"}, wantError: "invalid -bench expression"},
		{name: "invalid benchmark alternative", arguments: []string{"-bench=[]|[a]"}, wantError: `invalid -bench expression "[]"`},
		{name: "benchmark character class slash", arguments: []string{"-bench=[/]"}, want: options{count: 10, benchtime: "500ms", cpu: 1, benchmark: "[/]", sampling: 100}},
		{name: "benchmark parenthesized slash", arguments: []string{"-bench=(A/B)"}, want: options{count: 10, benchtime: "500ms", cpu: 1, benchmark: "(A/B)", sampling: 100}},
		{name: "benchmark character class pipe", arguments: []string{"-bench=[|]"}, want: options{count: 10, benchtime: "500ms", cpu: 1, benchmark: "[|]", sampling: 100}},
		{name: "benchmark parenthesized pipe", arguments: []string{"-bench=(A|B)"}, want: options{count: 10, benchtime: "500ms", cpu: 1, benchmark: "(A|B)", sampling: 100}},
		{name: "unknown flag", arguments: []string{"-unknown"}, wantError: "flag provided but not defined"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseFlags(test.arguments)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("parseFlags() error = %v, want an error containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("parseFlags() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseFlagsPreservesNumberErrors(t *testing.T) {
	for _, flag := range []string{"count", "cpu", "sampling", "benchtime"} {
		for _, value := range []string{"many", "999999999999999999999999999999"} {
			argument := "-" + flag + "=" + value
			if flag == "benchtime" {
				argument += "x"
			}
			t.Run(argument, func(t *testing.T) {
				_, err := parseFlags([]string{argument})
				var numberError *strconv.NumError
				if !errors.As(err, &numberError) {
					t.Fatalf("parseFlags(%q) error = %v, want a wrapped strconv.NumError", argument, err)
				}
				if !strings.Contains(err.Error(), numberError.Error()) {
					t.Fatalf("error %q does not include the parse error %q", err, numberError)
				}
			})
		}
	}
}

func TestParseFlagsReportsDurationErrors(t *testing.T) {
	_, err := parseFlags([]string{"-benchtime=1fortnight"})
	if err == nil || !strings.Contains(err.Error(), `unknown unit "fortnight"`) {
		t.Fatalf("parseFlags() error = %v, want the duration parse error", err)
	}
}

func TestHelp(t *testing.T) {
	if _, err := parseFlags([]string{"-help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseFlags(-help) error = %v, want flag.ErrHelp", err)
	}
	var usage strings.Builder
	printUsage(&usage)
	if strings.Contains(usage.String(), "`") {
		t.Fatalf("usage contains a stray backtick:\n%s", usage.String())
	}
	for _, name := range []string{"-bench", "-benchtime", "-count", "-cpu", "-outputdir", "-sampling"} {
		if !strings.Contains(usage.String(), name) {
			t.Errorf("usage does not contain %q:\n%s", name, usage.String())
		}
	}
}

func TestOpenOutputRootUsesAbsolutePath(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "results")
	output, err := openOutputRoot(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(output.Name()) {
		t.Errorf("output root name = %q, want an absolute path", output.Name())
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Stat("."); err == nil {
		t.Fatal("closed output root remains usable")
	}
}

func TestInitializeArtifactsRejectsTraversal(t *testing.T) {
	output, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()

	if err := initializeArtifacts(output, "valid.txt"); err != nil {
		t.Fatal(err)
	}
	if err := initializeArtifacts(output, "../escape.txt"); err == nil {
		t.Fatal("initializeArtifacts accepted a path outside the output root")
	}
}

func TestRetainTracerIntegration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orchestrion.tool.go")
	input := `package ddiast
import (
	_ "github.com/DataDog/orchestrion"
	_ "github.com/DataDog/dd-iast-go"
	_ "github.com/DataDog/dd-trace-go/contrib/net/http/v2"
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)
`
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := retainTracerIntegration(path); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output := string(contents)
	if strings.Contains(output, `"github.com/DataDog/dd-iast-go"`) ||
		strings.Contains(output, `"github.com/DataDog/dd-iast-go/`) {
		t.Fatalf("control integration file still imports dd-iast-go:\n%s", output)
	}
	if !strings.Contains(output, "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer") {
		t.Fatalf("control integration file removed the tracer:\n%s", output)
	}
	if !strings.Contains(output, "github.com/DataDog/dd-trace-go/contrib/net/http/v2") {
		t.Fatalf("control integration file removed net/http tracing:\n%s", output)
	}
}

func TestBenchmarkNames(t *testing.T) {
	results := fstest.MapFS{
		"results.txt": {Data: []byte("goos: linux\nBenchmarkHealth-4  100  10 ns/op\nBenchmarkHash-4  100  20 ns/op\nBenchmarkHealth-4  100  11 ns/op\nPASS\n")},
	}
	names, err := benchmarkNames(results, "results.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"BenchmarkHash-4", "BenchmarkHealth-4", "BenchmarkHealth-4"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("benchmarkNames() = %v, want %v", names, want)
	}
}

func TestCompareResultSets(t *testing.T) {
	tests := []struct {
		name      string
		control   string
		iast      string
		wantError string
	}{
		{name: "matching", control: "BenchmarkHealth-1 1 10 ns/op\n", iast: "BenchmarkHealth-1 1 12 ns/op\n"},
		{name: "mismatched", control: "BenchmarkHealth-1 1 10 ns/op\n", iast: "BenchmarkHash-1 1 12 ns/op\n", wantError: "result sets differ"},
		{name: "empty", control: "PASS\n", iast: "PASS\n", wantError: "matched no benchmarks"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := fstest.MapFS{
				"control.txt": {Data: []byte(test.control)},
				"iast.txt":    {Data: []byte(test.iast)},
			}
			err := compareResultSets(results, "control.txt", "iast.txt")
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("compareResultSets() error = %v, want an error containing %q", err, test.wantError)
			}
		})
	}
}

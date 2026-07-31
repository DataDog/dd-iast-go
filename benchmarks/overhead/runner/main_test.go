// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

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
	path := filepath.Join(t.TempDir(), "results.txt")
	input := "goos: linux\nBenchmarkHealth-4  100  10 ns/op\nBenchmarkHash-4  100  20 ns/op\nBenchmarkHealth-4  100  11 ns/op\nPASS\n"
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	names, err := benchmarkNames(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"BenchmarkHash-4", "BenchmarkHealth-4", "BenchmarkHealth-4"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("benchmarkNames() = %v, want %v", names, want)
	}
}

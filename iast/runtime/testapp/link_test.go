// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	_ "unsafe" // for go:linkname

	// An application with IAST uses the tracer. The woven tracer links the
	// request package of dd-iast-go (through its span hooks), and the
	// net/http aspect needs that package. The tracer does not import the
	// propagation package.
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

// This file imports nothing from dd-iast-go (plan runtime-operator-hooks,
// step 5b): all dd-iast-go code comes from weaving. The test reads the state
// of dd-iast-go through pull linknames of non-standard symbols, which the
// linker permits. The pulls do not import a package, so they do not change
// the set of packages in the program.

// registered is runtimebridge.Registered: all 6 propagation callbacks are
// registered.
//
//go:linkname registered github.com/DataDog/dd-iast-go/internal/taint/runtimebridge.Registered
func registered() bool

//go:linkname isTaintedString github.com/DataDog/dd-iast-go/internal/taint/request.IsTaintedString
func isTaintedString(value string) bool

//go:linkname isTaintedBytes github.com/DataDog/dd-iast-go/internal/taint/request.IsTaintedBytes
func isTaintedBytes(value []byte) bool

const childEnv = "DD_IAST_RUNTIME_LINK_CHILD"

var (
	sinkString string
	sinkBytes  []byte
)

// TestRuntimeOnlyLink checks the link rule of plan section 3.2 rule 6: the
// program imports nothing from dd-iast-go, and the only dd-iast-go aspects
// are the runtime aspect and the net/http source aspect. The propagation
// callbacks are registered, and a concatenation of a tainted request value is
// tainted (not only forced to the heap).
func TestRuntimeOnlyLink(t *testing.T) {
	if os.Getenv(childEnv) == "1" {
		child(t)
		return
	}
	if !built.WithOrchestrion {
		if os.Getenv("DD_IAST_REQUIRE_WOVEN") == "1" {
			t.Fatal("DD_IAST_REQUIRE_WOVEN=1: the test is not built with Orchestrion")
		}
		t.Skip("use `go tool orchestrion go test` to run this test")
	}
	// The IAST settings are read at init, so the check runs in a child
	// process with the settings in its environment.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRuntimeOnlyLink$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", "DD_IAST_ENABLED=true", "DD_IAST_REQUEST_SAMPLING=100")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "CHILD-OK") {
		t.Fatalf("child did not report:\n%s", output)
	}
}

func child(t *testing.T) {
	if !registered() {
		t.Fatal("the propagation callbacks are not registered: the runtime aspect does not link the propagation package")
	}
	var report string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.RawQuery
		sinkString = "prefix:" + query
		sinkBytes = []byte(sinkString)
		report = fmt.Sprintf("query=%t concat=%t bytes=%t", isTaintedString(query), isTaintedString(sinkString), isTaintedBytes(sinkBytes))
		_, _ = io.WriteString(w, report)
	}))
	defer server.Close()
	response, err := http.Get(server.URL + "/?attack=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "query=true concat=true bytes=true" {
		t.Fatalf("taint did not propagate through the woven runtime: %s", body)
	}
	fmt.Println("CHILD-OK", string(body))
}

// buildAndRun builds pkg with Orchestrion and -ldflags=-checklinkname=1 (plan
// section 3.9 item 4), runs it, and returns the symbols of the executable.
func buildAndRun(t *testing.T, pkg string) []string {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("use `go tool orchestrion go test` to run this test")
	}
	binary := filepath.Join(t.TempDir(), filepath.Base(pkg))
	build := exec.CommandContext(t.Context(), "go", "tool", "orchestrion", "go", "build", "-ldflags=-checklinkname=1", "-o", binary, pkg)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, output)
	}
	if output, err := exec.CommandContext(t.Context(), binary).CombinedOutput(); err != nil {
		t.Fatalf("run %s: %v\n%s", pkg, err, output)
	}
	output, err := exec.CommandContext(t.Context(), "go", "tool", "nm", binary).CombinedOutput()
	if err != nil {
		t.Fatalf("nm %s: %v\n%s", pkg, err, output)
	}
	return strings.Fields(string(output))
}

func TestBootstrapLinksRuntimeHooks(t *testing.T) {
	symbols := buildAndRun(t, "./cmd/bootstrap")
	want, err := os.ReadFile("cmd/bootstrap/symbols.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range strings.Fields(string(want)) {
		if !slices.Contains(symbols, symbol) {
			t.Errorf("the executable is missing the symbol %q", symbol)
		}
	}
}

func TestNoHookLinks(t *testing.T) {
	symbols := buildAndRun(t, "./cmd/nohook")
	if !slices.Contains(symbols, "runtime.__dd_iast_concatstrings") {
		t.Error("the runtime of the executable is not woven")
	}
}

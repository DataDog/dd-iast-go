// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text

import (
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// TestAspectCount is the aspect count guard (plan section 6.1 rule 6, PR #39
// strings_test.go:25): the telemetry count is the number of hook aspects (the
// "-decls" aspects are not hooks), and the aspect strings-telemetry-decls
// pushes this number.
func TestAspectCount(t *testing.T) {
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	registered := strings.Count(string(contents), "\n  - id:")
	decls := regexp.MustCompile(`\n  - id: \S+-decls\n`).FindAllString(string(contents), -1)
	require.Equal(t, registered-len(decls), instrumentedPropagationPoints)
	pushed := regexp.MustCompile(`\n *var __dd_iast_text_points uint32 = (\d+)\n`).FindStringSubmatch(string(contents))
	require.NotNil(t, pushed, "the pushed telemetry count is not in orchestrion.yml")
	require.Equal(t, strconv.Itoa(instrumentedPropagationPoints), pushed[1], "the pushed telemetry count")
}

// TestHookImports checks rule 1 of plan section 6.1, in the form that
// Orchestrion permits: the hook code in the standard library imports only
// standard library packages, and links no package. An import (or a link)
// of a dd-iast-go package from the standard library breaks go test of that
// package when it has in-package tests (Orchestrion cannot rebuild the
// standard library against the test variant).
func TestHookImports(t *testing.T) {
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	require.NotContains(t, string(contents), "\n          links:", "no links from the standard library")
	importLine := regexp.MustCompile(`(?m)^            (\w+): (\S+)$`)
	found := 0
	for _, m := range importLine.FindAllStringSubmatch(string(contents), -1) {
		found++
		path := m[2]
		first, _, _ := strings.Cut(path, "/")
		require.NotContains(t, first, ".", "import %s of the hooks is not a standard library package", path)
	}
	require.Greater(t, found, 10, "imports found in orchestrion.yml")
}

// TestLeafPackages checks that the packages whose symbols the hooks use do
// not depend on a hooked package (no cycle at link time, and the bit
// functions never run hooked code).
func TestLeafPackages(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not found")
	}
	out, err := exec.Command("go", "list", "-deps",
		"github.com/DataDog/dd-iast-go/internal/taint/heapbits",
		"github.com/DataDog/dd-iast-go/internal/taint/propbridge").CombinedOutput()
	require.NoError(t, err, "%s", out)
	deps := strings.Fields(string(out))
	for _, hooked := range []string{"strings", "bytes", "strconv", "net/url"} {
		require.NotContains(t, deps, hooked)
	}
}

// pbDerived is the variable that the hooks read (pushed by propbridge).
//
//go:linkname pbDerived __dd_iast_propbridge.derived
var pbDerived func(out, outLen, in, inLen uintptr, mode uint8)

// TestBridgeModes checks the mode values that the hooks use without an
// import of propbridge, and the push of Derived.
func TestBridgeModes(t *testing.T) {
	require.Equal(t, uint8(1), propbridge.Coarse)
	require.Equal(t, uint8(2), propbridge.Positional)
	require.NotNil(t, pbDerived)
	require.Equal(t, reflect.ValueOf(propbridge.Derived).Pointer(), reflect.ValueOf(pbDerived).Pointer())
}

// rtAnyStrsPtr is the variable that the strings.Join hook reads (pushed by
// the aspects of iast/runtime).
//
//go:linkname rtAnyStrsPtr __dd_iast_runtime.anystrsptr
var rtAnyStrsPtr func(p, n uintptr) bool

var joinBridgeSink []byte

// TestJoinBridge checks that the woven runtime pushes the function that the
// strings.Join hook uses for the check of its elements (without it, the hook
// does one Any for each element), and the arguments that the hook gives.
func TestJoinBridge(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	require.NotNil(t, rtAnyStrsPtr, "the woven runtime does not push __dd_iast_runtime.anystrsptr")
	tainted := append(make([]byte, 0, 16), "tainted-element"...)
	joinBridgeSink = tainted // heap memory: stack memory has no bits
	require.True(t, heapbits.SetBytes(tainted[3:5]))
	defer heapbits.ClearBytes(tainted)
	clean := strings.Clone("clean")
	check := func(elems []string) bool {
		p := unsafe.SliceData(elems)
		ok := rtAnyStrsPtr(uintptr(unsafe.Pointer(p)), uintptr(len(elems)))
		runtime.KeepAlive(p)
		return ok
	}
	value := unsafe.String(unsafe.SliceData(tainted), len(tainted))
	require.False(t, check(nil))
	require.False(t, check([]string{clean, "", clean}))
	require.False(t, check([]string{clean, value[:3], value[5:]}), "only the bytes of the strings")
	require.True(t, check([]string{clean, "", value[4:6]}))
	require.True(t, check([]string{value}))
	runtime.KeepAlive(tainted)
}

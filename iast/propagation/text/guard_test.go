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
	"strings"
	"testing"
	_ "unsafe" // linkname

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/stretchr/testify/require"
)

// TestAspectCount is the aspect count guard (plan section 6.1 rule 6, PR #39
// strings_test.go:25): the telemetry count is the number of aspects.
func TestAspectCount(t *testing.T) {
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	registered := strings.Count(string(contents), "\n  - id:")
	require.Equal(t, registered, instrumentedPropagationPoints)
	require.GreaterOrEqual(t, telemetry.InstrumentedPropagation, uint(instrumentedPropagationPoints))
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

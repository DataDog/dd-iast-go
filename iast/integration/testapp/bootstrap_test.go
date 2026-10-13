// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBootstrapProductionPackageEndingInTest builds 2 woven executables
// whose main packages import no integration. The second main package has a
// name that ends in ".test". Orchestrion must link the sink callback
// registrations into both executables, and the executables must run.
//
// The test builds the executables, thus -short skips it.
func TestBootstrapProductionPackageEndingInTest(t *testing.T) {
	if testing.Short() {
		t.Skip("builds woven executables")
	}
	want, err := os.ReadFile("cmd/bootstrap/symbols.txt")
	require.NoError(t, err)
	for _, pkg := range []string{"./cmd/bootstrap", "./cmd/bootstrap.test"} {
		t.Run(pkg, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), filepath.Base(pkg))
			build := exec.CommandContext(t.Context(), "go", "tool", "orchestrion", "go", "build", "-p=2", "-o", binary, pkg)
			output, err := build.CombinedOutput()
			require.NoError(t, err, "%s", output)

			output, err = exec.CommandContext(t.Context(), "go", "tool", "nm", binary).CombinedOutput()
			require.NoError(t, err, "%s", output)
			symbols := strings.Fields(string(output))
			for _, symbol := range strings.Fields(string(want)) {
				if !slices.Contains(symbols, symbol) {
					t.Errorf("production executable is missing bootstrap symbol %q", symbol)
				}
			}

			output, err = exec.CommandContext(t.Context(), binary).CombinedOutput()
			require.NoError(t, err, "%s", output)
		})
	}
}

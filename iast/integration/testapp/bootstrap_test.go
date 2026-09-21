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

func TestBootstrapProductionPackageEndingInTest(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "bootstrap.test")
	build := exec.CommandContext(t.Context(), "go", "tool", "orchestrion", "go", "build", "-p=2", "-o", binary, "./cmd/bootstrap.test")
	output, err := build.CombinedOutput()
	require.NoError(t, err, "%s", output)

	output, err = exec.CommandContext(t.Context(), "go", "tool", "nm", binary).CombinedOutput()
	require.NoError(t, err, "%s", output)
	symbols := strings.Fields(string(output))
	want, err := os.ReadFile("cmd/bootstrap/symbols.txt")
	require.NoError(t, err)
	for _, symbol := range strings.Fields(string(want)) {
		if !slices.Contains(symbols, symbol) {
			t.Errorf("production executable is missing bootstrap symbol %q", symbol)
		}
	}

	output, err = exec.CommandContext(t.Context(), binary).CombinedOutput()
	require.NoError(t, err, "%s", output)
}

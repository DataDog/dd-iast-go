// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package sentinel

import (
	"errors"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/_integration/otelc/internal/hookmanifest"
	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errBroken = errors.New("broken witness")

// skipUnlessInstrumented skips a test that needs a woven build. The sentinel
// itself never skips: see TestRunFailsWithoutInstrumentation.
func skipUnlessInstrumented(t *testing.T) {
	t.Helper()
	if !build.Instrumented() {
		t.Skip("the build is not instrumented, use a tool to run this test")
	}
}

// TestRunFailsWithoutInstrumentation: the sentinel must fail (never skip) for a
// build that is not woven. It has a meaning only for such a build; CI runs it
// without a tool.
func TestRunFailsWithoutInstrumentation(t *testing.T) {
	if build.Instrumented() {
		t.Skip("the build is instrumented")
	}
	assert.ErrorContains(t, Run(""), "not built with")
	assert.ErrorContains(t, Run("orchestrion"), "not built with")
}

// TestEveryWitnessIsInTheManifest runs without a tool. A witness that no line of
// the manifest names would never run, so a deleted line must fail a test.
func TestEveryWitnessIsInTheManifest(t *testing.T) {
	manifest, err := hookmanifest.Parse(strings.NewReader(manifestText))
	require.NoError(t, err, "the checked-in manifest is valid")
	listed := make(map[string]bool)
	for _, entry := range manifest {
		listed[entry.Hook] = true
	}
	for hook := range witnesses {
		assert.True(t, listed[hook], "the witness of %q is not in the manifest", hook)
	}
}

func TestCheckedInManifestIsValid(t *testing.T) {
	skipUnlessInstrumented(t)
	assert.NoError(t, Run(build.Tool()))
}

func TestRunWithExpectedTool(t *testing.T) {
	skipUnlessInstrumented(t)
	assert.NoError(t, run(build.Tool(), "", nil))
	assert.NoError(t, run("", "", nil))
	assert.ErrorContains(t, run("no-such-tool", "", nil), "want \"no-such-tool\"")
}

func TestRunWithInvalidManifest(t *testing.T) {
	skipUnlessInstrumented(t)
	assert.ErrorContains(t, run("", "not a manifest line\n", nil), "invalid expected-hook manifest")
}

func TestRunWitnesses(t *testing.T) {
	skipUnlessInstrumented(t)

	manifest := "* */* good\n* */* broken\n* */* missing\n* */* also-broken\n1.0 */* other-go-version\n"
	witnesses := map[string]func() error{
		"good":             func() error { return nil },
		"broken":           func() error { return errBroken },
		"also-broken":      func() error { return errBroken },
		"other-go-version": func() error { return errBroken },
	}

	err := run("", manifest, witnesses)
	require.Error(t, err)
	assert.ErrorIs(t, err, errBroken, "a failing witness is reported")
	assert.ErrorContains(t, err, "hook \"broken\":")
	assert.ErrorContains(t, err, "hook \"also-broken\":", "all the failures are reported, not only the first")
	assert.ErrorContains(t, err, "hook \"missing\" is in the manifest but has no witness")
	assert.NotContains(t, err.Error(), "good")
	assert.NotContains(t, err.Error(), "other-go-version", "a hook for another Go version is not checked")

	assert.NoError(t, run("", "* */* good\n", witnesses))
}

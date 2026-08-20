// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package config

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// sentinelEnvVar guards TestConfigSentinel so that it only ever produces
// output when deliberately invoked as a subprocess by
// runConfigInitSubprocess. Without this guard, a normal (non-subprocess) test
// run would execute this test in-process against whatever environment the
// parent test binary happens to have, which would be non-deterministic and
// would pollute test output.
const sentinelEnvVar = "DD_IAST_GO_TEST_CONFIG_SENTINEL"

// sentinelMarker prefixes the single line of JSON output produced by
// TestConfigSentinel so the parent process can locate it among any other
// test framework output on stdout.
const sentinelMarker = "DD_IAST_GO_TEST_CONFIG_SENTINEL_JSON:"

// configSnapshot captures every public configuration global that is wired up
// at package initialization time.
type configSnapshot struct {
	Enabled                   bool
	RequestSamplingPct        int
	MaxConcurrentRequests     int
	VulnerabilitiesPerRequest int
	DeduplicationEnabled      bool
	RedactionEnabled          bool
	RedactionNamePattern      string
	RedactionValuePattern     string
	TruncationMaxValue        uint64
	MaxRangeCount             uint64
	TelemetryVerbosity        LogLevel
	DbRowsToTaint             uint64
	StackTraceEnabled         bool
}

func currentConfigSnapshot() configSnapshot {
	return configSnapshot{
		Enabled:                   Enabled,
		RequestSamplingPct:        RequestSamplingPct,
		MaxConcurrentRequests:     MaxConcurrentRequests,
		VulnerabilitiesPerRequest: VulnerabilitiesPerRequest,
		DeduplicationEnabled:      DeduplicationEnabled,
		RedactionEnabled:          RedactionEnabled,
		RedactionNamePattern:      RedactionNamePattern.String(),
		RedactionValuePattern:     RedactionValuePattern.String(),
		TruncationMaxValue:        TruncationMaxValue,
		MaxRangeCount:             MaxRangeCount,
		TelemetryVerbosity:        TelemetryVerbosity,
		DbRowsToTaint:             DbRowsToTaint,
		StackTraceEnabled:         StackTraceEnabled,
	}
}

// TestConfigSentinel prints a JSON snapshot of every public configuration
// global to stdout, prefixed with sentinelMarker, but only when invoked as a
// subprocess through runConfigInitSubprocess. It exists purely to let a
// subprocess observe the outcome of this package's init-time environment
// wiring under a controlled environment.
func TestConfigSentinel(t *testing.T) {
	if os.Getenv(sentinelEnvVar) != "1" {
		t.Skip("this test only runs as a subprocess sentinel; see the TestConfigInit* tests")
	}
	data, err := json.Marshal(currentConfigSnapshot())
	require.NoError(t, err)
	// Intentionally written directly to stdout (not via t.Log) so the parent
	// process can parse it independently of `go test` output formatting.
	_, err = os.Stdout.WriteString(sentinelMarker + string(data) + "\n")
	require.NoError(t, err)
}

// runConfigInitSubprocess starts a fresh copy of this test binary with an
// explicitly filtered environment (the current process environment, with any
// pre-existing DD_IAST_* variables stripped, plus the sentinel marker and the
// caller-supplied overrides). It runs only TestConfigSentinel in the child,
// which reports back the configuration globals that resulted from package
// initialization under that environment.
func runConfigInitSubprocess(t *testing.T, env map[string]string) configSnapshot {
	t.Helper()

	var filtered []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DD_IAST_") {
			continue
		}
		filtered = append(filtered, kv)
	}
	filtered = append(filtered, sentinelEnvVar+"=1")
	for k, v := range env {
		filtered = append(filtered, k+"="+v)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestConfigSentinel$", "-test.v=false")
	cmd.Env = filtered

	out, err := cmd.Output()
	require.NoError(t, err, "subprocess failed, output: %s", out)

	var line string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, sentinelMarker) {
			line = l
			break
		}
	}
	require.NotEmpty(t, line, "subprocess did not produce the expected sentinel output; full output: %s", out)

	var snap configSnapshot
	require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, sentinelMarker)), &snap))
	return snap
}

func TestConfigInitDefaults(t *testing.T) {
	got := runConfigInitSubprocess(t, nil)

	want := configSnapshot{
		Enabled:                   true,
		RequestSamplingPct:        30,
		MaxConcurrentRequests:     2,
		VulnerabilitiesPerRequest: 2,
		DeduplicationEnabled:      true,
		RedactionEnabled:          true,
		RedactionNamePattern:      defaultRedactionNamePattern.String(),
		RedactionValuePattern:     defaultRedactionValuePattern.String(),
		TruncationMaxValue:        250,
		MaxRangeCount:             10,
		TelemetryVerbosity:        LogLevelInformation,
		DbRowsToTaint:             1,
		StackTraceEnabled:         true,
	}
	require.Equal(t, want, got)
}

func TestConfigInitValidEnvironment(t *testing.T) {
	env := map[string]string{
		EnvVarEnabled:                   "false",
		EnvVarRequestSampling:           "55",
		EnvVarMaxConcurrentRequests:     "7",
		EnvVarVulnerabilitiesPerRequest: "3",
		EnvVarDeduplicationEnabled:      "false",
		EnvVarRedactionEnabled:          "false",
		EnvVarRedactionNamePattern:      "^custom-name$",
		EnvVarRedactionValuePattern:     "^custom-value$",
		EnvVarTruncationMaxValue:        "999",
		EnvVarMaxRangeCount:             "42",
		EnvVarTelemetryVerbosity:        "DEBUG",
		EnvVarDbRowsToTaint:             "5",
		EnvVarStackTraceEnabled:         "false",
	}
	got := runConfigInitSubprocess(t, env)

	want := configSnapshot{
		Enabled:                   false,
		RequestSamplingPct:        55,
		MaxConcurrentRequests:     7,
		VulnerabilitiesPerRequest: 3,
		DeduplicationEnabled:      false,
		RedactionEnabled:          false,
		RedactionNamePattern:      "^custom-name$",
		RedactionValuePattern:     "^custom-value$",
		TruncationMaxValue:        999,
		MaxRangeCount:             42,
		TelemetryVerbosity:        LogLevelDebug,
		DbRowsToTaint:             5,
		StackTraceEnabled:         false,
	}
	require.Equal(t, want, got)
}

// TestConfigInitInvalidAndClampedEnvironment verifies that malformed or
// out-of-range environment values fall back to defaults or are clamped to the
// applicable bound.
func TestConfigInitInvalidAndClampedEnvironment(t *testing.T) {
	require.Equal(t, "DD_IAST_DB_ROWS_TO_TAINT", EnvVarDbRowsToTaint)

	env := map[string]string{
		EnvVarEnabled:                   "not-a-bool",
		EnvVarRequestSampling:           "500",
		EnvVarMaxConcurrentRequests:     "not-an-int",
		EnvVarVulnerabilitiesPerRequest: "0",
		EnvVarRedactionNamePattern:      "(unterminated",
		EnvVarTelemetryVerbosity:        "loud",
	}
	got := runConfigInitSubprocess(t, env)

	require.True(t, got.Enabled, "malformed boolean must fall back to the default")
	require.Equal(t, 100, got.RequestSamplingPct, "out-of-range percentage must clamp to the upper bound")
	require.Equal(t, 2, got.MaxConcurrentRequests, "malformed integer must fall back to the default")
	require.Equal(t, 1, got.VulnerabilitiesPerRequest, "value below the lower bound must clamp to the lower bound")
	require.Equal(t, defaultRedactionNamePattern.String(), got.RedactionNamePattern, "invalid regexp must fall back to the default pattern")
	require.Equal(t, LogLevelInformation, got.TelemetryVerbosity, "invalid log level must fall back to the default")
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestGateOffByEnvironment(t *testing.T) {
	type result struct {
		Enabled bool
		Reason  string
	}
	if os.Getenv("DD_IAST_GATE_TEST_HELPER") == "1" {
		if err := json.NewEncoder(os.Stdout).Encode(result{Enabled(), offReason}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	for _, tc := range []struct {
		name, iast, tracking, limit, reason string
	}{
		{"IAST disabled", "false", "true", "1048576", "IAST disabled"},
		{"tracking disabled", "true", "false", "1048576", "taint tracking disabled"},
		{"zero limit", "true", "true", "0", "memory limit is zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DD_IAST_GATE_TEST_HELPER", "1")
			t.Setenv(envVarIASTEnabled, tc.iast)
			t.Setenv(EnvVarTrackingEnabled, tc.tracking)
			t.Setenv(EnvVarMemoryLimit, tc.limit)
			cmd := exec.Command(os.Args[0], "-test.run=^TestGateOffByEnvironment$")
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("helper: %v", err)
			}
			var got result
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatalf("helper output %q: %v", output, err)
			}
			if got.Enabled || got.Reason != tc.reason {
				t.Fatalf("gate = %+v, want off (%s)", got, tc.reason)
			}
		})
	}
}

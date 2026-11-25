// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
)

func TestGateOffByConfig(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires a woven build")
	}
	program := initProgram(t)
	for _, tc := range []struct {
		name, iast, tracking, limit, reason string
		unsetTracking                       bool
	}{
		{"IAST disabled", "false", "true", "1048576", "IAST disabled", false},
		{"tracking disabled", "true", "false", "1048576", "taint tracking disabled", false},
		{"tracking unset", "true", "", "1048576", "taint tracking disabled", true},
		{"zero limit", "true", "true", "0", "memory limit is zero", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DD_IAST_ENABLED", tc.iast)
			t.Setenv(heapranges.EnvVarTrackingEnabled, tc.tracking)
			t.Setenv(heapranges.EnvVarMemoryLimit, tc.limit)
			if tc.unsetTracking {
				if err := os.Unsetenv(heapranges.EnvVarTrackingEnabled); err != nil {
					t.Fatal(err)
				}
			}
			output, err := exec.Command(program).Output()
			if err != nil {
				t.Fatalf("init program: %v", err)
			}
			var got struct {
				Enabled  bool              `json:"enabled"`
				Gate     uint32            `json:"gate"`
				Reason   string            `json:"reason"`
				Settings map[string]string `json:"settings"`
			}
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatalf("init program output %q: %v", output, err)
			}
			if !reflect.DeepEqual(got.Settings, buildSettings()) {
				t.Fatalf("build settings = %v, want %v", got.Settings, buildSettings())
			}
			if got.Enabled || got.Reason != tc.reason {
				t.Fatalf("gate = %+v, want off (%s)", got, tc.reason)
			}
		})
	}
}

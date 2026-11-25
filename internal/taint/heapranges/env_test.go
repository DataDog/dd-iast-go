// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"os"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config/parser"
)

func TestEnvironmentDefaults(t *testing.T) {
	for _, name := range []string{envVarIASTEnabled, EnvVarTrackingEnabled, EnvVarMemoryLimit} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	got := readEnvironment()
	if !got.iastEnabled || got.trackingEnabled || got.memoryLimit != defaultMemoryLimit || got.warningCount != 0 {
		t.Fatalf("unexpected defaults: %#v", got)
	}
	for _, value := range got.values[:got.valueCount] {
		if value.origin != parser.OriginDefault {
			t.Fatalf("unexpected origin for %s: %v", value.name, value.origin)
		}
	}
}

func TestMemoryLimitEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		want     uint64
		warnings int
		origin   parser.Origin
	}{
		{"zero", "0", 0, 0, parser.OriginEnvVar},
		{"below minimum", "1", minMemoryLimit, 1, parser.OriginEnvVar},
		{"minimum", "1048576", minMemoryLimit, 0, parser.OriginEnvVar},
		{"maximum", "1073741824", maxMemoryLimit, 0, parser.OriginEnvVar},
		{"above maximum", "1073741825", maxMemoryLimit, 1, parser.OriginEnvVar},
		{"negative", "-1", defaultMemoryLimit, 1, parser.OriginDefault},
		{"invalid", "bad", defaultMemoryLimit, 1, parser.OriginDefault},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envVarIASTEnabled, "true")
			t.Setenv(EnvVarTrackingEnabled, "false")
			t.Setenv(EnvVarMemoryLimit, tc.input)
			got := readEnvironment()
			if got.memoryLimit != tc.want || got.warningCount != tc.warnings {
				t.Fatalf("limit = %d, warnings = %d; want %d, %d", got.memoryLimit, got.warningCount, tc.want, tc.warnings)
			}
			if got.valueCount != 3 || got.values[2].name != EnvVarMemoryLimit || got.values[2].value != tc.want || got.values[2].origin != tc.origin {
				t.Fatalf("registered values = %#v", got.values[:got.valueCount])
			}
		})
	}
}

func TestTrackingEnvironment(t *testing.T) {
	for _, tc := range []struct {
		iast, tracking         string
		wantIAST, wantTracking bool
	}{
		{"false", "true", false, true},
		{"true", "false", true, false},
		{"true", "true", true, true},
	} {
		t.Run(tc.iast+"/"+tc.tracking, func(t *testing.T) {
			t.Setenv(envVarIASTEnabled, tc.iast)
			t.Setenv(EnvVarTrackingEnabled, tc.tracking)
			t.Setenv(EnvVarMemoryLimit, "0")
			got := readEnvironment()
			if got.iastEnabled != tc.wantIAST || got.trackingEnabled != tc.wantTracking {
				t.Fatalf("enabled = %t, tracking = %t", got.iastEnabled, got.trackingEnabled)
			}
		})
	}
}

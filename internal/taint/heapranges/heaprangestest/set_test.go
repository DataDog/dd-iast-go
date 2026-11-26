// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/build"
)

func TestSetRespectsOwnerLiveness(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires a woven build")
	}
	if (runtime.GOOS != "linux" && runtime.GOOS != "darwin") || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("unsupported platform")
	}
	settings := buildSettings()
	if settings["-asan"] == "true" || settings["-msan"] == "true" {
		t.Skip("unsupported sanitizer")
	}
	program := initProgram(t)
	t.Setenv("GOMAXPROCS", "2")
	for _, scenario := range []string{"unregistered", "live", "reverse", "absorbing", "ended", "reused", "same", "unknown", "no-snapshot", "exposed", "exposed-cc", "pool-empty", "cas-failed", "drop-on-failure", "limit", "model", "end-race"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, program, "set", scenario).Output()
			if err != nil {
				t.Fatalf("init program: %v", err)
			}
			var got struct {
				Valid bool `json:"set_valid"`
			}
			if err := json.Unmarshal(output, &got); err != nil || !got.Valid {
				t.Fatalf("set result %q: %v", output, err)
			}
		})
	}
}

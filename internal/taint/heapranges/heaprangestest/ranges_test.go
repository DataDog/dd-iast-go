// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/build"
)

func TestRangesReturnsEveryRange(t *testing.T) {
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
	for _, scenario := range []string{
		"nil buffer", "zero capacity", "exact fit", "one more than capacity", "length is ignored", "maximum",
		"collapse", "poison", "clean", "relative offsets", "merge", "model", "missing snapshot", "snapshot mismatch",
	} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, program, "ranges", scenario)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("init program: %v: %s", err, &stderr)
			}
			var got struct {
				Valid bool `json:"range_valid"`
			}
			if err := json.Unmarshal(output, &got); err != nil || !got.Valid {
				t.Fatalf("range result %q: %v (model seed 71829): %s", output, err, &stderr)
			}
		})
	}
}

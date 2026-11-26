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

func TestMapContract(t *testing.T) {
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
		"exact", "contributors-same", "contributors-different", "contributors-unknown", "contributors-conflict", "contributors-poison",
		"clean-contributors", "all-clean", "bits", "exposed-input", "constant-unknown",
		"early-end", "early-gap", "early-overlap", "early-bounds", "early-source", "early-input-bounds", "early-exact", "early-flags", "early-count", "early-budget", "early-partial-scan", "early-snapshot", "early-partial-snapshot",
		"two-inputs", "same-object-inputs", "too-many-inputs", "exposed-self", "exposed-other", "exposed-no-owner", "exposed-ended-owner", "exposed-no-area", "exposed-changed", "exposed-reuse", "exposed-full", "observed-writes", "private-to-exposed",
		"real-write", "conflict-write", "poison-destination", "span-poison-destination", "failure", "clean-failure", "cas-failure", "empty", "range-limit", "stack-destination", "out-of-bounds",
	} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, program, "mapping", scenario).Output()
			if err != nil {
				t.Fatalf("init program: %v", err)
			}
			var got struct {
				Valid bool `json:"mapping_valid"`
			}
			if err := json.Unmarshal(output, &got); err != nil || !got.Valid {
				t.Fatalf("mapping result %q: %v", output, err)
			}
		})
	}
}

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

func TestCopyContract(t *testing.T) {
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
		"immutable-origins", "exposed-self", "no-owner", "ended-owner", "no-area", "snapshot-reference",
		"changed-bytes", "sensitive-mismatch", "ended-source", "exposed-to-immutable", "clean-source", "clean-inline", "conflict", "poison-destination",
		"span-poison-destination", "poison-source", "private", "expose-private", "unmarked-private",
		"overlap-left", "overlap-right", "overlap-exposed", "model", "private-kept-ranges", "recorded-exposed",
		"recorded-immutable", "snapshot-full",
		"budget", "range-limit", "stale-table", "span-poison-failure", "cas-failed", "clean-nochange-pool", "pool-empty",
		"stack-source", "stack-destination", "out-of-bounds", "observed-writes",
	} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, program, "copy", scenario).Output()
			if err != nil {
				t.Fatalf("init program: %v", err)
			}
			var got struct {
				Valid bool `json:"copy_valid"`
			}
			if err := json.Unmarshal(output, &got); err != nil || !got.Valid {
				t.Fatalf("copy result %q: %v", output, err)
			}
		})
	}
}

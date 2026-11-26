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

func TestRetirementQueue(t *testing.T) {
	testRetirementProgram(t, "retire", "retire_valid")
}

func TestPoisonEntry(t *testing.T) {
	testRetirementProgram(t, "poison", "poison_valid")
}

func TestClearRanges(t *testing.T) {
	testRetirementProgram(t, "clear", "clear_valid")
}

func TestConcurrentPublication(t *testing.T) {
	testRetirementProgram(t, "publish", "publish_valid")
}

func TestOwnerLifecycle(t *testing.T) {
	testRetirementProgram(t, "owner", "owner_valid")
}

func TestSnapshotAreaLifecycle(t *testing.T) {
	testRetirementProgram(t, "snapshot", "snapshot_valid")
}

func TestSnapshotAreaBytes(t *testing.T) {
	testRetirementProgram(t, "snapshot-bytes", "snapshot_valid")
}

func testRetirementProgram(t *testing.T, scenario, field string) {
	t.Helper()
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, program, scenario).Output()
	if err != nil {
		t.Fatalf("init program: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(output, &got); err != nil || got[field] != true {
		t.Fatalf("retirement result %q: %v", output, err)
	}
}

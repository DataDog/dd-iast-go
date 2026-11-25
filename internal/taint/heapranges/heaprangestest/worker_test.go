// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"context"
	"encoding/json"
	"os/exec"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/build"
)

func TestRuntimeSlabPool(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires a woven build")
	}
	program := initProgram(t)
	t.Setenv("GOMAXPROCS", "8")
	for _, tc := range []struct {
		scenario string
		count    int
	}{{"pool", 24000}, {"tail", 0}} {
		t.Run(tc.scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, program, tc.scenario).Output()
			if err != nil {
				t.Fatalf("init program: %v", err)
			}
			var got struct {
				Count    int               `json:"pool_count"`
				Valid    bool              `json:"pool_valid"`
				Settings map[string]string `json:"settings"`
			}
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatalf("init program output %q: %v", output, err)
			}
			if !reflect.DeepEqual(got.Settings, buildSettings()) {
				t.Fatalf("build settings = %v, want %v", got.Settings, buildSettings())
			}
			if !got.Valid || got.Count != tc.count {
				t.Fatalf("pool = %+v, want %d distinct units", got, tc.count)
			}
		})
	}
}

func TestSlabWorkerInitialization(t *testing.T) {
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
	for _, tc := range []struct {
		name, scenario, procs string
		limit, mapped         uint64
		queues, ready         uint32
		pauseValid            bool
	}{
		{"default budget", "worker", "128", 64 << 20, 3 << 20, 128, 1, false},
		{"minimum budget", "worker", "128", 1 << 20, 1 << 20, 16, 0, false},
		{"partial slab budget", "worker", "128", (1 << 20) + (256 << 10), 1 << 20, 20, 0, false},
		{"background refill", "worker-refill", "2", 64 << 20, 3 << 20, 2, 2, false},
		{"processor growth", "worker-grow", "2", 64 << 20, 3 << 20, 32, 2, false},
		{"paused refiller", "worker-pause", "2", 64 << 20, 3 << 20, 2, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GOMAXPROCS", tc.procs)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, program, tc.scenario, strconv.FormatUint(tc.limit, 10)).Output()
			if err != nil {
				t.Fatalf("init program: %v", err)
			}
			var got struct {
				MapOK       bool              `json:"map_ok"`
				Mapped      uint64            `json:"mapped"`
				Queues      uint32            `json:"queues"`
				QueuesValid bool              `json:"queues_valid"`
				Ready       uint32            `json:"ready"`
				PauseValid  bool              `json:"pause_valid"`
				Settings    map[string]string `json:"settings"`
			}
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatalf("init program output %q: %v", output, err)
			}
			if !reflect.DeepEqual(got.Settings, settings) {
				t.Fatalf("build settings = %v, want %v", got.Settings, settings)
			}
			if !got.MapOK || !got.QueuesValid || got.Mapped != tc.mapped || got.Queues != tc.queues || got.Ready != tc.ready || got.PauseValid != tc.pauseValid {
				t.Fatalf("worker = %+v, want mapped=%d queues=%d ready=%d", got, tc.mapped, tc.queues, tc.ready)
			}
		})
	}
}

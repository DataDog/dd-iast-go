// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"encoding/json"
	"os/exec"
	"reflect"
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
)

func TestSlabMappingAndAccounting(t *testing.T) {
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
	t.Setenv("GOMAXPROCS", "1")
	for _, tc := range []struct {
		scenario  string
		accounted bool
	}{{"slab", true}, {"slab-negative", false}} {
		t.Run(tc.scenario, func(t *testing.T) {
			output, err := exec.Command(program, tc.scenario).Output()
			if err != nil {
				t.Fatalf("init program: %v", err)
			}
			var got struct {
				MapOK       bool              `json:"map_ok"`
				Mapped      uint64            `json:"mapped"`
				OtherSys    uint64            `json:"other_sys"`
				OtherBefore uint64            `json:"other_before"`
				Settings    map[string]string `json:"settings"`
			}
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatalf("init program output %q: %v", output, err)
			}
			if !reflect.DeepEqual(got.Settings, settings) {
				t.Fatalf("build settings = %v, want %v", got.Settings, settings)
			}
			if !got.MapOK || got.Mapped != 1<<20 {
				t.Fatalf("mapping result = %+v", got)
			}
			increased := got.OtherSys >= got.OtherBefore && got.OtherSys-got.OtherBefore >= got.Mapped
			if increased != tc.accounted {
				t.Fatalf("accounted = %t, want %t: %+v", increased, tc.accounted, got)
			}
		})
	}
}

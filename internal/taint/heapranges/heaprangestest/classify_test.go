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
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func TestEntryTableBinding(t *testing.T) {
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
	output, err := exec.CommandContext(ctx, program, "table").Output()
	if err != nil {
		t.Fatalf("init program: %v", err)
	}
	var got struct {
		Valid    bool              `json:"pool_valid"`
		Settings map[string]string `json:"settings"`
	}
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("init program output %q: %v", output, err)
	}
	if !reflect.DeepEqual(got.Settings, settings) || !got.Valid {
		t.Fatalf("table result = %+v, build settings = %v", got, settings)
	}
}

var classifierStatic [128]byte
var classifierHeap *[2048]byte

func TestHeapClassifier(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires a woven build")
	}
	if knobs.Classify == nil || knobs.ClassifyStack == nil {
		t.Fatal("classifier is not linked")
	}
	classifierHeap = new([2048]byte)
	t.Cleanup(func() { classifierHeap = nil })
	pointer := unsafe.Pointer(&classifierHeap[0])
	offset, size, index, ok := knobs.Classify(pointer, 2048)
	if !ok || size < 2048 || offset > size-2048 {
		t.Fatalf("heap classification = offset %d size %d index %d ok %t", offset, size, index, ok)
	}
	otherOffset, otherSize, otherIndex, ok := knobs.Classify(unsafe.Add(pointer, 128), 64)
	if !ok || otherOffset != offset+128 || otherSize != size || otherIndex != index {
		t.Fatalf("interior classification = offset %d size %d index %d ok %t", otherOffset, otherSize, otherIndex, ok)
	}
	for _, tc := range []struct {
		name string
		p    unsafe.Pointer
		n    uintptr
	}{
		{"nil", nil, 1},
		{"static", unsafe.Pointer(&classifierStatic[0]), 1},
		{"zero length", pointer, 0},
		{"cross slot", pointer, size - offset + 1},
		{"overflow", pointer, ^uintptr(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, ok := knobs.Classify(tc.p, tc.n); ok {
				t.Fatal("invalid range classified as heap")
			}
		})
	}
	if !knobs.ClassifyStack() {
		t.Fatal("stack range was not rejected")
	}
	runtime.KeepAlive(classifierHeap)
}

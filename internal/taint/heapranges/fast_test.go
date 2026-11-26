// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func TestFastCheckUnwoven(t *testing.T) {
	var value [32]byte
	if MayHaveTaint(unsafe.Pointer(&value[0]), uintptr(len(value))) || Any(unsafe.Pointer(&value[0]), uintptr(len(value))) || len(Ranges(unsafe.Pointer(&value[0]), uintptr(len(value)), nil)) != 0 {
		t.Fatal("unwoven check reported taint")
	}
}

func TestFastCheckDoesNotEscape(t *testing.T) {
	output, err := exec.Command("go", "build", "-gcflags=-m", "-o", filepath.Join(t.TempDir(), "escape"), "./testdata/escape").CombinedOutput()
	if err != nil {
		t.Fatalf("build escape test: %v\n%s", err, output)
	}
	text := string(output)
	if !strings.Contains(text, "moved to heap: control") || strings.Contains(text, "moved to heap: target") || strings.Contains(text, "moved to heap: ranges") {
		t.Fatalf("escape analysis output:\n%s", text)
	}
}

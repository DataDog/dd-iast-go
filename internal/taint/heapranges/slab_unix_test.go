// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build linux || darwin

package heapranges

import (
	"syscall"
	"testing"
	"unsafe"
)

func TestSlabMapping(t *testing.T) {
	memory, ok := mapSlab()
	if !ok {
		t.Fatal("slab mapping failed")
	}
	t.Cleanup(func() {
		if err := syscall.Munmap(memory); err != nil {
			t.Errorf("unmap test slab: %v", err)
		}
	})
	if len(memory) != slabSize {
		t.Fatalf("slab length = %d, want %d", len(memory), slabSize)
	}
	if uintptr(unsafe.Pointer(&memory[0]))%64 != 0 {
		t.Fatal("slab is not 64-byte aligned")
	}
	memory[0] = 1
	memory[len(memory)-1] = 2
	if memory[0] != 1 || memory[len(memory)-1] != 2 {
		t.Fatal("slab is not writable")
	}
}

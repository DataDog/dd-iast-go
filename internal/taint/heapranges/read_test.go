// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"reflect"
	"testing"
	"unsafe"
)

var rangeResult []Range

func TestRangesBuffer(t *testing.T) {
	old := runtimeRanges
	t.Cleanup(func() { runtimeRanges = old })
	want := [3]Range{
		{Off: 0, Len: 2, Origin: 1},
		{Off: 3, Len: 2, Origin: 2},
		{Off: 6, Len: 2, Origin: 3},
	}
	runtimeRanges = func(_ unsafe.Pointer, _ uintptr, out unsafe.Pointer) uint32 {
		output := (*[MaxRanges]Range)(out)
		copy(output[:], want[:])
		return uint32(len(want))
	}
	for _, tc := range []struct {
		name     string
		capacity int
		length   int
	}{
		{"nil", 0, 0},
		{"too small", 2, 2},
		{"exact", 3, 0},
		{"length ignored", MaxRanges, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buffer []Range
			if tc.capacity > 0 {
				buffer = make([]Range, tc.length, tc.capacity)
				for i := range buffer {
					buffer[i] = Range{Off: 99}
				}
			}
			got := Ranges(nil, 8, buffer)
			if !reflect.DeepEqual(got, want[:]) {
				t.Fatalf("ranges = %v, want %v", got, want)
			}
			if tc.capacity < len(want) {
				if cap(got) != MaxRanges {
					t.Fatalf("capacity = %d, want %d", cap(got), MaxRanges)
				}
				for _, sentinel := range buffer {
					if sentinel.Off != 99 {
						t.Fatal("small buffer was modified")
					}
				}
			} else if &got[0] != &buffer[:cap(buffer)][0] {
				t.Fatal("result does not use the caller buffer")
			}
		})
	}
	var buffer [MaxRanges]Range
	if allocations := testing.AllocsPerRun(100, func() { rangeResult = Ranges(nil, 8, buffer[:0]) }); allocations != 0 {
		t.Fatalf("large buffer: %v allocations, want 0", allocations)
	}
	if allocations := testing.AllocsPerRun(100, func() { rangeResult = Ranges(nil, 8, nil) }); allocations != 1 {
		t.Fatalf("nil buffer: %v allocations, want 1", allocations)
	}
}

func TestRangesUnwovenClean(t *testing.T) {
	old := runtimeRanges
	runtimeRanges = nil
	t.Cleanup(func() { runtimeRanges = old })
	buffer := make([]Range, 2, 3)
	got := Ranges(nil, 0, buffer)
	if len(got) != 0 || cap(got) != cap(buffer) || &got[:cap(got)][0] != &buffer[0] {
		t.Fatalf("clean result = %v, capacity %d", got, cap(got))
	}
}

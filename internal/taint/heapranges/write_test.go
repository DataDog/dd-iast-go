// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"runtime"
	"testing"
	"unsafe"
)

func TestCopyAndMapWhenNotWoven(t *testing.T) {
	if runtimeSet != nil {
		t.Skip("requires an unwoven build")
	}
	src := [4]byte{1, 2, 3, 4}
	dst := [4]byte{5, 6, 7, 8}
	inputs := []Input{{P: unsafe.Pointer(&src[0]), N: uintptr(len(src))}}
	segments := []Segment{{DstLen: 4, SrcLen: 4, Flags: SegmentExact}}
	if Copy(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), 4, Exposed, NoOwner) ||
		Map(unsafe.Pointer(&dst[0]), 4, inputs, segments, Exposed, NoOwner) ||
		Map(nil, 0, nil, nil, Exposed, NoOwner) {
		t.Fatal("unwoven write succeeded")
	}
	if src != [4]byte{1, 2, 3, 4} || dst != [4]byte{5, 6, 7, 8} {
		t.Fatal("unwoven write changed the bytes")
	}
}

func TestCopyAndMapDispatch(t *testing.T) {
	if runtimeSet != nil {
		t.Skip("requires an unwoven build")
	}
	var src, dst [4]byte
	owner := OwnerOf(3, 5)
	oldCopy, oldMap := runtimeCopy, runtimeMap
	defer func() { runtimeCopy, runtimeMap = oldCopy, oldMap }()
	runtimeCopy = func(d, s unsafe.Pointer, n uintptr, kind Kind, self Owner, work unsafe.Pointer) bool {
		return d == unsafe.Pointer(&dst[0]) && s == unsafe.Pointer(&src[0]) && n == 4 && kind == Immutable && self == owner && work != nil
	}
	runtimeMap = func(d unsafe.Pointer, n uintptr, srcs []Input, segs []Segment, kind Kind, self Owner, work unsafe.Pointer) bool {
		return d == unsafe.Pointer(&dst[0]) && n == 4 && len(srcs) == 1 && srcs[0].P == unsafe.Pointer(&src[0]) &&
			len(segs) == 1 && segs[0].Flags == SegmentExact && kind == Exposed && self == owner && work != nil
	}
	inputs := []Input{{P: unsafe.Pointer(&src[0]), N: 4}}
	segments := []Segment{{DstLen: 4, SrcLen: 4, Flags: SegmentExact}}
	if !Copy(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), 4, Immutable, owner) ||
		!Map(unsafe.Pointer(&dst[0]), 4, inputs, segments, Exposed, owner) {
		t.Fatal("write dispatch lost an argument")
	}
}

//go:noinline
func growMapTestStack(depth int) {
	var padding [1024]byte
	padding[0] = byte(depth)
	if depth > 0 {
		growMapTestStack(depth - 1)
	}
	runtime.KeepAlive(&padding)
}

func mapStackTest(_ unsafe.Pointer, _ uintptr, srcs []Input, segs []Segment, _ Kind, _ Owner, _ unsafe.Pointer) bool {
	growMapTestStack(128)
	runtime.GC()
	if len(srcs) != 1 || len(segs) != 1 || segs[0].DstLen != 4 || *(*byte)(srcs[0].P) != 42 {
		return false
	}
	*(*byte)(srcs[0].P) = 17
	return true
}

//go:noinline
func mapWithStackInputs() bool {
	var src [4]byte
	var inputs [MaxMapInputs]Input
	var segments [8]Segment
	src[0] = 42
	inputs[0] = Input{P: unsafe.Pointer(&src[0]), N: 4}
	segments[0] = Segment{DstLen: 4, SrcLen: 4, Flags: SegmentExact}
	return Map(nil, 4, inputs[:1], segments[:1], Immutable, NoOwner) && src[0] == 17
}

func TestMapStackInputsSurviveStackGrowth(t *testing.T) {
	if runtimeSet != nil {
		t.Skip("requires an unwoven build")
	}
	old := runtimeMap
	runtimeMap = mapStackTest
	defer func() { runtimeMap = old }()
	if !mapWithStackInputs() {
		t.Fatal("stack inputs were not preserved")
	}
}

func TestClearUnwoven(t *testing.T) {
	if runtimeClear != nil {
		t.Skip("requires an unwoven build")
	}
	value := [4]byte{1, 2, 3, 4}
	Clear(nil, 0)
	Clear(unsafe.Pointer(&value[0]), uintptr(len(value)))
	if value != [4]byte{1, 2, 3, 4} {
		t.Fatal("Clear changed the bytes")
	}
}

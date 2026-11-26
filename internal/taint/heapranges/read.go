// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "unsafe"

// MaxRanges is the largest number of ranges returned by Ranges.
const MaxRanges = 65

// Origin identifies the source of a range.
type Origin uint64

// Range describes a tainted part of a requested memory range.
type Range struct {
	Off    uint32
	Len    uint32
	Origin Origin
	Marks  uint8
	Flags  uint8
	_      [6]byte
}

var (
	_ [24 - unsafe.Sizeof(Range{})]byte
	_ [unsafe.Sizeof(Range{}) - 24]byte
	_ [0 - unsafe.Offsetof(Range{}.Off)]byte
	_ [unsafe.Offsetof(Range{}.Off) - 0]byte
	_ [4 - unsafe.Offsetof(Range{}.Len)]byte
	_ [unsafe.Offsetof(Range{}.Len) - 4]byte
	_ [8 - unsafe.Offsetof(Range{}.Origin)]byte
	_ [unsafe.Offsetof(Range{}.Origin) - 8]byte
	_ [16 - unsafe.Offsetof(Range{}.Marks)]byte
	_ [unsafe.Offsetof(Range{}.Marks) - 16]byte
	_ [17 - unsafe.Offsetof(Range{}.Flags)]byte
	_ [unsafe.Offsetof(Range{}.Flags) - 17]byte
)

var (
	runtimeAny    func(unsafe.Pointer, uintptr) bool
	runtimeRanges func(unsafe.Pointer, uintptr, unsafe.Pointer) uint32
)

// Any reports whether the range might contain taint.
func Any(p unsafe.Pointer, n uintptr) bool {
	if runtimeAny == nil {
		return false
	}
	return runtimeAny(noescape(p), n)
}

// Ranges returns all tainted ranges relative to p.
func Ranges(p unsafe.Pointer, n uintptr, buf []Range) []Range {
	if runtimeRanges == nil {
		return buf[:0]
	}
	var output [MaxRanges]Range
	count := int(runtimeRanges(noescape(p), n, noescape(unsafe.Pointer(&output[0]))))
	if count > cap(buf) {
		buf = make([]Range, MaxRanges)
	}
	buf = buf[:count]
	copy(buf, output[:count])
	return buf
}

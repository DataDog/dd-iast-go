// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"runtime"
	"unsafe"
)

const (
	// MaxMapInputs is the maximum number of inputs to a mapping.
	MaxMapInputs = 4
	// MaxSegments is the maximum number of segments in a mapping.
	MaxSegments = 1024
)

const (
	// SegmentExact maps each output byte to the matching input byte.
	SegmentExact uint8 = 1 << iota
	// SegmentUnknown marks output whose origin is unknown.
	SegmentUnknown
	// SegmentSensitive marks unknown output that can be sensitive.
	SegmentSensitive
)

// Input describes one input to a mapping.
type Input struct {
	P unsafe.Pointer
	N uintptr
}

// Segment describes one output part and its input contributors.
type Segment struct {
	DstOff, DstLen uint32
	SrcOff, SrcLen uint32
	Src            uint8
	Flags          uint8
}

var (
	_          [2*unsafe.Sizeof(uintptr(0)) - unsafe.Sizeof(Input{})]byte
	_          [unsafe.Sizeof(Input{}) - 2*unsafe.Sizeof(uintptr(0))]byte
	_          [unsafe.Sizeof(uintptr(0)) - unsafe.Offsetof(Input{}.N)]byte
	_          [unsafe.Offsetof(Input{}.N) - unsafe.Sizeof(uintptr(0))]byte
	_          [20 - unsafe.Sizeof(Segment{})]byte
	_          [unsafe.Sizeof(Segment{}) - 20]byte
	_          [4 - unsafe.Offsetof(Segment{}.DstLen)]byte
	_          [unsafe.Offsetof(Segment{}.DstLen) - 4]byte
	_          [8 - unsafe.Offsetof(Segment{}.SrcOff)]byte
	_          [unsafe.Offsetof(Segment{}.SrcOff) - 8]byte
	_          [12 - unsafe.Offsetof(Segment{}.SrcLen)]byte
	_          [unsafe.Offsetof(Segment{}.SrcLen) - 12]byte
	_          [16 - unsafe.Offsetof(Segment{}.Src)]byte
	_          [unsafe.Offsetof(Segment{}.Src) - 16]byte
	_          [17 - unsafe.Offsetof(Segment{}.Flags)]byte
	_          [unsafe.Offsetof(Segment{}.Flags) - 17]byte
	runtimeMap func(unsafe.Pointer, uintptr, []Input, []Segment, Kind, Owner, unsafe.Pointer) bool
)

// Map propagates ranges after a transform has written dst.
func Map(dst unsafe.Pointer, dstLen uintptr, srcs []Input, segs []Segment, kind Kind, self Owner) bool {
	if runtimeMap == nil {
		return false
	}
	var work [MaxMapInputs + 4][65]writeRange
	inputs := unsafe.Slice((*Input)(noescape(unsafe.Pointer(unsafe.SliceData(srcs)))), len(srcs))
	segments := unsafe.Slice((*Segment)(noescape(unsafe.Pointer(unsafe.SliceData(segs)))), len(segs))
	ok := runtimeMap(noescape(dst), dstLen, inputs, segments, kind, self, noescape(unsafe.Pointer(&work[0][0])))
	runtime.KeepAlive(srcs)
	runtime.KeepAlive(segs)
	runtime.KeepAlive(dst)
	return ok
}

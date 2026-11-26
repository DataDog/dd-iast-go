// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "unsafe"

// Kind describes how the memory can be changed.
type Kind uint8

const (
	// Immutable memory is not writable by application code.
	Immutable Kind = iota
	// Private memory is writable only by instrumented code.
	Private
	// Exposed memory can be changed by application code.
	Exposed
)

type writeRange struct {
	offset   uint32
	length   uint32
	origin   uint64
	snapshot uint32
	marks    uint8
	flags    uint8
	_        [2]byte
}

var (
	_            [24 - unsafe.Sizeof(writeRange{})]byte
	_            [unsafe.Sizeof(writeRange{}) - 24]byte
	_            [0 - unsafe.Offsetof(writeRange{}.offset)]byte
	_            [unsafe.Offsetof(writeRange{}.offset) - 0]byte
	_            [4 - unsafe.Offsetof(writeRange{}.length)]byte
	_            [unsafe.Offsetof(writeRange{}.length) - 4]byte
	_            [8 - unsafe.Offsetof(writeRange{}.origin)]byte
	_            [unsafe.Offsetof(writeRange{}.origin) - 8]byte
	_            [16 - unsafe.Offsetof(writeRange{}.snapshot)]byte
	_            [unsafe.Offsetof(writeRange{}.snapshot) - 16]byte
	_            [20 - unsafe.Offsetof(writeRange{}.marks)]byte
	_            [unsafe.Offsetof(writeRange{}.marks) - 20]byte
	_            [21 - unsafe.Offsetof(writeRange{}.flags)]byte
	_            [unsafe.Offsetof(writeRange{}.flags) - 21]byte
	runtimeClear func(unsafe.Pointer, uintptr, unsafe.Pointer)
	runtimeSet   func(unsafe.Pointer, uintptr, Origin, Kind, unsafe.Pointer) bool
)

// Set labels the requested range with an origin.
func Set(p unsafe.Pointer, n uintptr, origin Origin, kind Kind) bool {
	if runtimeSet == nil {
		return false
	}
	var work [64]writeRange
	return runtimeSet(noescape(p), n, origin, kind, noescape(unsafe.Pointer(&work[0])))
}

// Clear removes labels from the requested range.
func Clear(p unsafe.Pointer, n uintptr) {
	if runtimeClear == nil {
		return
	}
	var work [64]writeRange
	runtimeClear(noescape(p), n, noescape(unsafe.Pointer(&work[0])))
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

// bitStore is a replacement of the heap taint bits for the unit tests of
// this package (the bits need a woven runtime). The methods take uintptr
// values: an interface call makes pointer arguments escape.
type bitStore interface {
	set(p, n uintptr) bool
	any(p, n uintptr) bool
	next(p, n, from uintptr) uintptr
	nextClean(p, n, from uintptr) uintptr
}

// testBits is nil, except in the unit tests of this package. The tests set
// it before they start an analysis.
var testBits bitStore

func bitsSet(p unsafe.Pointer, n uintptr) bool {
	if b := testBits; b != nil {
		return b.set(uintptr(p), n)
	}
	return heapbits.Set(p, n)
}

func bitsAny(p unsafe.Pointer, n uintptr) bool {
	if b := testBits; b != nil {
		return b.any(uintptr(p), n)
	}
	return heapbits.Any(p, n)
}

func bitsNext(p unsafe.Pointer, n, from uintptr) uintptr {
	if b := testBits; b != nil {
		return b.next(uintptr(p), n, from)
	}
	return heapbits.Next(p, n, from)
}

func bitsNextClean(p unsafe.Pointer, n, from uintptr) uintptr {
	if b := testBits; b != nil {
		return b.nextClean(uintptr(p), n, from)
	}
	return heapbits.NextClean(p, n, from)
}

func bitsMarkLive() {
	if testBits != nil {
		return
	}
	heapbits.MarkLive()
}

// cloneBytes returns a heap copy of b with capacity c (c >= len(b)). It uses
// make and copy: they do not copy taint bits, also in a woven runtime.
func cloneBytes(b []byte, c int) []byte {
	clone := make([]byte, len(b), c)
	copy(clone, b)
	return clone
}

// ownerCopy returns an owner copy of b as a string. The copy has no taint
// bits. It returns "" for an empty b.
func ownerCopy(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	clone := cloneBytes(b, len(b))
	return unsafe.String(unsafe.SliceData(clone), len(clone))
}

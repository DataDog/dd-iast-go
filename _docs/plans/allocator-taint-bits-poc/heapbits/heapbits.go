// Package heapbits is a PoC: taint bits stored next to the Go allocator.
package heapbits

import (
	"runtime" // the symbols come from the woven runtime
	"unsafe"
)

//go:linkname rtSet __dd_iast_heapbits.set
var rtSet func(uintptr, uintptr) bool

//go:linkname rtClear __dd_iast_heapbits.clear
var rtClear func(uintptr, uintptr)

//go:linkname rtAny __dd_iast_heapbits.any
var rtAny func(uintptr, uintptr) bool

//go:linkname rtStats __dd_iast_heapbits.stats
var rtStats func() (uint64, uint64)

// Available tells if the runtime was woven.
func Available() bool { return rtSet != nil }

// TaintString taints all bytes of s. False: not heap memory (or no runtime support).
func TaintString(s string) bool {
	if rtSet == nil || len(s) == 0 {
		return false
	}
	ok := rtSet(uintptr(unsafe.Pointer(unsafe.StringData(s))), uintptr(len(s)))
	runtime.KeepAlive(s)
	return ok
}

// TaintBytes taints all bytes of b.
func TaintBytes(b []byte) bool {
	if rtSet == nil || len(b) == 0 {
		return false
	}
	ok := rtSet(uintptr(unsafe.Pointer(unsafe.SliceData(b))), uintptr(len(b)))
	runtime.KeepAlive(b)
	return ok
}

// ClearBytes removes the taint of b.
func ClearBytes(b []byte) {
	if rtClear == nil || len(b) == 0 {
		return
	}
	rtClear(uintptr(unsafe.Pointer(unsafe.SliceData(b))), uintptr(len(b)))
	runtime.KeepAlive(b)
}

// IsTainted tells if one byte of s is tainted.
func IsTainted(s string) bool {
	if rtAny == nil || len(s) == 0 {
		return false
	}
	return rtAny(uintptr(unsafe.Pointer(unsafe.StringData(s))), uintptr(len(s)))
}

// IsTaintedBytes tells if one byte of b is tainted.
func IsTaintedBytes(b []byte) bool {
	if rtAny == nil || len(b) == 0 {
		return false
	}
	return rtAny(uintptr(unsafe.Pointer(unsafe.SliceData(b))), uintptr(len(b)))
}

// Stats returns (bitmaps allocated, tainted spans swept).
func Stats() (uint64, uint64) {
	if rtStats == nil {
		return 0, 0
	}
	return rtStats()
}

//go:linkname rtNoSweep __dd_iast_heapbits.nosweep
var rtNoSweep func(bool)

// SetNoSweepForTest disables the sweep hook. Only for negative controls.
func SetNoSweepForTest(v bool) {
	if rtNoSweep != nil {
		rtNoSweep(v)
	}
}

//go:linkname rtFreegc __dd_iast_heapbits.freegc
var rtFreegc func(unsafe.Pointer, uintptr) bool

// FreegcForTest calls runtime.freegc (GOEXPERIMENT=runtimefreegc). Only for tests.
func FreegcForTest(p unsafe.Pointer, size uintptr) bool {
	if rtFreegc == nil {
		return false
	}
	return rtFreegc(p, size)
}

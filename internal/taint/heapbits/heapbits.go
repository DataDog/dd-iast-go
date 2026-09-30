// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package heapbits stores one taint bit for each byte of heap memory, next to
// the metadata of the Go allocator.
//
// The storage is in the Go runtime. The aspects in orchestrion.yml add it when
// the application is built with Orchestrion. Without these aspects (or on a
// platform that is not supported), all functions of this package do nothing
// and report "not tainted".
//
// The bits describe memory, not values. An operation that puts the bytes in
// new memory (the copy built-in function, a conversion that allocates, and so
// on) does not copy the bits; only [Copy] does. An operation that shares the
// memory (a sub-slice, or a conversion that the compiler makes without a
// copy) sees the same bits. Only heap memory can be tainted: stack memory, global variables and
// read-only data are refused. The runtime clears the bits of an object when
// the garbage collector frees it, so that a new object at the same address
// does not get old taint.
package heapbits

import (
	"runtime"
	"unsafe"
)

// The functions that call the runtime are not inlined (go:noinline): their
// stack check is a synchronous preemption point. The runtime entry points
// are nosplit and a short call has no other one, so a loop of inlined calls
// in application code could delay a stop-the-world.
//
// The runtime (woven by the aspects of orchestrion.yml) defines these
// variables with a push linkname. Without weaving, they stay nil.
//
// The functions take uintptr values (not pointers). A call through a function
// variable makes pointer arguments escape to the heap, and then the values
// that the application checks would move to the heap.
var (
	//go:linkname rtSet __dd_iast_heapbits.set
	rtSet func(p, n uintptr) bool

	//go:linkname rtClear __dd_iast_heapbits.clear
	rtClear func(p, n uintptr)

	//go:linkname rtAny __dd_iast_heapbits.any
	rtAny func(p, n uintptr) bool

	//go:linkname rtNext __dd_iast_heapbits.next
	rtNext func(p, n, from uintptr, want bool) uintptr

	//go:linkname rtCopy __dd_iast_heapbits.copy
	rtCopy func(dst, src, n uintptr) bool

	//go:linkname rtEnabled __dd_iast_heapbits.enabled
	rtEnabled func() bool

	//go:linkname rtSetBudget __dd_iast_heapbits.setbudget
	rtSetBudget func(bytes uintptr) bool
)

// DefaultBudget is the default memory budget of the taint bits: 64 MiB of
// storage, enough for taint in up to 512 MiB of heap.
const DefaultBudget = 64 << 20

// MaxBudget is the largest memory budget of the taint bits.
const MaxBudget = 1 << 30

// SetBudget sets the memory budget of the taint bits, in bytes. The runtime
// rounds it down to whole MiB; values above MaxBudget become MaxBudget; 0
// turns the storage off (Set then always fails). The budget counts all the
// memory that the feature maps for the bits (the 1 MiB slabs, which hold the
// bits and their directories), and this memory counts in the memory limit of
// the Go runtime (GOMEMLIMIT). It does not count the fixed metadata in the
// runtime (16 KiB of slab descriptors, and one field in each heap arena and
// span). When the budget is used, Set drops the taint (it returns false).
//
// SetBudget must be called before the first Set. It returns false (and
// changes nothing) after the runtime has mapped storage, or when the feature
// is not enabled.
func SetBudget(bytes uint64) bool {
	if rtSetBudget == nil || !Enabled() {
		return false
	}
	if bytes > MaxBudget {
		bytes = MaxBudget
	}
	return rtSetBudget(uintptr(bytes))
}

// Enabled reports whether the runtime was woven and the platform is
// supported.
func Enabled() bool {
	return rtEnabled != nil && rtEnabled()
}

// Set taints the n bytes at p. It returns false and changes no bit when n is
// 0, when the range wraps the address space, when the range is not inside one
// allocation slot of an in-use heap span (stack, global, off-heap or user
// arena memory, or a range that crosses into a neighbour object), when the
// span of the range is larger than 64 MiB (this bounds the work of the
// garbage collector hook), when the
// runtime cannot get the storage for the bits (the budget is used, the OS
// refused the memory, or another goroutine is getting the same storage: Set
// never waits), or when the feature is not enabled.
//
// The range must be the memory of one Go value (the data of one string or
// slice). The runtime checks the allocation slot, but several small
// pointer-free values can share one 16-byte slot (the tiny allocator); inside
// such a slot, it cannot check the bounds of each value. The String and Bytes
// helpers always give correct ranges.
//
//go:noinline
func Set(p unsafe.Pointer, n uintptr) bool {
	if rtSet == nil || n == 0 {
		return false
	}
	ok := rtSet(uintptr(p), n)
	runtime.KeepAlive(p)
	return ok
}

// Clear removes the taint of the n bytes at p. It ignores a range that [Set]
// would refuse, except that Clear never allocates. The same rule as for Set
// applies to the range.
//
//go:noinline
func Clear(p unsafe.Pointer, n uintptr) {
	if rtClear == nil || n == 0 {
		return
	}
	rtClear(uintptr(p), n)
	runtime.KeepAlive(p)
}

// Any reports whether one of the n bytes at p is tainted. It is safe for all
// addresses.
//
//go:noinline
func Any(p unsafe.Pointer, n uintptr) bool {
	if rtAny == nil || n == 0 {
		return false
	}
	ok := rtAny(uintptr(p), n)
	runtime.KeepAlive(p)
	return ok
}

// Next returns the smallest off in [from, n) such that the byte at p+off is
// tainted, or n. In all cases (also without weaving), from >= n returns n.
// Memory that is not heap memory is never tainted.
//
// Next and NextClean give the tainted ranges of a value without allocation:
//
//	for off := heapbits.Next(p, n, 0); off < n; {
//		end := heapbits.NextClean(p, n, off)
//		// bytes [off, end) are tainted
//		off = heapbits.Next(p, n, end)
//	}
//
//go:noinline
func Next(p unsafe.Pointer, n, from uintptr) uintptr {
	if from >= n {
		return n
	}
	if rtNext == nil {
		return n
	}
	r := rtNext(uintptr(p), n, from, true)
	runtime.KeepAlive(p)
	return r
}

// NextClean returns the smallest off in [from, n) such that the byte at p+off
// is not tainted, or n. In all cases, from >= n returns n; without weaving (or
// on a platform that is not supported), it returns from.
//
//go:noinline
func NextClean(p unsafe.Pointer, n, from uintptr) uintptr {
	if from >= n {
		return n
	}
	if rtNext == nil {
		return from
	}
	r := rtNext(uintptr(p), n, from, false)
	runtime.KeepAlive(p)
	return r
}

// Copy makes the bits of the n bytes at dst equal to the bits of the n bytes
// at src. Without concurrent writers, the result is the same as a memmove of
// the bits: overlap (dst == src included) is correct. With concurrent writers
// to src or dst, each destination word of bits is replaced atomically, but
// there is no snapshot of the whole range.
//
// Copy returns false and changes no bit in the same cases as [Set] (for dst).
// A source that is not heap memory (or not in one heap span) counts as clean:
// then Copy removes the taint of dst.
//
//go:noinline
func Copy(dst, src unsafe.Pointer, n uintptr) bool {
	if rtCopy == nil || n == 0 {
		return false
	}
	ok := rtCopy(uintptr(dst), uintptr(src), n)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(src)
	return ok
}

// SetString taints all bytes of s. See [Set].
func SetString(s string) bool {
	return Set(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)))
}

// SetBytes taints all bytes of b. See [Set].
func SetBytes(b []byte) bool {
	return Set(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)))
}

// ClearString removes the taint of all bytes of s. See [Clear].
func ClearString(s string) {
	Clear(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)))
}

// ClearBytes removes the taint of all bytes of b. See [Clear].
func ClearBytes(b []byte) {
	Clear(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)))
}

// AnyString reports whether one byte of s is tainted. See [Any].
func AnyString(s string) bool {
	return Any(unsafe.Pointer(unsafe.StringData(s)), uintptr(len(s)))
}

// AnyBytes reports whether one byte of b is tainted. See [Any].
func AnyBytes(b []byte) bool {
	return Any(unsafe.Pointer(unsafe.SliceData(b)), uintptr(len(b)))
}

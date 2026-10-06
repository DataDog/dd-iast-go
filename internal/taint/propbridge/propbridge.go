// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package propbridge is the leaf bridge between the propagation hooks and
// the request analysis (package internal/taint/request).
//
// The hooks are in packages of the standard library (and in the runtime).
// They must not import the analysis code: it imports packages that the hooks
// change, and that makes an import cycle. Thus this package imports only
// sync/atomic and unsafe. The analysis registers its functions here in its
// init function ([Register]); before that, all the functions of this package
// do nothing.
//
// # The uintptr contract
//
// The functions take uintptr values, not Go pointers: a pointer that goes
// through a function variable escapes to the heap, and then the values that
// the application checks would move to the heap. The caller must:
//
//   - keep the memory of each address alive with a typed reference until the
//     function returns (runtime.KeepAlive);
//   - give the address of the first byte of the memory and its length in
//     bytes.
//
// The entry points are nosplit: they change the addresses to unsafe.Pointer
// values before any call that can grow the stack. When the stack moves, the
// runtime adjusts these pointers (also pointers into the stack of the
// caller), so the analysis never uses a stale address. The analysis never
// keeps a pointer to the memory of the caller after it returns: it keeps
// only copies, and uintptr locators of heap memory.
//
// # Re-entry
//
// The analysis code does not call a hooked function, but a guard makes this
// safe also when a later change does: each entry point first enters a
// per-goroutine guard (a field of the runtime goroutine, given by the woven
// runtime). When the guard is already set, the call returns at once.
// Without weaving, there are no hooks, so no re-entry is possible, and the
// entry points run without a guard.
package propbridge

import (
	"sync/atomic"
	"unsafe"
)

// Modes of [Derived].
const (
	// Coarse: the output gets, for each request, one segment over the whole
	// output with the first source of that request in the input.
	Coarse uint8 = 1
	// Positional: byte i of the output comes from byte i of the input (the
	// output and the input have the same length). A different length makes
	// the analysis use Coarse.
	Positional uint8 = 2
)

// Kinds of the rune conversion callback of the runtime.
const (
	// RunesFromString: string to []rune. The input is UTF-8 bytes; the
	// output is the memory of the runes (4 bytes for each rune).
	RunesFromString uint8 = 1
	// StringFromRunes: []rune to string. The input is the memory of the runes
	// (4 bytes for each rune); the output is UTF-8 bytes.
	StringFromRunes uint8 = 2
)

// Callbacks are the analysis functions. All lengths are in bytes. The
// pointers are valid only until the function returns. A callback must not
// panic (it recovers its own panics: the runtime and the hooks call the
// entry points without a recover) and must not block.
type Callbacks struct {
	// Derived records an output whose bytes a propagation changed (see
	// [Derived]).
	Derived func(out unsafe.Pointer, outLen uintptr, in unsafe.Pointer, inLen uintptr, mode uint8)
	// Runes records the output of a rune conversion of the runtime.
	Runes func(out unsafe.Pointer, outLen uintptr, in unsafe.Pointer, inLen uintptr, kind uint8)
	// BodyRead records the n bytes at p that a Read of body wrote.
	BodyRead func(body, p unsafe.Pointer, n uintptr)
}

var registered atomic.Pointer[Callbacks]

// Register sets the callbacks. The analysis calls it in its init function.
// A nil value removes the callbacks (tests only).
func Register(c *Callbacks) {
	registered.Store(c)
}

// rtGuard is the per-goroutine re-entry guard of the woven runtime (push
// linkname, defined by iast/runtime/orchestrion.yml). guard(true) returns
// false when the guard of the current goroutine is already set; else it
// sets it and returns true. guard(false) clears it. It is nil without
// weaving.
//
//go:linkname rtGuard __dd_iast_propbridge.guard
var rtGuard func(enter bool) bool

// s2sOff is the string-to-slice switch of the woven runtime: 0 (the default)
// = []byte(s) and []rune(s) results get the taint of s; 1 = they do not. The
// runtime reads it with an atomic load.
//
//go:linkname s2sOff __dd_iast_propbridge.s2soff
var s2sOff uint32

// SetStringToSlice turns the string-to-slice propagation of the runtime on or
// off (DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED).
func SetStringToSlice(enabled bool) {
	if enabled {
		atomic.StoreUint32(&s2sOff, 0)
	} else {
		atomic.StoreUint32(&s2sOff, 1)
	}
}

// StringToSlice reports the value that [SetStringToSlice] set (true by
// default).
func StringToSlice() bool {
	return atomic.LoadUint32(&s2sOff) == 0
}

// runeDerived is the callback of the rune conversions of the runtime. The
// value is static data (a top-level function), so it is set before any init
// function runs. The runtime reads it with a pull linkname; when this package
// is not linked, the runtime variable is nil and the runtime does not call
// it.
//
//go:linkname runeDerived __dd_iast_propbridge.runederived
var runeDerived = runeEntry

// derivedEntry is [Derived] for the propagation hooks in the standard
// library (iast/propagation/*). These hooks cannot import this package (an
// import or a link from the standard library breaks go test of a package
// with in-package tests under Orchestrion), so they read this variable with
// a pull linkname. The value is static data (a top-level function), so it is
// set before any init function runs. When this package is not linked, the
// variable of the hooks is nil and they do not call it.
//
//go:linkname derivedEntry __dd_iast_propbridge.derived
var derivedEntry = Derived

// pointer changes an address of the caller into a pointer. It reads the
// bits of u as a pointer (not a uintptr conversion, which checkptr refuses
// for an address without an original pointer). The caller guarantees that
// the memory is live (see the uintptr contract).
//
//go:nosplit
func pointer(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// runeEntry is called by the runtime only on the tainted path of the rune
// conversions, after the context check and after the bits are copied.
//
//go:nosplit
func runeEntry(out, outLen, in, inLen uintptr, kind uint8) {
	// Pointers before any call: the stack can move after this line.
	outPtr, inPtr := pointer(out), pointer(in)
	c := registered.Load()
	if c == nil || c.Runes == nil {
		return
	}
	guard := rtGuard
	if guard != nil && !guard(true) {
		return
	}
	c.Runes(outPtr, outLen, inPtr, inLen, kind)
	if guard != nil {
		guard(false)
	}
}

// Derived records the outLen bytes at out as made by a change of the inLen
// bytes at in (see [Coarse] and [Positional]). The caller already set the
// taint bits of out. It does nothing before [Register].
//
//go:nosplit
func Derived(out, outLen, in, inLen uintptr, mode uint8) {
	outPtr, inPtr := pointer(out), pointer(in)
	c := registered.Load()
	if c == nil || c.Derived == nil {
		return
	}
	guard := rtGuard
	if guard != nil && !guard(true) {
		return
	}
	c.Derived(outPtr, outLen, inPtr, inLen, mode)
	if guard != nil {
		guard(false)
	}
}

// BodyRead records that a Read of the body object at body wrote the n bytes
// at p. When body is the registered body of a request, the analysis taints
// the bytes and keeps a copy; else it does nothing. It does nothing before
// [Register].
//
//go:nosplit
func BodyRead(body, p, n uintptr) {
	bodyPtr, pPtr := pointer(body), pointer(p)
	c := registered.Load()
	if c == nil || c.BodyRead == nil || n == 0 {
		return
	}
	guard := rtGuard
	if guard != nil && !guard(true) {
		return
	}
	c.BodyRead(bodyPtr, pPtr, n)
	if guard != nil {
		guard(false)
	}
}

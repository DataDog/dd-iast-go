// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package runtimebridge is the dependency-minimal bridge that the woven Go
// runtime calls (plan runtime-operator-hooks, section 3.2).
//
// Rules for this package:
//
//   - It imports only sync/atomic and unsafe. It must not import a package that
//     the runtime hooks weave. TestDependencies checks this.
//   - The gate words are zero-initialized BSS words. Zero means "off", also
//     before any init function runs.
//   - The untainted path of a bridge function does not allocate, does not
//     concatenate, does not lock, has no defer, and does not call a func value.
//   - Every path that runs store code or a callback is a //go:noinline function
//     with defer and recover. Thus a bridge call always returns to the runtime.
//   - The runtime declares the bridge functions with //go:noescape. Thus a
//     bridge function must never keep an operand, an input, or its backing
//     array after it returns (plan section 3.8). It can keep a result only
//     through a callback that adopts it as a heap root. The runtime calls a
//     result function only when the result is not on the stack.
package runtimebridge

import (
	"sync/atomic"
	"unsafe"
)

// gate is not zero while the bound store has at least one indexed root (plan
// section 3.2 rule 3). The woven runtime reads it first, with one atomic load.
// Only the Gate handle that Bind returns changes it.
//
//go:linkname gate __dd_iast_rt.gate
var gate uint32

// s2sGate is 1 when []byte(s) and []rune(s) propagation is on (plan section
// 4.4). Bind stores it once. Zero (the BSS value) means off.
//
//go:linkname s2sGate __dd_iast_rt.s2s_gate
var s2sGate uint32

// ConfirmResult is the result of the confirm function of a binding (plan
// section 3.2.1). The store uses this type for Store.Confirm.
type ConfirmResult uint8

const (
	// ConfirmClean: no live root contains the value, or no range of the root
	// overlaps the value window.
	ConfirmClean ConfirmResult = iota
	// ConfirmTainted: a live root contains the value, and one of its ranges
	// overlaps the value window.
	ConfirmTainted
	// ConfirmUnknown: a TryRLock failed. A pre-check treats it as tainted.
	ConfirmUnknown
)

// Binding is the store part of the bridge: the interior filter and the confirm
// function of one store. Bind installs one binding for the process.
type Binding struct {
	// Filter is the interior filter of the store. It must not be nil.
	Filter *Filter
	// Confirm reports whether [p, p+n) is tainted. It must not allocate and
	// must never wait for a lock. It takes a uintptr, so it cannot keep the
	// value live.
	Confirm func(p uintptr, n uint32) ConfirmResult
}

// Options are the process settings of the bridge.
type Options struct {
	// StringToSlice turns on the []byte(s) and []rune(s) propagation (plan
	// section 4.4, DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED).
	StringToSlice bool
}

// Callbacks are the tainted-path functions. The bridge calls them only after a
// filter hit, in a function that recovers a panic. They can allocate. They
// must not keep an operand or an input after they return. They can keep the
// result only as a store root (the result is heap memory).
type Callbacks struct {
	// Concat receives the result of concatstrings and its operands.
	Concat func(result string, operands []string)
	// ConcatBytes receives the result of concatbytes and its operands.
	ConcatBytes func(result []byte, operands []string)
	// FromBytes receives the result of string(b) and its input.
	FromBytes func(result string, input []byte)
	// ToBytes receives the result of []byte(s) and its input.
	ToBytes func(result []byte, input string)
	// FromRunes receives the result of string(rs) and its input.
	FromRunes func(result string, input []rune)
	// ToRunes receives the result of []rune(s) and its input.
	ToRunes func(result []rune, input string)
}

// Gate is the handle that changes the gate word. Only the caller of a
// successful Bind gets it.
type Gate struct {
	word *uint32
}

// Add adds delta to the gate word. The store calls it at the same time as it
// changes its indexed-root counter, so the gate is zero only when the counter
// is zero.
func (g *Gate) Add(delta int32) {
	if g != nil && g.word != nil {
		atomic.AddUint32(g.word, uint32(delta))
	}
}

var (
	// binding is set once, by the process store only (plan section 3.2 rule 6).
	binding atomic.Pointer[Binding]
	// callbacks is set by the propagation package. See Register.
	callbacks atomic.Pointer[Callbacks]
)

// Bind installs b once for the process, then stores the string-to-slice
// switch word. A second call, a nil or incomplete binding, or an unsupported
// Go release returns nil and false, and changes nothing. The caller must add
// its current indexed-root count to the returned gate, and then add every
// change of that count.
func Bind(b *Binding, options Options) (*Gate, bool) {
	if !supported {
		unsupportedGo.Add(1)
		return nil, false
	}
	if b == nil || b.Filter == nil || b.Confirm == nil {
		return nil, false
	}
	copied := *b
	if !binding.CompareAndSwap(nil, &copied) {
		return nil, false
	}
	if options.StringToSlice {
		atomic.StoreUint32(&s2sGate, 1)
	}
	return &Gate{word: &gate}, true
}

// Register installs the tainted-path callbacks and returns the previous ones.
// The callbacks resolve the bound store themselves, so a registration before
// or after Bind gives the same result.
func Register(c *Callbacks) *Callbacks { return callbacks.Swap(c) }

// Bound reports whether a binding is installed.
func Bound() bool { return binding.Load() != nil }

// GateValue returns the gate word. It is for telemetry and tests.
func GateValue() uint32 { return atomic.LoadUint32(&gate) }

// StringToSliceEnabled reports whether the string-to-slice switch word is on.
func StringToSliceEnabled() bool { return atomic.LoadUint32(&s2sGate) != 0 }

// Counters is a snapshot of the bridge counters.
type Counters struct {
	// HookEntries is the number of bridge function entries. The bridge counts
	// entries only while CountEntries(true) is in effect, because a shared
	// counter on every call costs too much on a busy process.
	HookEntries uint64
	// HookPanics is the number of recovered panics in store code or callbacks.
	HookPanics uint64
	// UnsupportedGo is the number of Bind calls refused because the Go
	// release is not supported (plan section 3.10).
	UnsupportedGo uint64
}

var (
	countEntries  atomic.Bool
	hookEntries   atomic.Uint64
	hookPanic     atomic.Uint64
	unsupportedGo atomic.Uint64
)

// CountEntries turns the HookEntries counter on or off and returns the
// previous state. Tests use it.
func CountEntries(on bool) bool { return countEntries.Swap(on) }

// Snapshot returns the bridge counters.
func Snapshot() Counters {
	return Counters{HookEntries: hookEntries.Load(), HookPanics: hookPanic.Load(), UnsupportedGo: unsupportedGo.Load()}
}

func enter() {
	if countEntries.Load() {
		hookEntries.Add(1)
	}
}

func stringPointer(s string) uintptr { return uintptr(unsafe.Pointer(unsafe.StringData(s))) }

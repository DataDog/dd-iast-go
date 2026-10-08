// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package runtimebridge is the dependency-minimal bridge that the woven Go
// runtime calls. The iast/runtime aspects weave the hooked runtime functions
// (concatstrings, concatbytes, slicebytetostring, stringtoslicebyte,
// slicerunetostring and stringtoslicerune).
//
// # Runtime hook rules
//
// Other files and tests refer to these rules as "rule 1" to "rule 6".
//
//  1. Imports: this package imports only sync/atomic and unsafe. It must not
//     import a package that the runtime hooks weave. TestDependencies checks
//     this with go list -deps.
//  2. Gate words: the gate words are zero-initialized BSS words. Zero means
//     "off". This is correct also before any init function runs.
//  3. Gate value: the gate is not zero while the bound store has at least one
//     indexed root. The store increments its indexed-root counter before it
//     marks a root as indexed, and decrements it only after it clears the
//     mark and removes the index refs. Thus, while a reader sees an indexed
//     root, the gate is not zero. A byte mutation does not change the counter.
//  4. Untainted path: the untainted path of a bridge function (the filter
//     checks, and a pre-check before a filter hit) does not allocate, does not
//     concatenate, does not lock, has no defer, and does not call a func
//     value. It reads the interior filter inline.
//  5. Recover: every path that runs store code (confirm after a filter hit,
//     and the tainted-path callbacks) is a //go:noinline function with defer
//     and recover. Thus a bridge call always returns to the runtime. The
//     woven runtime sets its per-g recursion guard before each bridge call
//     that can run store code, and clears it after. When no binding is
//     installed, a bridge function returns at once.
//  6. One binding: Bind installs one binding (the filter and the confirm
//     function of one store) for the process. Only the process store binds
//     (request.defaultManager calls Store.BindRuntimeBridge). A second Bind
//     changes nothing. Thus a test store, or any other store, never changes
//     the gate and is never visible to the hooks. The propagation package
//     registers the callbacks in its init function, and the callbacks use
//     store.RuntimeStore(), the store of the binding. Link rule: the runtime
//     aspect cannot import the propagation package, so the links list of the
//     runtime declarations aspect names this package and
//     internal/taint/propagation. Orchestrion then adds a blank import of the
//     packages that the program does not import, and the init function of
//     propagation runs.
//
// Pre-check and confirm: a pre-check returns true only when a live, validated
// root contains an operand and one of the ranges of the root overlaps the
// operand window. It never returns false for a tainted operand. A filter hit
// is not a proof of taint (hash collision, or another root in the same
// granule), so after a hit the pre-check calls the confirm function of the
// binding. ConfirmUnknown (a failed TryRLock) and a recovered panic also give
// true: this costs at most one heap allocation and never loses taint.
//
// Recursion guard: store code and callbacks can concatenate or convert, and
// thus enter a hooked function again. The per-g guard makes the runtime run
// the original body directly in that case. A panic in the bridge is
// recovered (rule 5), so the runtime always clears the guard.
//
// Bypass token: the runtime wrapper sets a per-g token to 1 just before it
// calls the original function again (the inner call), so that the inner entry
// runs the original body. Token rule 3: the wrapper clears the token after
// the inner call, also when the inner entry consumed it, because the gate can
// change to zero between the outer entry and the inner entry (then the inner
// entry does not read the token). Token rule 4: when the gate changes to zero
// before the inner entry and then the original body panics, or the gate
// changes back and the body runs a hooked function, the token stays 1 for one
// more entry. That entry runs without the wrapper and clears the token. The
// result is one missed propagation: no crash, no wrong taint, no leak.
//
// Callback contract (escape and GC): the runtime declares the bridge
// functions without a body and with //go:noescape, and the compiler trusts
// this. A violation is memory corruption, not only a wrong taint.
//
//   - A bridge function or a callback must never keep an operand, an input, or
//     its backing array after it returns, and must not give one to code that
//     can keep it.
//   - It can keep a result only through a callback that adopts it as a heap
//     root. The runtime calls a result function only when the result is not on
//     the stack.
//   - Operands can be in a stack buffer, and the stack can grow and move during
//     the call. Thus code converts each operand to a uintptr key once, and
//     after that it never reads bytes through the key. A stale stack key gives
//     only a lookup miss, because no root is stack memory.
//
// Supported releases: the runtime hooks support go1.26.x and go1.27.x only.
// On go1.28 and later (unsupported.go), Bind refuses every binding and
// increments the UnsupportedGo counter. Then the gates stay zero, each hook
// costs one atomic load, and the interior lookup still works. There is no
// warning. If the woven runtime does not compile on a new release (a renamed
// runtime field, or a changed signature that the signature assertions of the
// woven runtime find), the build fails loudly.
//
// Interior index (filter.go): the store indexes each root by granule keys in
// two tiers. Tier S is for spans of 2 to 256 bytes (64-byte granules). Tier L
// is for spans of 257 bytes to 64 KiB (4 KiB granules). A root is visible only
// after all its index refs are published, and each ref increments the filter
// counter of its bucket. Thus a zero filter bucket proves that no visible root
// covers the granule. A reader checks tier S completely before it reads tier
// L. The store package doc and internal/taint/store/interior.go give the
// details.
package runtimebridge

import (
	"sync/atomic"
	"unsafe"
)

// gate is not zero while the bound store has at least one indexed root (rule
// 3). The woven runtime reads it first, with one atomic load.
// Only the Gate handle that Bind returns changes it.
//
//go:linkname gate __dd_iast_rt.gate
var gate uint32

// s2sGate is 1 when []byte(s) and []rune(s) propagation is on (the
// string-to-slice switch, DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED). Bind
// stores it once. Zero (the BSS value) means off.
//
//go:linkname s2sGate __dd_iast_rt.s2s_gate
var s2sGate uint32

// ConfirmResult is the result of the confirm function of a binding (see
// "Pre-check and confirm" in the package doc). The store uses this type for Store.Confirm.
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
	// StringToSlice turns on the []byte(s) and []rune(s) propagation
	// (DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED).
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
	// binding is set once, by the process store only (rule 6).
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
	// release is not supported (see "Supported releases" in the package doc).
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

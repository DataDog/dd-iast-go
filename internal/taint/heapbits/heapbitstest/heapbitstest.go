// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package heapbitstest gives tests access to the test knobs and counters of
// the woven runtime part of package heapbits. Production code must not use
// it.
package heapbitstest

import (
	_ "runtime" // the symbols come from the woven runtime
	"unsafe"
)

// testingEnabled turns the test knobs of the woven runtime on. The runtime
// declares the same symbol without a value; this definition (with a value)
// exists only in programs that link this package, which production programs
// never do.
//
//go:linkname testingEnabled __dd_iast_heapbits_testing.enabled
var testingEnabled = true

var (
	//go:linkname rtStats __dd_iast_heapbits.stats
	rtStats func() [15]uint64

	//go:linkname rtAllocKnobs __dd_iast_heapbits.allocknobs
	rtAllocKnobs func(fail, park, parkSlot, parkScan bool) uint32

	//go:linkname rtHookKnobs __dd_iast_heapbits.hookknobs
	rtHookKnobs func(noFreegc, noFinalizerSkip bool)

	//go:linkname rtNoSweep __dd_iast_heapbits.nosweep
	rtNoSweep func(bool)

	//go:linkname rtFreegc __dd_iast_heapbits.freegc
	rtFreegc func(unsafe.Pointer, uintptr) bool

	//go:linkname rtSweepKnobs __dd_iast_heapbits.sweepknobs
	rtSweepKnobs func(p uintptr, pause uint32, gosignal bool) (uint64, uint32)

	//go:linkname rtSpanInfo __dd_iast_heapbits.spaninfo
	rtSpanInfo func(p uintptr) (uintptr, uintptr)

	//go:linkname rtSpanFlag __dd_iast_heapbits.spanflag
	rtSpanFlag func(uintptr) int

	//go:linkname rtSweepLog __dd_iast_heapbits.sweeplog
	rtSweepLog func(*[4096]uint64) uint64

	//go:linkname rtHasDir __dd_iast_heapbits.hasdir
	rtHasDir func(uintptr) bool

	//go:linkname rtSlowPath __dd_iast_heapbits.slowpath
	rtSlowPath func(bool) uint64

	//go:linkname rtTestKnobs __dd_iast_heapbits.testknobs
	rtTestKnobs func(movestack, forceyield bool) (probe, workerProbe uint32, yields uint64)

	//go:linkname rtGateKnob __dd_iast_heapbits.gateknob
	rtGateKnob func(noSetGate bool) bool
)

// SetNoGateFromSet stops (true) or starts again (false) the store of the
// sticky gate (heapbits.Live) by Set. Copy and heapbits.MarkLive still store
// it. Only for the tests of the gate. It returns the gate value, or false
// when the runtime is not woven.
func SetNoGateFromSet(off bool) bool {
	if rtGateKnob == nil {
		return false
	}
	return rtGateKnob(off)
}

// Probe results of [Knobs].
const (
	ProbeNone     = 0 // no entry point (or worker) ran since the last call
	ProbeInStack  = 1 // the classified address was in the current stack
	ProbeOffStack = 2 // the classified address was not in the current stack
)

// Knobs sets the test knobs of the entry points. It returns the stack probe
// of the last entry point and the stack probe of the last worker (see the
// Probe constants; reading them resets them to ProbeNone), and the number of
// checkpoint yields since the start of the program.
//
// A worker must never run for a stack address: after an operation on a stack
// address, the worker probe must be ProbeNone.
//
// With movestack true, every entry point calls a function with a stack check
// before its classifier (negative control of the stack probe). With
// forceyield true, every checkpoint of a worker yields.
func Knobs(movestack, forceyield bool) (probe, workerProbe uint32, yields uint64) {
	if rtTestKnobs == nil {
		return ProbeNone, ProbeNone, 0
	}
	return rtTestKnobs(movestack, forceyield)
}

// Storage is a snapshot of the storage of the taint bits.
type Storage struct {
	Slabs       uint64 // mapped slabs (1 MiB each)
	ChunksInUse uint64 // chunks (16 KiB each) given to directories or bits
	Mapped      uint64 // mapped bytes
	Used        uint64 // mapped and reserved bytes (the budget counter)
	Budget      uint64 // budget in bytes
	Sweeps      uint64 // tainted spans processed by the sweep hook
	Drops       Drops
	Accounted   uint64 // bytes charged to the runtime memory stats
	UsedMax     uint64 // high-water mark of Used
	Recycled    uint64 // chunks given back by the sweeper
}

// Drops counts the refused operations (the taint is dropped), by reason.
type Drops struct {
	Budget, RefillBusy, Contention, Mmap, SlotBusy uint64
	Span                                           uint64 // span larger than MaxSpanBytes
}

// MaxSpanBytes is the largest heap span in which Set accepts a range.
const MaxSpanBytes = 64 << 20

// ChunksPerSlab is the number of chunks in one slab.
const ChunksPerSlab = 64

// SlabBytes is the size of one slab.
const SlabBytes = 1 << 20

// ChunkHeapBytes is the heap size that one chunk covers.
const ChunkHeapBytes = 128 << 10

// Stats returns a snapshot of the storage.
func Stats() Storage {
	if rtStats == nil {
		return Storage{}
	}
	r := rtStats()
	return Storage{
		Slabs: r[0], ChunksInUse: r[1], Mapped: r[2], Used: r[3], Budget: r[4], Sweeps: r[5],
		Drops:     Drops{Budget: r[6], RefillBusy: r[7], Contention: r[8], Mmap: r[9], SlotBusy: r[10], Span: r[13]},
		Accounted: r[11], UsedMax: r[12], Recycled: r[14],
	}
}

// Waiting goroutines reported by [AllocKnobs].
const (
	NoneParked   = 0
	RefillParked = 1 // the refill owner waits (after its budget reservation)
	SlotParked   = 2 // the owner of a claimed slot waits (before its chunk)
	ScanParked   = 3 // a goroutine waits after its scan of the free chunks
)

// AllocKnobs sets the test knobs of the allocator: with fail true, the next
// mmap calls fail; with park true, the next goroutine that maps a slab waits
// (after its budget reservation) until park is false again; with parkSlot
// true, the next goroutine that claims an empty slot waits (before it gets
// the chunk) until parkSlot is false again; with parkScan true, the first
// goroutine that finds no free chunk waits (before it tries to become the
// refill owner) until parkScan is false again (one goroutine only). It
// returns which goroutine waits.
func AllocKnobs(fail, park, parkSlot, parkScan bool) (parked uint32) {
	if rtAllocKnobs == nil {
		return NoneParked
	}
	return rtAllocKnobs(fail, park, parkSlot, parkScan)
}

// Enabled reports whether the test knobs are active in the woven runtime.
func Enabled() bool {
	return testingEnabled && rtNoSweep != nil
}

// SetNoSweep turns the sweep hook off (true) or on (false). Only for
// negative controls: with the hook off, freed memory keeps its taint.
func SetNoSweep(off bool) {
	if rtNoSweep != nil {
		rtNoSweep(off)
	}
}

// Freegc calls runtime.freegc for a pointer-free object. It returns false
// when freegc did not free the object (for example when
// GOEXPERIMENT=runtimefreegc is not set).
func Freegc(p unsafe.Pointer, size uintptr) bool {
	if rtFreegc == nil {
		return false
	}
	return rtFreegc(p, size)
}

// SetForceSlowPath makes Any use its slow path (classification, then the
// worker) also when the arena of the address has no bitmap or no metadata.
// Without it, Any returns "clean" at once for such an address. It returns
// the number of Any calls that reached the classification of the slow path
// since the start of the program.
func SetForceSlowPath(on bool) uint64 {
	if rtSlowPath == nil {
		return 0
	}
	return rtSlowPath(on)
}

// HasDirectory reports whether the heap arena of p has a taint directory.
func HasDirectory(p unsafe.Pointer) bool {
	if rtHasDir == nil {
		return false
	}
	return rtHasDir(uintptr(p))
}

// SpanFlag returns the taint flag of the heap span of p (1: the span is
// eligible for the sweep hook), or -1 when p is not heap memory or when the
// test knobs are not active.
func SpanFlag(p unsafe.Pointer) int {
	if rtSpanFlag == nil {
		return -1
	}
	return rtSpanFlag(uintptr(p))
}

// SpanInfo returns the base address and the object count of the heap span of
// p, or 0, 0.
func SpanInfo(p unsafe.Pointer) (base, nelems uintptr) {
	if rtSpanInfo == nil {
		return 0, 0
	}
	return rtSpanInfo(uintptr(p))
}

// Sweep waiting states of [SweepKnobs].
const (
	SweepNotWaiting = 0
	SweepWaiting    = 1 // the sweep of the target waits at the pause point
	SweepContinued  = 2 // it continued (go signal, or its 200 ms limit)
)

// Pause points of [SweepKnobs].
const (
	NoPause          = 0
	PauseAfterReset  = 1 // after the flag reset, before the live check
	PauseAfterChecks = 2 // after the live check (the end of the hook)
)

// SweepKnobs sets the test knobs of the sweep hook. The target is the span of
// p (nil: none; a new target resets the counters). With a pause point, the
// sweep hook of the target waits there until gosignal is true (at most
// 200 ms). It returns the number of sweep hooks of the target and the
// waiting state.
func SweepKnobs(p unsafe.Pointer, pause uint32, gosignal bool) (sweeps uint64, waiting uint32) {
	if rtSweepKnobs == nil {
		return 0, SweepNotWaiting
	}
	return rtSweepKnobs(uintptr(p), pause, gosignal)
}

// SetHookKnobs turns off (true) or on (false) the freegc hook, and the
// finalizer check of the sweep hook. Only for negative controls.
func SetHookKnobs(noFreegc, noFinalizerSkip bool) {
	if rtHookKnobs != nil {
		rtHookKnobs(noFreegc, noFinalizerSkip)
	}
}

// SweepDurations returns the number of sweep hooks since the start of the
// program, and a ring of the durations (ns) of the last 4096 of them (hook
// k is at index k%4096). Only test programs record it.
func SweepDurations() (n uint64, ring [4096]uint64) {
	if rtSweepLog == nil {
		return 0, ring
	}
	n = rtSweepLog(&ring)
	return n, ring
}

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
	rtStats func() (bitmaps, sweeps uint64)

	//go:linkname rtNoSweep __dd_iast_heapbits.nosweep
	rtNoSweep func(bool)

	//go:linkname rtFreegc __dd_iast_heapbits.freegc
	rtFreegc func(unsafe.Pointer, uintptr) bool

	//go:linkname rtSlowPath __dd_iast_heapbits.slowpath
	rtSlowPath func(bool) uint64

	//go:linkname rtTestKnobs __dd_iast_heapbits.testknobs
	rtTestKnobs func(movestack, forceyield bool) (probe, workerProbe uint32, yields uint64)
)

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

// Stats returns the number of bitmaps that the runtime allocated and the
// number of tainted spans that the sweep hook processed.
func Stats() (bitmaps, sweeps uint64) {
	if rtStats == nil {
		return 0, 0
	}
	return rtStats()
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

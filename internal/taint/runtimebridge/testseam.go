// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtimebridge

import "sync/atomic"

// This file has the test seams of the bridge. Only tests call the functions
// that end in "ForTest". The woven tests of iast/runtime use them to replace
// the binding or the callbacks for one test. The linker removes them from a
// program that does not call them.

// Registered reports whether all 6 tainted-path callbacks are registered. The
// link fixture of iast/runtime uses it to check that the propagation package
// is in the program also when the program does not import it.
func Registered() bool {
	c := callbacks.Load()
	return c != nil && c.Concat != nil && c.ConcatBytes != nil && c.FromBytes != nil &&
		c.ToBytes != nil && c.FromRunes != nil && c.ToRunes != nil
}

// CurrentForTest returns the installed binding and callbacks. A test can wrap
// them and install the wrappers with ReplaceForTest.
func CurrentForTest() (*Binding, *Callbacks) { return binding.Load(), callbacks.Load() }

// ReplaceForTest installs b, the switch word and c for one test, and returns a
// function that restores the previous state.
func ReplaceForTest(b *Binding, s2s bool, c *Callbacks) (restore func()) {
	previousBinding := binding.Swap(b)
	var word uint32
	if s2s {
		word = 1
	}
	previousS2S := atomic.SwapUint32(&s2sGate, word)
	previousCallbacks := callbacks.Swap(c)
	return func() {
		binding.Store(previousBinding)
		atomic.StoreUint32(&s2sGate, previousS2S)
		callbacks.Store(previousCallbacks)
	}
}

// SwapGateForTest stores value in the gate word and returns the previous
// value. The bypass-token tests use it to change the gate between the outer
// entry and the inner entry of a hooked function. The test must store the
// previous value again, because the store adds its changes to the word.
func SwapGateForTest(value uint32) uint32 { return atomic.SwapUint32(&gate, value) }

// MarkForTest sets the filter buckets of p.
func MarkForTest(f *Filter, p uintptr) { f[bucketS(p)].Add(1) }

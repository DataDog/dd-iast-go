// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtimebridge

import "sync/atomic"

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

// MarkForTest sets the filter buckets of p.
func MarkForTest(f *Filter, p uintptr) { f[bucketS(p)].Add(1) }

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package writerbridge is the dependency-minimal bytes.Buffer invalidation
// bridge imported into the bytes standard-library package.
package writerbridge

import "sync/atomic"

const expectationSlots = 128

type callback struct{ invalidate func(uintptr) }

var registered atomic.Pointer[callback]
var activeCounter atomic.Pointer[atomic.Int32]
var expected [expectationSlots]atomic.Uintptr

// Register installs the numeric writer invalidation callback.
func Register(invalidate func(uintptr)) {
	if invalidate != nil {
		registered.Store(&callback{invalidate: invalidate})
	}
}

// BindActiveCounter installs the process request store's writer-state counter.
func BindActiveCounter(counter *atomic.Int32) {
	activeCounter.Store(counter)
}

// Active reports whether any writer state can require invalidation.
func Active() bool {
	counter := activeCounter.Load()
	return counter != nil && counter.Load() > 0
}

// Expect marks one direct wrapped mutation. False means no state needs a marker
// or the bounded marker table was contended or full.
func Expect(pointer uintptr) bool {
	if pointer == 0 || !Active() {
		return false
	}
	start := int((pointer >> 3) % expectationSlots)
	for probe := 0; probe < 4; probe++ {
		slot := &expected[(start+probe)%expectationSlots]
		if slot.CompareAndSwap(0, pointer) {
			return true
		}
	}
	return false
}

// Cancel removes an unused direct-mutation marker after return or panic.
func Cancel(pointer uintptr, marked bool) {
	if marked {
		consume(pointer)
	}
}

// Invalidate is called before one bytes.Buffer mutation.
func Invalidate(pointer uintptr) {
	if pointer == 0 || !Active() {
		return
	}
	invalidateSlow(pointer)
}

//go:noinline
func invalidateSlow(pointer uintptr) {
	if consume(pointer) {
		return
	}
	callback := registered.Load()
	if callback != nil {
		callback.invalidate(pointer)
	}
}

func consume(pointer uintptr) bool {
	start := int((pointer >> 3) % expectationSlots)
	for probe := 0; probe < 4; probe++ {
		slot := &expected[(start+probe)%expectationSlots]
		if slot.CompareAndSwap(pointer, 0) {
			return true
		}
	}
	return false
}

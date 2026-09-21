// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package writerbridge is the dependency-minimal bytes.Buffer invalidation
// bridge imported into the bytes standard-library package.
package writerbridge

import "sync/atomic"

const expectationSlots = 128

// Mutation classifies backing writes, receiver-only changes, and exposures.
type Mutation uint8

const (
	BackingWrite Mutation = iota
	HeaderOnly
	Exposure
)

type callback struct {
	invalidate func(uintptr, uintptr, uintptr, bool)
}

var registered atomic.Pointer[callback]
var activeStates atomic.Int32
var expected [expectationSlots]atomic.Uintptr

// Register installs the numeric writer invalidation callback.
func Register(invalidate func(pointer, backing, capacity uintptr, preserve bool)) {
	if invalidate != nil {
		registered.Store(&callback{invalidate: invalidate})
	}
}

// ActiveCounter returns the process writer-state fast gate. The request store
// is the sole writer after initialization.
func ActiveCounter() *atomic.Int32 {
	return &activeStates
}

// Active reports whether any writer state can require invalidation.
func Active() bool {
	return activeStates.Load() > 0
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

// Invalidate receives only scalar native backing metadata from bytes.Buffer.
// Expected writes still invalidate peers; only internal observations and
// precise wrapped header changes suppress the callback altogether.
func Invalidate(pointer, backing, capacity uintptr, mutation Mutation) {
	if pointer == 0 || !Active() {
		return
	}
	invalidateSlow(pointer, backing, capacity, mutation)
}

//go:noinline
func invalidateSlow(pointer, backing, capacity uintptr, mutation Mutation) {
	expected := consume(pointer)
	if expected && mutation != BackingWrite {
		return
	}
	if mutation == HeaderOnly {
		backing, capacity = 0, 0
	}
	callback := registered.Load()
	if callback != nil {
		callback.invalidate(pointer, backing, capacity, expected)
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

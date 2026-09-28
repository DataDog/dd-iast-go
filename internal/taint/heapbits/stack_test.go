// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// probeLocal calls one entry point on a buffer of the stack of the current
// goroutine and returns the stack probe of the entry point. The buffer must
// not escape: the calls are direct (a call through a function value would
// move it to the heap).
//
//go:noinline
func probeLocal(movestack bool, op string) uint32 {
	var local [64]byte
	heapbitstest.Knobs(movestack, false)
	switch op {
	case "Set":
		heapbits.SetBytes(local[:])
	case "Clear":
		heapbits.ClearBytes(local[:])
	case "Any":
		heapbits.AnyBytes(local[:])
	}
	probe, _, _ := heapbitstest.Knobs(false, false)
	return probe
}

// longLocal calls one entry point on a stack buffer that is longer than the
// fast path of Any (16 bitmap words), and returns the worker probe. A worker
// must never run for a stack address.
//
//go:noinline
func longLocal(op string) uint32 {
	var local [4096]byte
	heapbitstest.Knobs(false, false)
	switch op {
	case "Set":
		heapbits.SetBytes(local[:])
	case "Clear":
		heapbits.ClearBytes(local[:])
	case "Any":
		heapbits.AnyBytes(local[:])
	}
	_, worker, _ := heapbitstest.Knobs(false, false)
	return worker
}

// The classifier must refuse a long stack range before any worker runs (a
// worker has a stack check, so the stack could move in it).
func TestNoWorkerForStackAddress(t *testing.T) {
	need(t)
	// Without a bitmap in the arena of the stack, Any returns at once, before
	// the classification. The knob sends it to the slow path in all cases.
	defer heapbitstest.SetForceSlowPath(false)
	for _, name := range stackOps {
		before := heapbitstest.SetForceSlowPath(true)
		if probe := longLocal(name); probe != heapbitstest.ProbeNone {
			t.Errorf("%s: a worker ran for a stack address (worker probe = %d)", name, probe)
		}
		// Any must have reached its classification (else the test proves
		// nothing about the order).
		if after := heapbitstest.SetForceSlowPath(true); name == "Any" && after == before {
			t.Error("Any: the slow path did not reach the classification")
		}
	}
	// Positive control: for a long heap range, the workers run.
	b := heapBytes(4096)
	for _, name := range stackOps {
		heapbitstest.Knobs(false, false)
		switch name {
		case "Set":
			heapbits.SetBytes(b)
		case "Clear":
			heapbits.ClearBytes(b)
		case "Any":
			heapbits.AnyBytes(b)
		}
		if _, worker, _ := heapbitstest.Knobs(false, false); worker != heapbitstest.ProbeOffStack {
			t.Errorf("%s: the worker did not run for a long heap range (worker probe = %d)", name, worker)
		}
	}
}

var stackOps = []string{"Set", "Clear", "Any"}

// moveMode reports whether the test binary was built with
// -gcflags=all=-d=maymorestack=runtime.mayMoreStackMove. The negative control
// (a call with a stack check before the classifier) then always moves the
// stack, and the probe sees an address that is no longer in the stack.
func moveMode(t *testing.T) bool {
	t.Helper()
	switch probe := probeLocal(true, "Any"); probe {
	case heapbitstest.ProbeOffStack:
		return true
	case heapbitstest.ProbeInStack:
		return false
	default:
		t.Fatalf("stack probe did not run (probe = %d)", probe)
		return false
	}
}

// The entry points must classify a stack address before the stack can move.
// The test proves it only in a build with
// -gcflags=all=-d=maymorestack=runtime.mayMoreStackMove, where the stack
// moves at every function entry that has a stack check.
func TestStackAddressClassifiedBeforeStackMove(t *testing.T) {
	need(t)
	if !heapbitstest.Enabled() {
		t.Fatal("test knobs are not enabled")
	}
	moving := moveMode(t)
	for _, name := range stackOps {
		if probe := probeLocal(false, name); probe != heapbitstest.ProbeInStack {
			t.Errorf("%s: the stack moved before the classifier (probe = %d)", name, probe)
		}
	}
	if !moving {
		t.Log("the stack does not move at each call in this build: the result proves little; " +
			"run with -gcflags=all=-d=maymorestack=runtime.mayMoreStackMove")
	}
}

// Negative control: with a call that has a stack check before the classifier,
// the probe must see the move (only in the maymorestack build).
func TestStackProbeNegativeControl(t *testing.T) {
	need(t)
	if !moveMode(t) {
		t.Skip("needs -gcflags=all=-d=maymorestack=runtime.mayMoreStackMove")
	}
	for _, name := range stackOps {
		if probe := probeLocal(true, name); probe != heapbitstest.ProbeOffStack {
			t.Errorf("%s: the probe did not see the stack move (probe = %d)", name, probe)
		}
	}
}

// The workers must reach their checkpoints: every 512 words at least.
func TestWorkerCheckpoints(t *testing.T) {
	need(t)
	const size = 1 << 20 // 16384 bitmap words
	b := heapBytes(size)
	// Make the chunks of b exist, with no bit set.
	if !heapbits.SetBytes(b) {
		t.Fatal("Set failed")
	}
	heapbits.ClearBytes(b)

	_, _, before := heapbitstest.Knobs(false, true)
	defer heapbitstest.Knobs(false, false)
	step := func(name string, op func()) {
		t.Helper()
		_, _, start := heapbitstest.Knobs(false, true)
		op()
		_, _, end := heapbitstest.Knobs(false, true)
		// 16384 words / 512 = 32 checkpoints; allow the edges.
		if got := end - start; got < 30 {
			t.Errorf("%s: %d checkpoint yields, want at least 30", name, got)
		}
	}
	step("Any", func() {
		if heapbits.AnyBytes(b) {
			t.Error("b is clean")
		}
	})
	step("Set", func() { heapbits.SetBytes(b) })
	step("Clear", func() { heapbits.ClearBytes(b) })
	_, _, after := heapbitstest.Knobs(false, false)
	if after <= before {
		t.Error("no yield at all")
	}
}

// The fast path of Any reads at most 16 bitmap words; a range of 17 words
// goes to the worker. The worker probe shows which path ran.
func TestAnyFastPathBoundary(t *testing.T) {
	need(t)
	b := heapBytes(8192) // a size class of 8192 bytes: aligned to 8192
	// Without a bitmap in the arena, Any returns at once: make it exist.
	if !heapbits.SetBytes(b) {
		t.Fatal("Set failed")
	}
	heapbits.ClearBytes(b)
	cases := []struct {
		off, n int
		worker bool
	}{
		{0, 16 * 64, false},    // words 0..15
		{0, 16*64 + 1, true},   // words 0..16
		{1, 16*64 - 1, false},  // words 0..15
		{1, 16 * 64, true},     // words 0..16
		{63, 15*64 + 1, false}, // words 0..15
		{63, 15*64 + 2, true},  // words 0..16
	}
	for _, c := range cases {
		heapbitstest.Knobs(false, false)
		heapbits.AnyBytes(b[c.off : c.off+c.n])
		_, worker, _ := heapbitstest.Knobs(false, false)
		if got := worker != heapbitstest.ProbeNone; got != c.worker {
			t.Errorf("off=%d n=%d: worker ran = %v, want %v", c.off, c.n, got, c.worker)
		}
	}
}

// Any has a nosplit fast path for short ranges (up to 16 bitmap words) and a
// worker for longer ranges. Both must give the same result for all lengths
// and for a taint at the start, in the middle and at the end.
func TestAnyFastPathAndWorker(t *testing.T) {
	need(t)
	b := heapBytes(8192)
	for _, off := range []int{0, 1, 63, 64, 65} {
		for n := 1; n+off <= 2200; n += 7 {
			r := b[off : off+n]
			for _, k := range []int{0, n / 2, n - 1} {
				heapbits.ClearBytes(b)
				heapbits.SetBytes(r[k : k+1])
				if !heapbits.AnyBytes(r) {
					t.Fatalf("off=%d n=%d taint at %d: not found", off, n, k)
				}
				if k > 0 && heapbits.AnyBytes(r[:k]) {
					t.Fatalf("off=%d n=%d taint at %d: found before it", off, n, k)
				}
				if k < n-1 && heapbits.AnyBytes(r[k+1:]) {
					t.Fatalf("off=%d n=%d taint at %d: found after it", off, n, k)
				}
			}
		}
	}
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package writerbridge_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/stretchr/testify/require"
)

func TestExpectedMutationSkipsOneInvalidation(t *testing.T) {
	calls := 0
	writerbridge.Register(func(uintptr, uintptr, uintptr, bool) { calls++ })
	writerbridge.ActiveCounter().Store(1)
	t.Cleanup(func() { writerbridge.ActiveCounter().Store(0) })
	const pointer = uintptr(0x1000)
	marked := writerbridge.Expect(pointer)
	if !marked {
		t.Fatal("expectation was not admitted")
	}
	writerbridge.Invalidate(pointer, 0, 0, writerbridge.Exposure)
	writerbridge.Cancel(pointer, marked)
	if calls != 0 {
		t.Fatalf("expected mutation invalidated state %d times", calls)
	}
	writerbridge.Invalidate(pointer, 0, 0, writerbridge.Exposure)
	if calls != 1 {
		t.Fatalf("indirect mutation callback count = %d, want 1", calls)
	}
}

func TestCancelRemovesUnusedExpectation(t *testing.T) {
	calls := 0
	writerbridge.Register(func(uintptr, uintptr, uintptr, bool) { calls++ })
	writerbridge.ActiveCounter().Store(1)
	t.Cleanup(func() { writerbridge.ActiveCounter().Store(0) })
	const pointer = uintptr(0x2000)
	marked := writerbridge.Expect(pointer)
	writerbridge.Cancel(pointer, marked)
	writerbridge.Invalidate(pointer, 0, 0, writerbridge.Exposure)
	if calls != 1 {
		t.Fatalf("callback count = %d, want 1", calls)
	}
}

func TestMutationClassesAndExpectedPeerInvalidation(t *testing.T) {
	for _, mutation := range []writerbridge.Mutation{writerbridge.BackingWrite, writerbridge.HeaderOnly, writerbridge.Exposure} {
		for _, expected := range []bool{false, true} {
			calls := 0
			writerbridge.Register(func(pointer, backing, capacity uintptr, preserve bool) {
				calls++
				require.Equal(t, uintptr(0x1000), pointer)
				require.Equal(t, expected, preserve)
				if mutation == writerbridge.HeaderOnly {
					require.Zero(t, backing)
					require.Zero(t, capacity)
				} else {
					require.Equal(t, uintptr(0x2000), backing)
					require.Equal(t, uintptr(1<<20), capacity)
				}
			})
			writerbridge.ActiveCounter().Store(1)
			t.Cleanup(func() { writerbridge.ActiveCounter().Store(0) })
			if expected {
				require.True(t, writerbridge.Expect(0x1000))
			}
			writerbridge.Invalidate(0x1000, 0x2000, 1<<20, mutation)
			if expected && mutation != writerbridge.BackingWrite {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		}
	}
}

func TestNestedMutationAndCancellation(t *testing.T) {
	writerbridge.ActiveCounter().Store(1)
	t.Cleanup(func() { writerbridge.ActiveCounter().Store(0) })
	var preserved []bool
	writerbridge.Register(func(_, _, _ uintptr, preserve bool) { preserved = append(preserved, preserve) })
	const pointer = uintptr(0x3000)
	outer, nested := writerbridge.Expect(pointer), writerbridge.Expect(pointer)
	require.True(t, outer)
	require.True(t, nested)
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.BackingWrite) // WriteRune
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.BackingWrite) // WriteByte
	writerbridge.Cancel(pointer, nested)
	writerbridge.Cancel(pointer, outer)
	require.Equal(t, []bool{true, true}, preserved)

	// Truncate(0) and exhausted-buffer growth delegate to Reset after the
	// outer marker was consumed. Header-only Reset cannot invalidate peers.
	outer = writerbridge.Expect(pointer)
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.HeaderOnly)
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.HeaderOnly)
	writerbridge.Cancel(pointer, outer)
	require.Equal(t, []bool{true, true, false}, preserved)
	outer = writerbridge.Expect(pointer)
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.BackingWrite)
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.HeaderOnly)
	writerbridge.Cancel(pointer, outer)
	require.Equal(t, []bool{true, true, false, true, false}, preserved)

	// A panic before consuming the nested marker must not suppress a later
	// unrelated exposure or mutation.
	outer, nested = writerbridge.Expect(pointer), writerbridge.Expect(pointer)
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.BackingWrite)
	writerbridge.Cancel(pointer, nested)
	writerbridge.Cancel(pointer, outer)
	writerbridge.Invalidate(pointer, 0x4000, 64, writerbridge.Exposure)
	require.Equal(t, []bool{true, true, false, true, false, true, false}, preserved)
}

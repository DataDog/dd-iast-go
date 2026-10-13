// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/stretchr/testify/require"
)

// propagationCounts is the change of the propagation counters.
type propagationCounts struct {
	executed, coarsened, dropped uint64
}

// requirePropagation runs f and checks the change of the propagation
// counters.
func requirePropagation(t *testing.T, want propagationCounts, f func()) {
	t.Helper()
	executed := telemetry.ExecutedPropagation.Load()
	coarsened := telemetry.CoarsenedPropagation.Load()
	dropped := telemetry.DroppedPropagation.Load()
	f()
	got := propagationCounts{
		executed:  telemetry.ExecutedPropagation.Load() - executed,
		coarsened: telemetry.CoarsenedPropagation.Load() - coarsened,
		dropped:   telemetry.DroppedPropagation.Load() - dropped,
	}
	require.Equal(t, want, got)
}

// TestPropagationTelemetry checks the counters of the propagation
// callbacks: an added entry is executed, an entry of the coarse rule is also
// coarsened, and a refused entry or a busy owner is dropped.
//
// The test holds the slot lock as a different goroutine does:
// +checklocksignore
func TestPropagationTelemetry(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	a := newAnalysis(t, m)
	input := taintBytes(t, a, "q", "ab")
	output := func(text string) []byte {
		out := heapBytes(text)
		f.set(uintptr(unsafeData(out)), uintptr(len(out)))
		return out
	}

	t.Run("positional", func(t *testing.T) {
		out := output("ab")
		requirePropagation(t, propagationCounts{executed: 1}, func() {
			m.derived(unsafeData(out), 2, unsafeData(input), 2, propbridge.Positional)
		})
	})
	t.Run("coarse", func(t *testing.T) {
		out := output("<ab>")
		requirePropagation(t, propagationCounts{executed: 1, coarsened: 1}, func() {
			m.derived(unsafeData(out), 4, unsafeData(input), 2, propbridge.Coarse)
		})
	})
	t.Run("positional with other length is coarse", func(t *testing.T) {
		out := output("abab")
		requirePropagation(t, propagationCounts{executed: 1, coarsened: 1}, func() {
			m.derived(unsafeData(out), 4, unsafeData(input), 2, propbridge.Positional)
		})
	})
	t.Run("weak input", func(t *testing.T) {
		weak := taintRuns(f, "a", "t")
		out := output("<a>")
		requirePropagation(t, propagationCounts{}, func() {
			m.derived(unsafeData(out), 3, unsafeData(weak), 1, propbridge.Coarse)
		})
	})
	t.Run("busy", func(t *testing.T) {
		out := output("[ab]")
		a.slot.mu.Lock()
		requirePropagation(t, propagationCounts{dropped: 1}, func() {
			m.derived(unsafeData(out), 4, unsafeData(input), 2, propbridge.Coarse)
		})
		a.slot.mu.Unlock()
	})
	t.Run("runes", func(t *testing.T) {
		runes := []rune(string(input))
		f.set(uintptr(unsafe.Pointer(&runes[0])), 8)
		requirePropagation(t, propagationCounts{executed: 1}, func() {
			m.runes(unsafe.Pointer(&runes[0]), 8, unsafeData(input), 2, propbridge.RunesFromString)
		})
		// A wrong output length makes the rune rule use the coarse rule.
		short := output("abc")
		requirePropagation(t, propagationCounts{executed: 1, coarsened: 1}, func() {
			m.runes(unsafeData(short), 3, unsafeData(input), 2, propbridge.RunesFromString)
		})
	})
	t.Run("table full", func(t *testing.T) {
		var free int
		m.use(a.slot, a.generation, a.id, func(d *ownerData) { free = MaxDerived - d.nderived })
		for i := range free {
			out := output(fmt.Sprintf("<%03d>", i))
			m.derived(unsafeData(out), uintptr(len(out)), unsafeData(input), 2, propbridge.Coarse)
		}
		out := output("~~~~~")
		requirePropagation(t, propagationCounts{dropped: 1}, func() {
			m.derived(unsafeData(out), 5, unsafeData(input), 2, propbridge.Coarse)
		})
	})
}

// TestPropagationTelemetryBudget: the memory budget of the owner refuses the
// entry.
func TestPropagationTelemetryBudget(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	a := newAnalysis(t, m)
	input := taintBytes(t, a, "q", "ab")
	m.use(a.slot, a.generation, a.id, func(d *ownerData) { d.budget = 0 })
	out := heapBytes("<ab>")
	f.set(uintptr(unsafeData(out)), 4)
	requirePropagation(t, propagationCounts{dropped: 1}, func() {
		m.derived(unsafeData(out), 4, unsafeData(input), 2, propbridge.Coarse)
	})
}

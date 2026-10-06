// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/stretchr/testify/require"
)

// useProcessManager makes m the process manager for the test (IsTainted*
// and Visit* use it).
func useProcessManager(t *testing.T, m *Manager) {
	t.Helper()
	previous := processManager.Swap(m)
	t.Cleanup(func() { processManager.Store(previous) })
}

// requireStrong checks the result of the attribution of value for a, and
// that IsTaintedBytes and VisitBytesOwner give the same result (parity).
func requireStrong(t *testing.T, a Analysis, value []byte, strong bool, segments string) {
	t.Helper()
	var r Attribution
	require.Equal(t, strong, a.AttributeBytes(value, &r), "AttributeBytes")
	require.Equal(t, strong, r.Strong(), "Strong")
	require.Equal(t, segments, describe(&r))
	require.Equal(t, strong, IsTaintedBytes(value), "IsTaintedBytes")
	require.Equal(t, strong, IsTaintedString(unsafe.String(unsafe.SliceData(value), len(value))), "IsTaintedString")
	owner, ok := a.Owner()
	require.True(t, ok)
	visited := 0
	require.Equal(t, strong, VisitBytesOwner(value, owner, func(ResolvedRange) bool {
		visited++
		return true
	}), "VisitBytesOwner")
	require.Equal(t, strong, visited > 0)
	var any Attribution
	require.Equal(t, strong, a.manager.AttributeBytesAny(value, Owner{}, &any), "AttributeBytesAny")
}

// TestStrongForeignOneByteCopy: a foreign tainted '-' in a query, and the
// owner has a source with '-': the 1-byte content match is weak, thus no
// report.
func TestStrongForeignOneByteCopy(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	useProcessManager(t, m)
	a := newAnalysis(t, m)
	taintBytes(t, a, "q", "val-ue")
	foreign := taintRuns(f, "-", "t")
	query := f.concat(heapBytes("SELECT "), foreign, heapBytes(" x"))
	requireStrong(t, a, query, false, "7-8=q:val-ue")
}

// TestStrongFullCopy: a copy of the source "1 OR 1=1" is reported.
func TestStrongFullCopy(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	useProcessManager(t, m)
	a := newAnalysis(t, m)
	value := taintBytes(t, a, "q", "1 OR 1=1")
	query := f.concat(heapBytes("WHERE id="), value)
	requireStrong(t, a, query, true, "9-17=q:1 OR 1=1")
}

// TestStrongThreeByteCopy: a 3-byte content match of a longer source is
// weak; a full copy of a 3-byte source is strong (min(4, 3) = 3).
func TestStrongThreeByteCopy(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	useProcessManager(t, m)
	a := newAnalysis(t, m)
	long := taintBytes(t, a, "long", "attacker")
	part := f.concat(heapBytes("x="), long[1:4])
	requireStrong(t, a, part, false, "2-5=long:attacker")
	// A 4-byte content match of the longer source is strong.
	part = f.concat(heapBytes("x="), long[1:5])
	requireStrong(t, a, part, true, "2-6=long:attacker")

	short := taintBytes(t, a, "short", "abc")
	full := f.concat(heapBytes("x="), short)
	requireStrong(t, a, full, true, "2-5=short:abc")
}

// TestStrongOneByteAddressMatch: an address match is strong, also for 1
// byte.
func TestStrongOneByteAddressMatch(t *testing.T) {
	useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	useProcessManager(t, m)
	a := newAnalysis(t, m)
	value := taintBytes(t, a, "q", "attacker")
	requireStrong(t, a, value[3:4], true, "0-1=q:attacker")
}

// TestStrongWeakSegmentInReport: a weak segment keeps its source in a value
// that a strong segment makes tainted.
func TestStrongWeakSegmentInReport(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	useProcessManager(t, m)
	a := newAnalysis(t, m)
	value := taintBytes(t, a, "q", "1 OR 1=1")
	other := taintBytes(t, a, "p", "a-b")
	query := f.concat(value, heapBytes(" "), other[1:2])
	requireStrong(t, a, query, true, "0-8=q:1 OR 1=1 9-10=p:a-b")
	var r Attribution
	require.True(t, a.AttributeBytes(query, &r))
	require.True(t, r.Segments[0].Strong, "an 8-byte content match")
	require.False(t, r.Segments[1].Strong, "a 1-byte content match of a 3-byte source")

	// The window itself: an address match, strong.
	requireStrong(t, a, other[1:2], true, "0-1=p:a-b")
}

// TestStrongDerived: derived entries count as sources for the rule; an
// input with weak segments only makes no derived entry.
func TestStrongDerived(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	useProcessManager(t, m)
	a := newAnalysis(t, m)
	source := taintBytes(t, a, "q", "o'brien")
	quoted := heapBytes(`"o\'brien"`)
	f.set(uintptr(unsafeData(quoted)), uintptr(len(quoted)))
	m.derived(unsafeData(quoted), uintptr(len(quoted)), unsafeData(source), uintptr(len(source)), propbridge.Coarse)
	requireStrong(t, a, quoted, true, `0-10=q:o'brien`)
	// A content match of 4 bytes of the derived copy is strong.
	copied := f.concat(heapBytes("x="), quoted[2:6])
	requireStrong(t, a, copied, true, `2-6=q:o'brien`)
	// "\\" is only in the derived copy: a 1-byte content match is weak.
	copied = f.concat(heapBytes("x="), quoted[2:3])
	requireStrong(t, a, copied, false, `2-3=q:o'brien`)

	// A weak input makes no entry.
	weak := taintRuns(f, "o", "t")
	out := heapBytes("<o>")
	f.set(uintptr(unsafeData(out)), uintptr(len(out)))
	m.derived(unsafeData(out), uintptr(len(out)), unsafeData(weak), uintptr(len(weak)), propbridge.Coarse)
	m.use(a.slot, a.generation, a.id, func(d *ownerData) {
		require.Equal(t, 1, d.nderived)
	})
}

// TestDroppedSourceTelemetry: each source drop of an active analysis
// increments telemetry.DroppedSource; an inactive analysis does not.
//
// The test holds the slot lock as a different goroutine does:
// +checklocksignore
func TestDroppedSourceTelemetry(t *testing.T) {
	f := useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	requireDrop := func(t *testing.T, want uint64, f func()) {
		t.Helper()
		before := telemetry.DroppedSource.Load()
		f()
		require.Equal(t, want, telemetry.DroppedSource.Load()-before)
	}

	t.Run("admission", func(t *testing.T) {
		requireDrop(t, 1, func() { _, _ = a.TaintString(param, "q", heapString("x")) })
		requireDrop(t, 1, func() { _, _ = a.TaintString(param, strings.Repeat("n", MaxNameBytes+1), heapString("value")) })
		requireDrop(t, 1, func() { _, _ = a.TaintString(0, "q", heapString("value")) })
	})
	t.Run("set failure without clone", func(t *testing.T) {
		value := heapString("refused")
		addr := uintptr(unsafe.Pointer(unsafe.StringData(value)))
		f.refuse = func(p, _ uintptr) bool { return p == addr }
		t.Cleanup(func() { f.refuse = nil })
		requireDrop(t, 1, func() { require.False(t, a.TaintStringInPlace(param, "q", value)) })
		requireDrop(t, 0, func() {
			_, ok := a.TaintString(param, "q", value)
			require.True(t, ok, "a clone")
		})
		f.refuse = nil
	})
	t.Run("busy", func(t *testing.T) {
		a.slot.mu.Lock()
		requireDrop(t, 1, func() { _, _ = a.TaintString(param, "q", heapString("busy-value")) })
		a.slot.mu.Unlock()
	})
	t.Run("budget", func(t *testing.T) {
		b := newAnalysis(t, m)
		m.use(b.slot, b.generation, b.id, func(d *ownerData) { d.budget = 3 })
		requireDrop(t, 1, func() { _, _ = b.TaintString(param, "q", heapString("value")) })
	})
	t.Run("body", func(t *testing.T) {
		b := newAnalysis(t, m)
		body := new([64]byte)
		require.True(t, b.RegisterBody(unsafe.Pointer(body)))
		chunk := heapBytes("first")
		requireDrop(t, 0, func() { m.bodyRead(unsafe.Pointer(body), unsafeData(chunk), uintptr(len(chunk))) })
		b.slot.mu.Lock()
		chunk = heapBytes("busy")
		requireDrop(t, 1, func() { m.bodyRead(unsafe.Pointer(body), unsafeData(chunk), uintptr(len(chunk))) })
		b.slot.mu.Unlock()
		chunk = heapBytes("stack")
		addr := uintptr(unsafeData(chunk))
		f.refuse = func(p, _ uintptr) bool { return p == addr }
		requireDrop(t, 1, func() { m.bodyRead(unsafe.Pointer(body), unsafeData(chunk), uintptr(len(chunk))) })
		f.refuse = nil
	})
	t.Run("inactive", func(t *testing.T) {
		b, ok := m.Acquire(MaxAnalyses)
		require.True(t, ok)
		b.Finish()
		requireDrop(t, 0, func() { _, _ = b.TaintString(param, "q", heapString("x")) })
		requireDrop(t, 0, func() { _, _ = b.TaintString(param, "q", heapString("value")) })
		requireDrop(t, 0, func() { _, _ = Analysis{}.TaintString(param, "q", heapString("value")) })
	})
}

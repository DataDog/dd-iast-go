// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestZeroOwnerAccessorsAndDrops(t *testing.T) {
	var owner Owner
	require.True(t, owner.Disabled())
	require.Zero(t, owner.ID())
	require.Zero(t, owner.Generation())
	index, valid := owner.Index()
	require.Zero(t, index)
	require.False(t, valid)
	require.Zero(t, owner.Charged())
	require.Zero(t, owner.Values())
	require.Equal(t, Counters{}, owner.Counters())
	owner.RecordBytesDrop()
	owner.Finish()
}

func TestOverflowReleaseDefensiveBounds(t *testing.T) {
	store := New()
	initial := store.overflowN
	store.freeOverflow(0)
	require.Equal(t, initial, store.overflowN)
	index := store.allocateOverflow()
	require.NotZero(t, index)
	require.Equal(t, initial-1, store.overflowN)
	store.overflow[index-1].ranges[0].Length = 7
	store.freeOverflow(index)
	require.Equal(t, initial, store.overflowN)
	require.Zero(t, store.overflow[index-1].ranges[0].Length)
	store.freeOverflowLocked(0)
	store.freeOverflowLocked(index)
	require.Equal(t, initial, store.overflowN)
}

func TestOverflowExhaustionAndRecovery(t *testing.T) {
	store := New()
	allocated := make([]uint16, 0, OverflowBlocks)
	for range OverflowBlocks {
		allocated = append(allocated, store.allocateOverflow())
	}
	require.Zero(t, store.allocateOverflow())
	for _, index := range allocated {
		store.freeOverflow(index)
	}
	require.Equal(t, uint16(OverflowBlocks), store.overflowN)
}

func TestByteRootDefensiveBoundaries(t *testing.T) {
	store := New()
	owner := store.Acquire()
	_, _, ok := owner.TaintBytes(nil, 1)
	require.False(t, ok)
	_, _, ok = owner.TaintBytes([]byte{'x'}, 1)
	require.False(t, ok)
	_, _, _, _, ok = owner.TaintSourceBytes(make([]byte, MaxRootBytes+1), "", 1)
	require.False(t, ok)
	_, _, _, ok = owner.AdoptSourceBytes([]byte{'x'}, "", 1)
	require.False(t, ok)
	owner.RecordBytesDrop()
	require.NotZero(t, owner.Counters().Bytes)
	owner.Finish()
	_, _, ok = owner.TaintBytes([]byte("late"), 1)
	require.False(t, ok)
	_, _, _, _, ok = owner.TaintSourceBytes([]byte("late"), "", 1)
	require.False(t, ok)
	_, _, _, ok = owner.AdoptSourceBytes([]byte("late"), "", 1)
	require.False(t, ok)
}

func TestRootAPIDefensiveBoundaries(t *testing.T) {
	taintStore := New()
	owner := taintStore.Acquire()
	t.Cleanup(func() { owner.Finish() })
	oversizedString := strings.Repeat("x", MaxRootBytes+1)
	oversizedBytes := make([]byte, MaxRootBytes+1)
	oversizedCapacity := make([]byte, 2, MaxRootBytes+1)

	_, _, _, ok := owner.TaintSourceString("x", "name", 1)
	require.False(t, ok)
	_, _, _, ok = owner.TaintSourceString(oversizedString, "name", 1)
	require.False(t, ok)
	_, _, _, ok = owner.TaintSourceString("value", oversizedString, 1)
	require.False(t, ok)

	_, _, ok = owner.TaintBytes(oversizedCapacity, 1)
	require.False(t, ok)
	_, _, _, _, ok = owner.TaintSourceBytes([]byte("x"), "name", 1)
	require.False(t, ok)
	_, _, _, _, ok = owner.TaintSourceBytes(oversizedCapacity, "name", 1)
	require.False(t, ok)
	_, _, _, _, ok = owner.TaintSourceBytes([]byte("value"), oversizedString, 1)
	require.False(t, ok)

	_, _, _, ok = owner.AdoptSourceBytes(oversizedBytes, "name", 1)
	require.False(t, ok)
	_, _, _, ok = owner.AdoptSourceBytes(oversizedCapacity, "name", 1)
	require.False(t, ok)
	_, _, _, ok = owner.AdoptSourceBytes([]byte("value"), oversizedString, 1)
	require.False(t, ok)

	var valid ranges.Set
	require.True(t, ranges.AdoptCanonical(&valid, ranges.DefaultLimit, []ranges.Range{{Length: 2}}, 2).Valid)
	_, ok = owner.AdoptString("", &valid)
	require.False(t, ok)
	_, ok = owner.AdoptString("x", &valid)
	require.False(t, ok)
	_, ok = owner.AdoptString(oversizedString, &valid)
	require.False(t, ok)
	_, ok = owner.AdoptString("xx", nil)
	require.False(t, ok)
	_, ok = owner.AdoptBytes(nil, &valid)
	require.False(t, ok)
	_, ok = owner.AdoptBytes([]byte("x"), &valid)
	require.False(t, ok)
	_, ok = owner.AdoptBytes(oversizedCapacity, &valid)
	require.False(t, ok)
	_, ok = owner.AdoptBytes([]byte("xx"), nil)
	require.False(t, ok)

	_, ok = owner.reserveRootSlot(0)
	require.False(t, ok)
	_, ok = owner.reserveRootSlot(MaxRootChargeBytes + 1)
	require.False(t, ok)
	owner.owner.rootsMu.Lock()
	_, _, ok = owner.TaintString("contended", 1)
	owner.owner.rootsMu.Unlock()
	require.False(t, ok)

	counters := owner.Counters()
	require.Equal(t, uint64(10), counters.Bytes)
	require.Equal(t, uint64(2), counters.OneByte)
	require.Equal(t, uint64(2), counters.Ranges)
	require.Equal(t, uint64(1), counters.Contention)
}

func TestRootValueReleaseAndWriterIdentityDefenses(t *testing.T) {
	var root rootRecord
	root.valueQuota.Store(uint64(7)<<32 | 2)
	releaseRootValue(&root, 6)
	require.Equal(t, uint64(7)<<32|2, root.valueQuota.Load())
	releaseRootValue(&root, 7)
	require.Equal(t, uint64(7)<<32|1, root.valueQuota.Load())
	releaseRootValue(&root, 7)
	releaseRootValue(&root, 7)
	require.Equal(t, uint64(7)<<32, root.valueQuota.Load())
	_, _, ok := (WriterRef{}).Identity()
	require.False(t, ok)
	store := New()
	owner := store.Acquire()
	ref := WriterRef{store: store, generation: owner.gen, index: owner.index}
	index, generation, ok := ref.Identity()
	require.True(t, ok)
	require.Equal(t, owner.index, index)
	require.Equal(t, owner.gen, generation)
	owner.Finish()
	_, _, ok = ref.Identity()
	require.False(t, ok)
}

func TestOperatorValueMirror(t *testing.T) {
	store := New()
	var active atomic.Int32
	store.BindOperatorActive(&active)
	owner := store.Acquire()
	_, _, ok := owner.TaintString("mirrored", 1)
	require.True(t, ok)
	require.Equal(t, int32(1), active.Load())
	owner.Finish()
	require.Zero(t, active.Load())
}

func TestProcessCounterAccessors(t *testing.T) {
	store := New()
	require.Zero(t, store.ProcessCharged())
	require.Zero(t, store.ProcessValues())
	require.Zero(t, store.AcquireDrops())
	require.Same(t, &store.values, store.ActiveValues())
	owner := store.Acquire()
	managed, _, ok := owner.TaintString("managed-value", 1)
	require.True(t, ok)
	key, ok := StringKey(managed)
	require.True(t, ok)
	require.True(t, store.MayContain(key))
	require.False(t, store.MayContain(Key{}))
	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	_, ok = snapshot.At(-1)
	require.False(t, ok)
	_, ok = snapshot.At(snapshot.Len())
	require.False(t, ok)
	owner.Finish()
	store.Lookup(key, &snapshot)
	require.Zero(t, snapshot.Len())
}

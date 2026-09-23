// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestWriterLifecycleContentionInvalidatesSkippedState(t *testing.T) {
	store := New()
	var active atomic.Int32
	store.BindWriterActive(&active)
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	object := &writerObject{id: 101}
	view := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1})
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, WriterView{}, view, &input, 4, 4))
	require.Equal(t, int32(1), active.Load())
	owner.owner.lifecycleMu.Lock()
	adopted := owner.AdoptBufferWriter(object, view)
	owner.owner.lifecycleMu.Unlock()
	require.False(t, adopted)
	require.True(t, owner.owner.writerDirty.Load())
	owner.owner.writersMu.Lock()
	var snapshot ranges.Set
	found := owner.SnapshotWriter(object, WriterStringBuilder, view, &snapshot)
	owner.owner.writersMu.Unlock()
	require.False(t, found)
	require.Equal(t, int32(1), active.Load())
	require.False(t, owner.SnapshotWriter(object, WriterStringBuilder, view, &snapshot))
	require.Zero(t, active.Load())
	require.Zero(t, owner.Charged())
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, WriterView{}, view, &input, 4, 4))
	owner.owner.lifecycleMu.Lock()
	var refs [1]WriterRef
	count := LookupWriterValue(store, object, WriterStringBuilder, WriterView{}, refs[:])
	owner.owner.lifecycleMu.Unlock()
	require.Zero(t, count)
	require.True(t, owner.owner.writerDirty.Load())
	require.False(t, owner.SnapshotWriter(object, WriterStringBuilder, view, &snapshot))
	require.Zero(t, active.Load())
}

func TestWriterInputValidationAndViewReplacement(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	object := &writerObject{id: 102}
	first := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	input := writerInput(t, 4, ranges.Range{Start: 1, Length: 2, SourceID: 3})
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, WriterView{}, first, &input, 4, 4))
	replacement := WriterView{Pointer: 0x2000, Length: 6, Capacity: 16}
	newInput := writerInput(t, 2, ranges.Range{Length: 2, SourceID: 4})
	stale := WriterView{Pointer: 0x9999, Length: 4, Capacity: 8}
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, stale, replacement, &newInput, 2, 2))
	require.Equal(t, int64(16), owner.Charged())
	var snapshot ranges.Set
	require.True(t, owner.SnapshotWriter(object, WriterStringBuilder, replacement, &snapshot))
	var got [1]ranges.Range
	require.Equal(t, 1, snapshot.CopyTo(got[:]))
	require.Equal(t, ranges.Range{Start: 4, Length: 2, SourceID: 4}, got[0])
	invalidInput := writerInput(t, 5, ranges.Range{Length: 5, SourceID: 5})
	after := WriterView{Pointer: replacement.Pointer, Length: 8, Capacity: 16}
	require.False(t, owner.UpdateWriter(object, WriterStringBuilder, replacement, after, &invalidInput, 2, 2))
	require.Zero(t, owner.Charged())
	require.False(t, owner.SnapshotWriter(object, WriterStringBuilder, replacement, &snapshot))
	require.Zero(t, LookupWriterValue(nil, object, WriterStringBuilder, WriterView{}, make([]WriterRef, 1)))
	require.Zero(t, LookupWriterValue(store, object, WriterInvalid, WriterView{}, make([]WriterRef, 1)))
	require.Zero(t, LookupWriterValue(store, object, WriterStringBuilder, WriterView{}, nil))
}

func TestWriterTruncationOutcomesAndChargeRelease(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	object := &writerObject{id: 103}
	input := writerInput(t, 8, ranges.Range{Start: 2, Length: 4, SourceID: 6})
	full := WriterView{Pointer: 0x3000, Length: 8, Capacity: 32}
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, full, &input, 8, 8))
	shrunk := WriterView{Pointer: full.Pointer, Length: 4, Capacity: 32}
	require.True(t, owner.TruncateWriter(object, WriterBytesBuffer, full, shrunk))
	require.Equal(t, int64(32), owner.Charged())
	var snapshot ranges.Set
	require.True(t, owner.SnapshotWriter(object, WriterBytesBuffer, shrunk, &snapshot))
	var got [1]ranges.Range
	require.Equal(t, 1, snapshot.CopyTo(got[:]))
	require.Equal(t, ranges.Range{Start: 2, Length: 2, SourceID: 6}, got[0])
	empty := WriterView{Length: 0, Capacity: 32}
	require.True(t, owner.TruncateWriter(object, WriterBytesBuffer, shrunk, empty))
	require.Zero(t, owner.Charged())
	require.False(t, store.HasWriterStates())
	require.True(t, owner.TruncateWriter(object, WriterBytesBuffer, WriterView{}, WriterView{}))
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, full, &input, 8, 8))
	bad := WriterView{Pointer: full.Pointer, Length: 9, Capacity: 32}
	require.False(t, owner.TruncateWriter(object, WriterBytesBuffer, full, bad))
	require.Zero(t, owner.Charged())
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, full, &input, 8, 8))
	wrongBefore := WriterView{Pointer: 0x4000, Length: 8, Capacity: 32}
	require.False(t, owner.TruncateWriter(object, WriterBytesBuffer, wrongBefore, shrunk))
	require.Zero(t, owner.Charged())
	t.Cleanup(func() { forceWriterLockFail.Store(false) })
	forceWriterLockFail.Store(true)
	require.False(t, owner.ResetWriter(object, WriterBytesBuffer))
	forceWriterLockFail.Store(false)
	require.True(t, owner.ResetWriter(object, WriterBytesBuffer))
}

func TestWriterGrowthRespectsOwnerAndProcessQuotas(t *testing.T) {
	t.Run("owner", func(t *testing.T) {
		store := New()
		owner := store.Acquire()
		t.Cleanup(owner.Finish)
		fillOwnerRootQuota(t, owner)
		input := writerInput(t, 2, ranges.Range{Length: 2, SourceID: 1})
		view := WriterView{Pointer: 0x5000, Length: 2, Capacity: 8}
		require.False(t, owner.UpdateWriter(&writerObject{id: 104}, WriterStringBuilder, WriterView{}, view, &input, 2, 2))
		require.False(t, store.HasWriterStates())
		require.Equal(t, int64(RequestRootBytes), owner.Charged())
	})
	t.Run("process", func(t *testing.T) {
		store := New()
		owners := make([]*Owner, ProcessRootBytes/RequestRootBytes)
		for index := range owners {
			owners[index] = store.Acquire()
			t.Cleanup(owners[index].Finish)
			fillOwnerRootQuota(t, owners[index])
		}
		owner := store.Acquire()
		t.Cleanup(owner.Finish)
		input := writerInput(t, 2, ranges.Range{Length: 2, SourceID: 1})
		view := WriterView{Pointer: 0x6000, Length: 2, Capacity: 8}
		require.False(t, owner.UpdateWriter(&writerObject{id: 105}, WriterStringBuilder, WriterView{}, view, &input, 2, 2))
		require.Zero(t, owner.Charged())
		require.Equal(t, int64(ProcessRootBytes), store.ProcessCharged())
	})
}

func TestWriterStaleOwnerAndReadLockContention(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	object := &writerObject{id: 107}
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1})
	view := WriterView{Pointer: 0x7000, Length: 4, Capacity: 8}
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, WriterView{}, view, &input, 4, 4))

	owner.owner.writersMu.Lock()
	var snapshot ranges.Set
	found := owner.SnapshotWriter(object, WriterStringBuilder, view, &snapshot)
	owner.owner.writersMu.Unlock()
	require.False(t, found)
	require.False(t, owner.owner.writerDirty.Load(), "a skipped observation does not dirty mutation state")

	t.Cleanup(func() { forceWriterLockFail.Store(false) })
	forceWriterLockFail.Store(true)
	require.False(t, owner.TruncateWriter(object, WriterStringBuilder, view, WriterView{Pointer: view.Pointer, Length: 2, Capacity: 8}))
	forceWriterLockFail.Store(false)
	require.True(t, owner.owner.writerDirty.Load())
	require.False(t, owner.SnapshotWriter(object, WriterStringBuilder, view, &snapshot))
	owner.Finish()

	require.False(t, owner.AdoptBufferWriter(object, view))
	require.False(t, owner.UpdateWriter(object, WriterStringBuilder, WriterView{}, view, &input, 4, 4))
	require.False(t, owner.SnapshotWriter(object, WriterStringBuilder, view, &snapshot))
	require.False(t, owner.ResetWriter(object, WriterStringBuilder))
	require.False(t, owner.TruncateWriter(object, WriterStringBuilder, view, WriterView{}))
}

func TestWriterNoStateAndNilStoreOperations(t *testing.T) {
	var store *Store
	store.BindWriterActive(new(atomic.Int32))
	store.InvalidateBuffer(1, 0, 0, false)
	require.False(t, store.HasWriterStates())
	live := New()
	owner := live.Acquire()
	t.Cleanup(owner.Finish)
	object := &writerObject{id: 106}
	require.True(t, owner.ResetWriter(object, WriterStringBuilder))
	require.True(t, owner.TruncateWriter(object, WriterStringBuilder, WriterView{}, WriterView{}))
}

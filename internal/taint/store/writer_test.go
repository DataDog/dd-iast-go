// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

type writerObject struct{ id int }

func writerInput(t *testing.T, length uint32, values ...ranges.Range) ranges.Set {
	t.Helper()
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, values, length).Valid)
	return set
}

func TestWriterUpdateSnapshotAndMismatchInvalidation(t *testing.T) {
	s := New()
	owner := s.Acquire()
	object := &writerObject{id: 1}
	input := writerInput(t, 4, ranges.Range{Start: 1, Length: 2, SourceID: 3})
	before := WriterView{}
	after := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, before, after, &input, 4, 4))
	require.True(t, s.HasWriterStates())
	require.Equal(t, int64(8), owner.Charged())

	var refs [MaxSnapshotOwners]WriterRef
	require.Equal(t, 1, LookupWriterValue(s, object, WriterStringBuilder, refs[:]))
	handle, ok := refs[0].Handle()
	require.True(t, ok)
	var snapshot ranges.Set
	require.True(t, handle.SnapshotWriter(object, WriterStringBuilder, after, &snapshot))
	var got [2]ranges.Range
	require.Equal(t, 1, snapshot.CopyTo(got[:]))
	require.Equal(t, ranges.Range{Start: 1, Length: 2, SourceID: 3}, got[0])

	// An untainted write advances the logical length without changing ranges.
	advanced := WriterView{Pointer: 0x1000, Length: 6, Capacity: 8}
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, after, advanced, nil, 2, 2))
	require.True(t, owner.SnapshotWriter(object, WriterStringBuilder, advanced, &snapshot))
	require.Equal(t, 1, snapshot.CopyTo(got[:]))
	require.Equal(t, ranges.Range{Start: 1, Length: 2, SourceID: 3}, got[0])

	// A stale pre-view clears state and releases its charge.
	mismatch := WriterView{Pointer: 0x2000, Length: 8, Capacity: 8}
	require.False(t, owner.UpdateWriter(object, WriterStringBuilder, after, mismatch, nil, 2, 2))
	require.Zero(t, LookupWriterValue(s, object, WriterStringBuilder, refs[:]))
	require.Zero(t, owner.Charged())
	owner.Finish()
	require.False(t, s.HasWriterStates())
}

func TestWriterGrowthTruncateResetAndPointerInvalidation(t *testing.T) {
	s := New()
	owner := s.Acquire()
	object := &writerObject{id: 2}
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1})
	first := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, first, &input, 4, 4))
	grown := WriterView{Pointer: 0x3000, Length: 8, Capacity: 16}
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, first, grown, nil, 4, 4))
	require.Equal(t, int64(16), owner.Charged())

	truncated := WriterView{Pointer: 0x3000, Length: 2, Capacity: 16}
	require.True(t, owner.TruncateWriter(object, WriterBytesBuffer, grown, truncated))
	var snapshot ranges.Set
	require.True(t, owner.SnapshotWriter(object, WriterBytesBuffer, truncated, &snapshot))
	var got [1]ranges.Range
	require.Equal(t, 1, snapshot.CopyTo(got[:]))
	require.Equal(t, ranges.Range{Length: 2, SourceID: 1}, got[0])

	pointer, ok := dynamicPointer(object)
	require.True(t, ok)
	s.InvalidateWriterPointer(pointer)
	var refs [MaxSnapshotOwners]WriterRef
	require.Zero(t, LookupWriterValue(s, object, WriterBytesBuffer, refs[:]))
	require.Zero(t, owner.Charged())

	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, first, &input, 4, 4))
	require.True(t, owner.ResetWriter(object, WriterBytesBuffer))
	require.Zero(t, owner.Charged())
	owner.Finish()
	require.Zero(t, s.ProcessCharged())
}

func TestWriterLimitDirtyDropAndTwoOwners(t *testing.T) {
	s := New()
	firstOwner := s.Acquire()
	secondOwner := s.Acquire()
	input := writerInput(t, 2, ranges.Range{Length: 2, SourceID: 0})
	objects := make([]*writerObject, MaxWriters+1)
	for index := 0; index < MaxWriters; index++ {
		objects[index] = &writerObject{id: index}
		view := WriterView{Pointer: uintptr(0x1000 + index*16), Length: 2, Capacity: 8}
		require.True(t, firstOwner.UpdateWriter(objects[index], WriterStringBuilder, WriterView{}, view, &input, 2, 2))
	}
	objects[MaxWriters] = &writerObject{id: MaxWriters}
	overflowView := WriterView{Pointer: 0x9000, Length: 2, Capacity: 8}
	require.False(t, firstOwner.UpdateWriter(objects[MaxWriters], WriterStringBuilder, WriterView{}, overflowView, &input, 2, 2))

	shared := objects[0]
	view := WriterView{Pointer: 0x1000, Length: 2, Capacity: 8}
	require.True(t, secondOwner.UpdateWriter(shared, WriterStringBuilder, WriterView{}, view, &input, 2, 2))
	var refs [MaxSnapshotOwners]WriterRef
	require.Equal(t, 2, LookupWriterValue(s, shared, WriterStringBuilder, refs[:]))

	forceWriterLockFail.Store(true)
	missed := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	require.False(t, firstOwner.UpdateWriter(shared, WriterStringBuilder, view, missed, nil, 2, 2))
	forceWriterLockFail.Store(false)
	// The next mutation clears every dirty state before it can be resumed.
	after := WriterView{Pointer: 0x1000, Length: 6, Capacity: 8}
	require.True(t, firstOwner.UpdateWriter(shared, WriterStringBuilder, missed, after, nil, 2, 2))
	require.Equal(t, 1, LookupWriterValue(s, shared, WriterStringBuilder, refs[:]))

	firstOwner.Finish()
	secondOwner.Finish()
	require.Zero(t, s.ProcessCharged())
}

func TestWriterRejectsInvalidObjectsAndOversizedGrowth(t *testing.T) {
	s := New()
	owner := s.Acquire()
	type zero struct{}
	input := writerInput(t, 2, ranges.Range{Length: 2, SourceID: 0})
	view := WriterView{Pointer: 0x1000, Length: 2, Capacity: 8}
	require.False(t, owner.UpdateWriter(zero{}, WriterStringBuilder, WriterView{}, view, &input, 2, 2))
	require.False(t, owner.UpdateWriter(&zero{}, WriterStringBuilder, WriterView{}, view, &input, 2, 2))

	object := &writerObject{id: 4}
	require.True(t, owner.UpdateWriter(object, WriterStringBuilder, WriterView{}, view, &input, 2, 2))
	oversized := WriterView{Pointer: 0x2000, Length: 4, Capacity: MaxRootBytes + 1}
	require.False(t, owner.UpdateWriter(object, WriterStringBuilder, view, oversized, nil, 2, 2))
	var refs [MaxSnapshotOwners]WriterRef
	require.Zero(t, LookupWriterValue(s, object, WriterStringBuilder, refs[:]))
	require.Zero(t, owner.Charged())
	owner.Finish()
}

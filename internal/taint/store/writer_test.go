// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"context"
	"testing"
	"time"
	"unsafe"

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
	require.Equal(t, 1, LookupWriterValue(s, object, WriterStringBuilder, WriterView{}, refs[:]))
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
	require.Zero(t, LookupWriterValue(s, object, WriterStringBuilder, WriterView{}, refs[:]))
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
	require.Zero(t, LookupWriterValue(s, object, WriterBytesBuffer, WriterView{}, refs[:]))
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
	require.Equal(t, 2, LookupWriterValue(s, shared, WriterStringBuilder, WriterView{}, refs[:]))

	forceWriterLockFail.Store(true)
	missed := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	require.False(t, firstOwner.UpdateWriter(shared, WriterStringBuilder, view, missed, nil, 2, 2))
	forceWriterLockFail.Store(false)
	// The next mutation clears every dirty state before it can be resumed.
	after := WriterView{Pointer: 0x1000, Length: 6, Capacity: 8}
	require.True(t, firstOwner.UpdateWriter(shared, WriterStringBuilder, missed, after, nil, 2, 2))
	require.Equal(t, 1, LookupWriterValue(s, shared, WriterStringBuilder, WriterView{}, refs[:]))

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
	require.Zero(t, LookupWriterValue(s, object, WriterStringBuilder, WriterView{}, refs[:]))
	require.Zero(t, owner.Charged())
	owner.Finish()
}

func anchoredWriterView(backing []byte, offset, length int) WriterView {
	return WriterView{
		Pointer: uintptr(unsafe.Pointer(&backing[offset])), Length: uint32(length), Capacity: uint32(cap(backing)),
		Backing: uintptr(unsafe.Pointer(unsafe.SliceData(backing))), Anchor: &backing[offset],
	}
}

func TestBufferWriterExactAdoptionAndCharges(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	backing, independent := make([]byte, 16), make([]byte, 16)
	view := anchoredWriterView(backing, 3, 4)
	donor, copied := &writerObject{id: 1}, &writerObject{id: 2}
	want := ranges.Range{Start: 1, Length: 2, SourceID: 3, Marks: 8}
	input := writerInput(t, 4, want)
	require.True(t, owner.UpdateWriter(donor, WriterBytesBuffer, WriterView{}, view, &input, 4, 4))
	charge := owner.Charged()
	var snapshot ranges.Set
	var refs [MaxSnapshotOwners]WriterRef
	require.Equal(t, 1, LookupWriterValue(s, copied, WriterBytesBuffer, view, refs[:]))
	require.True(t, owner.SnapshotWriter(copied, WriterBytesBuffer, view, &snapshot))
	var got [1]ranges.Range
	require.Equal(t, 1, snapshot.CopyTo(got[:]))
	require.Equal(t, want, got[0])
	require.Equal(t, charge, owner.Charged())
	require.Equal(t, uint8(1), owner.owner.writerCount)

	for _, mismatch := range []WriterView{
		anchoredWriterView(backing, 4, 4), anchoredWriterView(backing, 3, 3),
		anchoredWriterView(backing[:8:8], 3, 4), anchoredWriterView(independent, 3, 4),
		{Pointer: view.Pointer, Length: view.Length, Capacity: view.Capacity},
	} {
		require.False(t, owner.SnapshotWriter(copied, WriterBytesBuffer, mismatch, &snapshot))
		require.False(t, owner.AdoptBufferWriter(copied, mismatch))
	}
	require.False(t, owner.SnapshotWriter(copied, WriterStringBuilder, view, &snapshot))

	// A receiver assigned different backing must lose its obsolete entry before
	// adopting the donor; there is still only one canonical record afterwards.
	otherView := anchoredWriterView(independent, 3, 4)
	require.True(t, owner.UpdateWriter(copied, WriterBytesBuffer, WriterView{}, otherView, &input, 4, 4))
	require.Equal(t, charge*2, owner.Charged())
	version := owner.owner.writerVersion.Load()
	require.True(t, owner.AdoptBufferWriter(copied, view))
	require.Greater(t, owner.owner.writerVersion.Load(), version)
	require.Equal(t, charge, owner.Charged())
	require.Equal(t, uint8(1), owner.owner.writerCount)
	require.Same(t, copied, owner.owner.writers[0].object)
	require.Same(t, view.Anchor, owner.owner.writers[0].view.Anchor)
	require.True(t, owner.SnapshotWriter(copied, WriterBytesBuffer, view, &snapshot))
	require.Equal(t, 1, snapshot.CopyTo(got[:]))
	require.Equal(t, want, got[0])
}

func TestBufferWriterOverlapAndExpectedPeerInvalidation(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	backing, unrelated := make([]byte, 64), make([]byte, 32)
	views := []WriterView{anchoredWriterView(backing[:32:32], 0, 4), anchoredWriterView(backing[4:36:36], 0, 4), anchoredWriterView(unrelated, 0, 4)}
	objects := []*writerObject{{id: 1}, {id: 2}, {id: 3}}
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 2, Marks: 4})
	for index := range objects {
		require.True(t, owner.UpdateWriter(objects[index], WriterBytesBuffer, WriterView{}, views[index], &input, 4, 4))
	}
	pointer, ok := dynamicPointer(objects[0])
	require.True(t, ok)
	s.InvalidateBuffer(pointer, views[0].Backing, uintptr(views[0].Capacity), true)
	var snapshot ranges.Set
	require.True(t, owner.SnapshotWriter(objects[0], WriterBytesBuffer, views[0], &snapshot))
	require.False(t, owner.SnapshotWriter(objects[1], WriterBytesBuffer, views[1], &snapshot))
	require.True(t, owner.SnapshotWriter(objects[2], WriterBytesBuffer, views[2], &snapshot))
	require.Equal(t, int64(64), owner.Charged())
	// A header-only operation does not invalidate a peer sharing the backing.
	otherPointer, ok := dynamicPointer(objects[1])
	require.True(t, ok)
	s.InvalidateBuffer(otherPointer, 0, 0, false)
	require.True(t, owner.SnapshotWriter(objects[0], WriterBytesBuffer, views[0], &snapshot))
}

func TestBufferWriterNativeIntervalBeyondTrackingLimit(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	backing := make([]byte, MaxRootBytes+32)
	view := anchoredWriterView(backing[MaxRootBytes:MaxRootBytes+16:MaxRootBytes+16], 0, 4)
	object, alias := &writerObject{id: 1}, &writerObject{id: 2}
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1})
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, view, &input, 4, 4))
	pointer, ok := dynamicPointer(alias)
	require.True(t, ok)
	s.InvalidateBuffer(pointer, uintptr(unsafe.Pointer(unsafe.SliceData(backing))), uintptr(cap(backing)), false)
	var snapshot ranges.Set
	require.False(t, owner.SnapshotWriter(object, WriterBytesBuffer, view, &snapshot))
	require.Zero(t, owner.Charged())
}

func TestBufferWriterIndexRefreshAndOwnerReuse(t *testing.T) {
	s := New()
	owner := s.Acquire()
	object, copied := &writerObject{id: 1}, &writerObject{id: 2}
	first := anchoredWriterView(make([]byte, 16), 0, 4)
	grown := anchoredWriterView(make([]byte, 32), 0, 4)
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1, Marks: 2})
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, first, &input, 4, 4))
	var refs [MaxSnapshotOwners]WriterRef
	require.Equal(t, 1, LookupWriterValue(s, object, WriterBytesBuffer, first, refs[:]))
	oldRef := refs[0]
	version := owner.owner.writerVersion.Load()
	require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, first, grown, nil, 0, 0))
	require.Equal(t, version+2, owner.owner.writerVersion.Load())
	pointer, ok := dynamicPointer(copied)
	require.True(t, ok)
	require.False(t, writerPresent(owner.owner, pointer, first.Backing, uintptr(first.Capacity), false))
	require.True(t, writerPresent(owner.owner, pointer, grown.Backing, uintptr(grown.Capacity), false))
	s.InvalidateBuffer(pointer, first.Backing, uintptr(first.Capacity), false)
	var snapshot ranges.Set
	require.True(t, owner.SnapshotWriter(object, WriterBytesBuffer, grown, &snapshot))
	require.Same(t, grown.Anchor, owner.owner.writers[0].view.Anchor)
	truncated := grown
	truncated.Length = 2
	require.True(t, owner.TruncateWriter(object, WriterBytesBuffer, grown, truncated))
	require.Equal(t, version+4, owner.owner.writerVersion.Load())
	require.True(t, owner.AdoptBufferWriter(copied, truncated))
	require.Equal(t, pointer, owner.owner.writerPointers[0].Load())
	require.Equal(t, grown.Backing, owner.owner.writerStarts[0].Load())
	require.Equal(t, grown.Backing+32, owner.owner.writerEnds[0].Load())
	owner.Finish()
	require.Zero(t, s.ProcessCharged())
	require.False(t, s.HasWriterStates())
	for index := range owner.owner.writers {
		require.Nil(t, owner.owner.writers[index].view.Anchor)
		require.Nil(t, owner.owner.writers[index].object)
		require.Zero(t, owner.owner.writerPointers[index].Load())
		require.Zero(t, owner.owner.writerStarts[index].Load())
		require.Zero(t, owner.owner.writerEnds[index].Load())
	}
	reused := s.Acquire()
	t.Cleanup(reused.Finish)
	require.Same(t, owner.owner, reused.owner)
	require.NotEqual(t, owner.Generation(), reused.Generation())
	_, ok = oldRef.Handle()
	require.False(t, ok)
	require.False(t, reused.SnapshotWriter(copied, WriterBytesBuffer, truncated, &snapshot))
	require.True(t, reused.UpdateWriter(object, WriterBytesBuffer, WriterView{}, first, &input, 4, 4))
	owner.Finish() // Old-generation finish cannot remove the new anchor or charge.
	require.Equal(t, int64(16), reused.Charged())
	require.True(t, reused.SnapshotWriter(copied, WriterBytesBuffer, first, &snapshot))
}

func TestBufferWriterContentionDoesNotResumeStaleAliases(t *testing.T) {
	for _, mode := range []string{"invalidate", "lookup", "adopt", "lifecycle", "version-changing", "unrelated"} {
		t.Run(mode, func(t *testing.T) {
			s := New()
			owner := s.Acquire()
			t.Cleanup(owner.Finish)
			object, copied := &writerObject{id: 1}, &writerObject{id: 2}
			view := anchoredWriterView(make([]byte, 16), 0, 4)
			unrelated := anchoredWriterView(make([]byte, 16), 0, 4)
			input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1})
			require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, view, &input, 4, 4))
			locked, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			go func() {
				defer close(done)
				if mode == "lifecycle" {
					owner.owner.lifecycleMu.Lock()
					defer owner.owner.lifecycleMu.Unlock()
				} else {
					owner.owner.writersMu.Lock()
					defer owner.owner.writersMu.Unlock()
				}
				if mode == "version-changing" {
					owner.owner.writerVersion.Add(1)
					defer owner.owner.writerVersion.Add(1)
				}
				close(locked)
				select {
				case <-release:
				case <-ctx.Done():
				}
			}()
			select {
			case <-locked:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			pointer, ok := dynamicPointer(copied)
			require.True(t, ok)
			switch mode {
			case "lookup":
				var refs [MaxSnapshotOwners]WriterRef
				require.Zero(t, LookupWriterValue(s, copied, WriterBytesBuffer, view, refs[:]))
			case "adopt":
				require.False(t, owner.AdoptBufferWriter(copied, view))
			case "unrelated", "version-changing":
				s.InvalidateBuffer(pointer, unrelated.Backing, uintptr(unrelated.Capacity), false)
			default:
				s.InvalidateBuffer(pointer, view.Backing, uintptr(view.Capacity), false)
			}
			require.Equal(t, mode != "unrelated", owner.owner.writerDirty.Load())
			close(release)
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var snapshot ranges.Set
			require.Equal(t, mode == "unrelated", owner.SnapshotWriter(copied, WriterBytesBuffer, view, &snapshot))
			if mode != "unrelated" {
				require.Zero(t, owner.Charged())
				require.False(t, owner.AdoptBufferWriter(copied, view))
				require.False(t, s.HasWriterStates())
			}
		})
	}
}

func TestBufferWriterFixedMetadataBounds(t *testing.T) {
	require.Equal(t, 64, MaxOwners)
	require.Equal(t, 8, MaxWriters)
	t.Logf("WriterView=%d writerRecord=%d owner=%d Store=%d added fixed metadata=%d bytes", unsafe.Sizeof(WriterView{}), unsafe.Sizeof(writerRecord{}), unsafe.Sizeof(owner{}), unsafe.Sizeof(Store{}), 4*unsafe.Sizeof(uintptr(0))*MaxOwners*MaxWriters)
}

func TestBufferWriterBoundedEntriesAndRetainedCharges(t *testing.T) {
	s := New()
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1})
	owners := make([]*Owner, MaxOwners)
	for index := range owners {
		owner := s.Acquire()
		require.False(t, owner.Disabled())
		owners[index] = owner
		t.Cleanup(owner.Finish)
		for writerIndex := range MaxWriters {
			// The interior view charges only its accessible capacity. Its anchor
			// intentionally retains the whole larger allocation, not a clone.
			backing := make([]byte, 128)
			view := anchoredWriterView(backing[32:48:48], 0, 4)
			object := &writerObject{id: writerIndex}
			require.True(t, owner.UpdateWriter(object, WriterBytesBuffer, WriterView{}, view, &input, 4, 4))
			copied := &writerObject{id: writerIndex + 100}
			require.True(t, owner.AdoptBufferWriter(copied, view))
			require.Equal(t, int64((writerIndex+1)*16), owner.Charged())
		}
		view := anchoredWriterView(make([]byte, 16), 0, 4)
		require.False(t, owner.UpdateWriter(&writerObject{id: 99}, WriterBytesBuffer, WriterView{}, view, &input, 4, 4))
		require.Equal(t, uint8(MaxWriters), owner.owner.writerCount)
	}
	require.True(t, s.Acquire().Disabled())
	require.Equal(t, int32(MaxOwners*MaxWriters), s.writerStates.Load())
	require.Equal(t, int64(MaxOwners*MaxWriters*16), s.ProcessCharged())
	for _, owner := range owners {
		owner.Finish()
	}
	require.Zero(t, s.ProcessCharged())
	require.Zero(t, s.writerStates.Load())
}

func TestBufferWriterFanoutCannotResumeSkippedOwners(t *testing.T) {
	s := New()
	view := anchoredWriterView(make([]byte, 16), 0, 4)
	input := writerInput(t, 4, ranges.Range{Length: 4, SourceID: 1})
	object, copied := &writerObject{id: 1}, &writerObject{id: 2}
	owners := make([]*Owner, MaxSnapshotOwners+1)
	for index := range owners {
		owners[index] = s.Acquire()
		t.Cleanup(owners[index].Finish)
		require.True(t, owners[index].UpdateWriter(object, WriterBytesBuffer, WriterView{}, view, &input, 4, 4))
	}
	var refs [MaxSnapshotOwners]WriterRef
	require.Equal(t, MaxSnapshotOwners, LookupWriterValue(s, copied, WriterBytesBuffer, view, refs[:]))
	skipped := owners[MaxSnapshotOwners]
	require.True(t, skipped.owner.writerDirty.Load())
	var snapshot ranges.Set
	require.False(t, skipped.SnapshotWriter(copied, WriterBytesBuffer, view, &snapshot))
	require.Zero(t, skipped.Charged())
}

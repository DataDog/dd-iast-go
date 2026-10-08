// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// WriterKind identifies one supported stateful writer type.
type WriterKind uint8

const (
	WriterInvalid WriterKind = iota
	WriterStringBuilder
	WriterBytesBuffer
)

// WriterView describes the complete visible writer backing state. Pointer is a
// numeric comparison key only and is never converted back to a pointer. Buffer
// views also retain an Anchor into the allocation at Backing; builders do not.
// Capacity charges the accessible backing, not an unknowable larger allocation
// retained by an interior slice.
type WriterView struct {
	Pointer  uintptr
	Length   uint32
	Capacity uint32
	Backing  uintptr
	Anchor   *byte
}

type writerRecord struct {
	object  any
	pointer uintptr
	kind    WriterKind
	view    WriterView
	set     ranges.Set
	charged int64
}

// WriterRef is a generation-captured writer owner result.
type WriterRef struct {
	store      *Store
	generation uint64
	index      uint8
	Kind       WriterKind
}

// Handle revalidates the writer owner and returns a handle by value.
func (r WriterRef) Handle() (Owner, bool) {
	if r.store == nil || r.index >= MaxOwners {
		return Owner{}, false
	}
	record := &r.store.owners[r.index]
	if record.generation.Load() != r.generation || ownerState(record.state.Load()) != stateActive {
		return Owner{}, false
	}
	return Owner{store: r.store, owner: record, index: r.index, gen: r.generation}, true
}

// Identity returns the captured owner slot identity.
func (r WriterRef) Identity() (index uint8, generation uint64, ok bool) {
	if _, ok = r.Handle(); !ok {
		return 0, 0, false
	}
	return r.index, r.generation, true
}

// LookupWriterValue returns candidate owners tracking object or an exact anchored
// Buffer view. A zero view requests receiver-only discovery, as used by Reset.
// Contention dirties possible matches so a skipped mutation cannot resume them.
func LookupWriterValue(s *Store, object any, kind WriterKind, view WriterView, out []WriterRef) int {
	pointer, ok := dynamicPointer(object)
	if !ok || s == nil || kind == WriterInvalid || len(out) == 0 {
		return 0
	}
	count := 0
	for ownerIndex := range s.owners {
		record := &s.owners[ownerIndex]
		generation := record.generation.Load()
		if generation == 0 || ownerState(record.state.Load()) != stateActive || record.writerDirty.Load() || !writerPresent(record, pointer, view.Backing, uintptr(view.Capacity), false) {
			continue
		}
		if !record.lifecycleMu.TryRLock() {
			record.writerDirty.Store(true)
			record.drops.contention.Add(1)
			continue
		}
		if generation != record.generation.Load() || ownerState(record.state.Load()) != stateActive || !record.writersMu.TryRLock() {
			record.writerDirty.Store(true)
			record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
			continue
		}
		found := !record.writerDirty.Load() && (writerIndexLocked(record, pointer, kind) >= 0 || writerViewIndexLocked(record, pointer, kind, view) >= 0)
		record.writersMu.RUnlock()   // +checklocksforce: TryRLock.
		record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		if !found {
			continue
		}
		if count >= len(out) {
			record.writerDirty.Store(true)
			record.drops.fanout.Add(1)
			continue
		}
		out[count] = WriterRef{store: s, generation: generation, index: uint8(ownerIndex), Kind: kind}
		count++
	}
	return count
}

// AdoptBufferWriter transfers an exact Buffer view to the receiver before its
// wrapped mutation. It reuses the canonical entry and its existing byte charge.
func (o *Owner) AdoptBufferWriter(object any, view WriterView) bool {
	pointer, ok := dynamicPointer(object)
	if !ok || !o.beginWrite() {
		if ok && o.alive() {
			o.owner.writerDirty.Store(true)
		}
		return false
	}
	defer o.endWrite()
	record := o.owner
	if forceWriterLockFail.Load() || !record.writersMu.TryLock() {
		record.writerDirty.Store(true)
		record.drops.contention.Add(1)
		return false
	}
	defer record.writersMu.Unlock() // +checklocksforce: TryLock.
	record.writerVersion.Add(1)
	defer record.writerVersion.Add(1)
	o.clearDirtyWritersLocked()
	index := writerIndexLocked(record, pointer, WriterBytesBuffer)
	if index >= 0 && record.writers[index].view != view {
		o.removeWriterLocked(index, true)
	}
	index = writerViewIndexLocked(record, pointer, WriterBytesBuffer, view)
	if index < 0 || !validWriterView(view) {
		return false
	}
	record.writers[index].object = object
	record.writers[index].pointer = pointer
	refreshWriterIndexLocked(record, index)
	return true
}

// UpdateWriter validates one completed write and appends input provenance. It
// creates state only when written input contains provenance.
func (o *Owner) UpdateWriter(object any, kind WriterKind, before, after WriterView, input *ranges.Set, inputLength, written uint32) bool {
	pointer, ok := dynamicPointer(object)
	if !ok || kind == WriterInvalid || !o.beginWrite() {
		return false
	}
	defer o.endWrite()
	record := o.owner
	if forceWriterLockFail.Load() || !record.writersMu.TryLock() {
		record.writerDirty.Store(true)
		record.drops.contention.Add(1)
		return false
	}
	defer record.writersMu.Unlock() // +checklocksforce: TryLock.
	record.writerVersion.Add(1)
	defer record.writerVersion.Add(1)
	o.clearDirtyWritersLocked()

	index := writerIndexLocked(record, pointer, kind)
	if !validWriterView(before) || !validWriterView(after) || written > inputLength || uint64(before.Length)+uint64(written) != uint64(after.Length) {
		if index >= 0 {
			o.removeWriterLocked(index, true)
		}
		return false
	}
	if index >= 0 && record.writers[index].view != before {
		o.removeWriterLocked(index, true)
		index = -1
	}

	var writtenSet ranges.Set
	if input != nil {
		if !input.ValidFor(inputLength) || !ranges.Slice(&writtenSet, input.Limit(), input, inputLength, 0, written).Valid {
			if index >= 0 {
				o.removeWriterLocked(index, true)
			}
			return false
		}
	}
	if index < 0 && writtenSet.Len() == 0 {
		return true
	}

	var current *ranges.Set
	limit := writtenSet.Limit()
	if index >= 0 {
		current = &record.writers[index].set
		limit = current.Limit()
	}
	var next ranges.Set
	outcome := ranges.Concat(&next, limit, current, before.Length, setOrNil(&writtenSet), written)
	if !outcome.Valid || next.Len() == 0 || !next.ValidFor(after.Length) {
		if index >= 0 {
			o.removeWriterLocked(index, true)
		}
		return outcome.Valid
	}

	if index < 0 {
		if record.writerCount >= MaxWriters {
			record.drops.full.Add(1)
			return false
		}
		index = int(record.writerCount)
		record.writerCount++
		record.writers[index] = writerRecord{object: object, pointer: pointer, kind: kind}
		o.store.addWriterStates(1)
	}
	entry := &record.writers[index]
	if !o.resizeWriterChargeLocked(entry, after.Capacity) {
		o.removeWriterLocked(index, true)
		return false
	}
	entry.object = object
	entry.pointer = pointer
	entry.kind = kind
	entry.view = after
	entry.set = next
	refreshWriterIndexLocked(record, index)
	return true
}

// SnapshotWriter copies writer ranges after exact view validation.
func (o *Owner) SnapshotWriter(object any, kind WriterKind, view WriterView, dst *ranges.Set) bool {
	pointer, ok := dynamicPointer(object)
	if !ok || dst == nil || !validWriterView(view) || !o.beginWrite() {
		return false
	}
	defer o.endWrite()
	record := o.owner
	if record.writerDirty.Load() {
		if !record.writersMu.TryLock() {
			record.drops.contention.Add(1)
			return false
		}
		record.writerVersion.Add(1)
		o.clearDirtyWritersLocked()
		record.writerVersion.Add(1)
		record.writersMu.Unlock() // +checklocksforce: TryLock.
		return false
	}
	if !record.writersMu.TryRLock() {
		record.drops.contention.Add(1)
		return false
	}
	defer record.writersMu.RUnlock() // +checklocksforce: TryRLock.
	index := writerViewIndexLocked(record, pointer, kind, view)
	if record.writerDirty.Load() || index < 0 || record.writers[index].view != view {
		return false
	}
	*dst = record.writers[index].set
	return dst.Len() > 0
}

// ResetWriter removes writer state and releases its active capacity charge.
func (o *Owner) ResetWriter(object any, kind WriterKind) bool {
	pointer, ok := dynamicPointer(object)
	if !ok || !o.beginWrite() {
		return false
	}
	defer o.endWrite()
	record := o.owner
	if forceWriterLockFail.Load() || !record.writersMu.TryLock() {
		record.writerDirty.Store(true)
		record.drops.contention.Add(1)
		return false
	}
	defer record.writersMu.Unlock() // +checklocksforce: TryLock.
	record.writerVersion.Add(1)
	defer record.writerVersion.Add(1)
	o.clearDirtyWritersLocked()
	index := writerIndexLocked(record, pointer, kind)
	if index < 0 {
		return true
	}
	o.removeWriterLocked(index, true)
	return true
}

// TruncateWriter validates and applies one completed truncation.
func (o *Owner) TruncateWriter(object any, kind WriterKind, before, after WriterView) bool {
	pointer, ok := dynamicPointer(object)
	if !ok || !o.beginWrite() {
		return false
	}
	defer o.endWrite()
	record := o.owner
	if forceWriterLockFail.Load() || !record.writersMu.TryLock() {
		record.writerDirty.Store(true)
		record.drops.contention.Add(1)
		return false
	}
	defer record.writersMu.Unlock() // +checklocksforce: TryLock.
	record.writerVersion.Add(1)
	defer record.writerVersion.Add(1)
	o.clearDirtyWritersLocked()
	index := writerIndexLocked(record, pointer, kind)
	if !validWriterView(before) || !validWriterView(after) || after.Length > before.Length {
		if index >= 0 {
			o.removeWriterLocked(index, true)
		}
		return false
	}
	if index < 0 {
		return true
	}
	entry := &record.writers[index]
	if entry.view != before {
		o.removeWriterLocked(index, true)
		return false
	}
	var next ranges.Set
	if !ranges.Slice(&next, entry.set.Limit(), &entry.set, before.Length, 0, after.Length).Valid || next.Len() == 0 {
		o.removeWriterLocked(index, true)
		return true
	}
	if !o.resizeWriterChargeLocked(entry, after.Capacity) {
		o.removeWriterLocked(index, true)
		return false
	}
	entry.view = after
	entry.set = next
	refreshWriterIndexLocked(record, index)
	return true
}

// BindWriterActive binds the process invalidation fast counter. It must be
// called once before the store is made visible to request handlers.
func (s *Store) BindWriterActive(active *atomic.Int32) {
	if s == nil {
		return
	}
	s.writerActive = active
}

func (s *Store) addWriterStates(delta int32) {
	s.writerStates.Add(delta)
	if s.writerActive != nil {
		s.writerActive.Add(delta)
	}
}

// HasWriterStates reports whether any owner retains writer state.
func (s *Store) HasWriterStates() bool {
	return s != nil && s.writerStates.Load() > 0
}

// InvalidateWriterPointer drops every state matching the numeric object pointer.
func (s *Store) InvalidateWriterPointer(pointer uintptr) {
	s.InvalidateBuffer(pointer, 0, 0, false)
}

// InvalidateBuffer drops a receiver and overlapping anchored Buffer backing
// intervals. Expected backing writes preserve only their prepared receiver.
// The native-width interval also covers buffers larger than the tracking limit.
func (s *Store) InvalidateBuffer(pointer, backing, capacity uintptr, preserve bool) {
	if s == nil || pointer == 0 {
		return
	}
	for ownerIndex := range s.owners {
		record := &s.owners[ownerIndex]
		if ownerState(record.state.Load()) != stateActive || !writerPresent(record, pointer, backing, capacity, preserve) {
			continue
		}
		if !record.lifecycleMu.TryRLock() {
			record.writerDirty.Store(true)
			record.drops.contention.Add(1)
			continue
		}
		if ownerState(record.state.Load()) != stateActive || !record.writersMu.TryLock() {
			record.writerDirty.Store(true)
			record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
			continue
		}
		owner := Owner{store: s, owner: record, index: uint8(ownerIndex), gen: record.generation.Load()}
		record.writerVersion.Add(1)
		owner.clearDirtyWritersLocked()
		for index := 0; index < int(record.writerCount); {
			entry := &record.writers[index]
			if !(preserve && entry.pointer == pointer) && (entry.pointer == pointer || entry.kind == WriterBytesBuffer && overlaps(entry.view.Backing, uintptr(entry.view.Capacity), backing, capacity)) {
				owner.removeWriterLocked(index, true)
				continue
			}
			index++
		}
		record.writerVersion.Add(1)
		record.writersMu.Unlock()    // +checklocksforce: TryLock.
		record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
	}
}

func validWriterView(view WriterView) bool {
	return view.Length <= view.Capacity && view.Capacity <= MaxRootBytes && (view.Length == 0 || view.Pointer != 0) &&
		((view.Backing == 0 && view.Anchor == nil) || (view.Backing != 0 && view.Anchor != nil && view.Backing+uintptr(view.Capacity) > view.Backing))
}

func overlaps(first, firstCapacity, second, secondCapacity uintptr) bool {
	return first != 0 && second != 0 && firstCapacity != 0 && secondCapacity != 0 &&
		first < second+secondCapacity && second < first+firstCapacity
}

func writerPresent(record *owner, pointer, backing, capacity uintptr, preserve bool) bool {
	for attempt := 0; attempt < 3; attempt++ {
		before := record.writerVersion.Load()
		if before&1 != 0 {
			continue
		}
		found := false
		for index := 0; index < MaxWriters; index++ {
			candidate := record.writerPointers[index].Load()
			if preserve && candidate == pointer {
				continue
			}
			start, end := record.writerStarts[index].Load(), record.writerEnds[index].Load()
			found = found || candidate == pointer || overlaps(start, end-start, backing, capacity)
		}
		after := record.writerVersion.Load()
		if before == after && after&1 == 0 {
			return found
		}
	}
	return true // A concurrent change is a conservative possible match.
}

// Called with writersMu held and writerVersion odd, including view-only changes.
func refreshWriterIndexLocked(record *owner, index int) {
	entry := &record.writers[index]
	record.writerPointers[index].Store(entry.pointer)
	start, end := uintptr(0), uintptr(0)
	if entry.kind == WriterBytesBuffer && entry.view.Anchor != nil {
		start = entry.view.Backing
		end = start + uintptr(entry.view.Capacity)
	}
	record.writerStarts[index].Store(start)
	record.writerEnds[index].Store(end)
}

func writerViewIndexLocked(record *owner, pointer uintptr, kind WriterKind, view WriterView) int {
	index := writerIndexLocked(record, pointer, kind)
	if index >= 0 && (view == (WriterView{}) || record.writers[index].view == view) {
		return index
	}
	if kind == WriterBytesBuffer && view.Anchor != nil && validWriterView(view) {
		for index := 0; index < int(record.writerCount); index++ {
			entry := &record.writers[index]
			if entry.kind == kind && entry.view == view {
				return index
			}
		}
	}
	return -1
}

func writerIndexLocked(record *owner, pointer uintptr, kind WriterKind) int {
	for index := 0; index < int(record.writerCount); index++ {
		entry := &record.writers[index]
		if entry.pointer == pointer && entry.kind == kind {
			return index
		}
	}
	return -1
}

func (o *Owner) resizeWriterChargeLocked(entry *writerRecord, capacity uint32) bool {
	desired := int64(0)
	if capacity > 0 {
		desired = sizeClass(int(capacity))
	}
	delta := desired - entry.charged
	if delta > 0 {
		if !reserveInt64(&o.owner.charged, delta, RequestRootBytes) {
			o.owner.drops.bytes.Add(1)
			return false
		}
		if !reserveInt64(&o.store.charged, delta, ProcessRootBytes) {
			o.owner.charged.Add(-delta)
			o.owner.drops.bytes.Add(1)
			return false
		}
	} else if delta < 0 {
		o.owner.charged.Add(delta)
		o.store.charged.Add(delta)
	}
	entry.charged = desired
	return true
}

func (o *Owner) removeWriterLocked(index int, release bool) {
	record := o.owner
	if index < 0 || index >= int(record.writerCount) {
		return
	}
	entry := &record.writers[index]
	if release && entry.charged != 0 {
		record.charged.Add(-entry.charged)
		o.store.charged.Add(-entry.charged)
	}
	last := int(record.writerCount) - 1
	if index != last {
		record.writers[index] = record.writers[last]
		refreshWriterIndexLocked(record, index)
	}
	record.writers[last] = writerRecord{}
	refreshWriterIndexLocked(record, last)
	record.writerCount--
	o.store.addWriterStates(-1)
}

func (o *Owner) clearDirtyWritersLocked() {
	if !o.owner.writerDirty.Swap(false) {
		return
	}
	for o.owner.writerCount > 0 {
		o.removeWriterLocked(int(o.owner.writerCount)-1, true)
	}
}

func releaseWritersForFinishLocked(s *Store, record *owner) int64 {
	var charged int64
	count := int(record.writerCount)
	record.writerVersion.Add(1)
	for index := 0; index < count; index++ {
		charged += record.writers[index].charged
		record.writers[index] = writerRecord{}
		refreshWriterIndexLocked(record, index)
	}
	record.writerVersion.Add(1)
	if count > 0 {
		s.addWriterStates(int32(-count))
	}
	return charged
}

func setOrNil(set *ranges.Set) *ranges.Set {
	if set == nil || set.Len() == 0 {
		return nil
	}
	return set
}

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
// numeric comparison key only and is never converted back to a pointer.
type WriterView struct {
	Pointer  uintptr
	Length   uint32
	Capacity uint32
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

// LookupWriterValue returns active owners tracking object as kind. Contention is
// a safe miss and out bounds the owner fanout.
func LookupWriterValue(s *Store, object any, kind WriterKind, out []WriterRef) int {
	pointer, ok := dynamicPointer(object)
	if !ok || s == nil || kind == WriterInvalid || len(out) == 0 {
		return 0
	}
	count := 0
	for ownerIndex := range s.owners {
		record := &s.owners[ownerIndex]
		generation := record.generation.Load()
		if generation == 0 || ownerState(record.state.Load()) != stateActive || record.writerDirty.Load() || !writerPointerPresent(record, pointer) {
			continue
		}
		if !record.lifecycleMu.TryRLock() {
			record.drops.contention.Add(1)
			continue
		}
		if generation != record.generation.Load() || ownerState(record.state.Load()) != stateActive || !record.writersMu.TryRLock() {
			record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
			continue
		}
		found := writerIndexLocked(record, pointer, kind) >= 0
		record.writersMu.RUnlock()   // +checklocksforce: TryRLock.
		record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		if !found {
			continue
		}
		if count >= len(out) {
			record.drops.fanout.Add(1)
			continue
		}
		out[count] = WriterRef{store: s, generation: generation, index: uint8(ownerIndex), Kind: kind}
		count++
	}
	return count
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
		record.writerVersion.Add(1)
		index = int(record.writerCount)
		record.writerCount++
		record.writers[index] = writerRecord{object: object, pointer: pointer, kind: kind}
		record.writerPointers[index].Store(pointer)
		record.writerVersion.Add(1)
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
		o.clearDirtyWritersLocked()
		record.writersMu.Unlock() // +checklocksforce: TryLock.
		return false
	}
	if !record.writersMu.TryRLock() {
		record.drops.contention.Add(1)
		return false
	}
	defer record.writersMu.RUnlock() // +checklocksforce: TryRLock.
	index := writerIndexLocked(record, pointer, kind)
	if index < 0 || record.writers[index].view != view {
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
	if s == nil || pointer == 0 {
		return
	}
	for ownerIndex := range s.owners {
		record := &s.owners[ownerIndex]
		if ownerState(record.state.Load()) != stateActive || !writerPointerPresent(record, pointer) {
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
		owner.clearDirtyWritersLocked()
		for index := 0; index < int(record.writerCount); {
			if record.writers[index].pointer == pointer {
				owner.removeWriterLocked(index, true)
				continue
			}
			index++
		}
		record.writersMu.Unlock()    // +checklocksforce: TryLock.
		record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
	}
}

func validWriterView(view WriterView) bool {
	return view.Length <= view.Capacity && view.Capacity <= MaxRootBytes && (view.Length == 0 || view.Pointer != 0)
}

func writerPointerPresent(record *owner, pointer uintptr) bool {
	for attempt := 0; attempt < 3; attempt++ {
		before := record.writerVersion.Load()
		if before&1 != 0 {
			continue
		}
		found := false
		for index := 0; index < MaxWriters; index++ {
			found = found || record.writerPointers[index].Load() == pointer
		}
		after := record.writerVersion.Load()
		if before == after && after&1 == 0 {
			return found
		}
	}
	return true // A concurrent change is a conservative possible match.
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
	record.writerVersion.Add(1)
	last := int(record.writerCount) - 1
	if index != last {
		record.writers[index] = record.writers[last]
		record.writerPointers[index].Store(record.writers[index].pointer)
	}
	record.writers[last] = writerRecord{}
	record.writerPointers[last].Store(0)
	record.writerCount--
	record.writerVersion.Add(1)
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
		record.writerPointers[index].Store(0)
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

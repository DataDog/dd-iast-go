// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// ResolvedRange is a complete copied range and request source. Its strings are
// valid for the synchronous visitor call and must not be retained by internal
// instrumentation after that call returns.
type ResolvedRange struct {
	Start        uint32
	Length       uint32
	Source       Source
	Marks        uint64
	OwnerID      uint64
	OwnerGen     uint64
	OwnerIndex   uint8
	RangeOrdinal uint8
}

// VisitString visits complete live provenance for value. It returns true if it
// delivered at least one range.
func VisitString(value string, visit func(ResolvedRange) bool) bool {
	key, ok := store.StringKey(value)
	if !ok {
		return false
	}
	return visitKey(key, visit, nil)
}

// VisitStringHidden is [VisitString] with hidden. When hidden is not nil, it
// gets each byte interval of value that can contain bytes of an owner, but
// that visit does not get: the ranges of an owner whose sources cannot be
// copied, and the complete value when the lookup can have skipped an owner
// (see [store.Snapshot.Partial]). The owner of a hidden interval is not
// known. When visit returns false, the visit stops and hidden can miss
// intervals.
func VisitStringHidden(value string, visit func(ResolvedRange) bool, hidden func(start, length uint32)) bool {
	key, ok := store.StringKey(value)
	if !ok {
		return false
	}
	return visitKey(key, visit, hidden)
}

// VisitBytes visits complete live provenance for value. It returns true if it
// delivered at least one range.
func VisitBytes(value []byte, visit func(ResolvedRange) bool) bool {
	key, ok := store.BytesKey(value)
	if !ok {
		return false
	}
	return visitKey(key, visit, nil)
}

// Owner identifies one generation-validated store owner: the store owner slot
// index, ID, and generation of one request analysis.
type Owner struct {
	ID         uint64
	Generation uint64
	Index      uint8
}

// Owner returns the live store owner of a.
func (a Analysis) Owner() (Owner, bool) {
	index, id, generation, ok := a.Identity()
	return Owner{ID: id, Generation: generation, Index: index}, ok
}

// VisitStringOwner visits the complete live provenance of value that owner
// has. It returns true if it delivered at least one range of owner. It does
// not copy a source of a different owner. See [VisitBytesOwner] for foreign.
func VisitStringOwner(value string, owner Owner, visit func(ResolvedRange) bool, foreign func(start, length uint32)) bool {
	key, ok := store.StringKey(value)
	if !ok {
		return false
	}
	return visitKeyOwner(key, owner, visit, foreign)
}

// VisitBytesOwner visits the complete live provenance of value that owner has.
// It returns true if it delivered at least one range of owner. It does not
// copy a source of a different owner. When foreign is not nil, it gets the
// byte interval of each range of a different owner (also a range with secure
// marks). When the lookup can have skipped an owner (see
// [store.Snapshot.Partial]), foreign also gets the complete value: an unknown
// owner can have bytes in it.
func VisitBytesOwner(value []byte, owner Owner, visit func(ResolvedRange) bool, foreign func(start, length uint32)) bool {
	key, ok := store.BytesKey(value)
	if !ok {
		return false
	}
	return visitKeyOwner(key, owner, visit, foreign)
}

// IsTaintedString reports whether value has complete live provenance.
func IsTaintedString(value string) bool {
	return VisitString(value, stopAfterFirst)
}

// IsTaintedBytes reports whether value has complete live provenance.
func IsTaintedBytes(value []byte) bool {
	return VisitBytes(value, stopAfterFirst)
}

func stopAfterFirst(ResolvedRange) bool { return false }

// isManagedSource reports whether value is the complete managed root of a
// string source of the owner of a. Only then can a lazy source hook skip source
// management. These values are not managed sources of a:
//   - a tainted window of a different root (for example a query value in the raw
//     query string): it has the provenance of the other root;
//   - a complete root of a different owner: the source is of a different request;
//   - a complete propagated root of a: it is tainted, but it is not a source.
//
// The cheap store filter check comes first.
func (a Analysis) isManagedSource(value string) bool {
	key, ok := store.StringKey(value)
	if !ok || !a.Active() || a.manager.used.Load() == 0 || !a.manager.store.MayContain(key) {
		return false
	}
	return a.isManagedSourceHit(key, value)
}

//go:noinline
func (a Analysis) isManagedSourceHit(key store.Key, value string) bool {
	ownerIndex, ownerID, ownerGen, ok := a.Identity()
	if !ok {
		return false
	}
	var snapshot store.Snapshot
	if !a.manager.store.Lookup(key, &snapshot) {
		return false
	}
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok || !entry.WholeRoot || entry.OwnerIndex != ownerIndex || entry.OwnerID != ownerID || entry.OwnerGen != ownerGen {
			continue
		}
		// A source root has one range over the complete value.
		if entry.Ranges.Len() != 1 {
			return false
		}
		var compact [1]ranges.Range
		if entry.Ranges.CopyTo(compact[:]) != 1 || compact[0].Start != 0 || compact[0].Length != uint32(len(value)) {
			return false
		}
		source, ok := a.Source(compact[0].SourceID)
		// The source value of a string source is its managed root.
		return ok && source.Kind == SourceString && sameStringBacking(source.Value, value)
	}
	return false
}

func visitKey(key store.Key, visit func(ResolvedRange) bool, hidden func(start, length uint32)) bool {
	if visit == nil {
		return false
	}
	manager := processManager.Load()
	if manager == nil || manager.used.Load() == 0 || !manager.store.MayContain(key) {
		return false
	}
	// A filter hit is frequent under a high index load. Confirm rejects most
	// clean values with no range copy and no large Snapshot on the stack.
	if manager.store.Confirm(key.Pointer, key.Length) == store.ConfirmClean {
		return false
	}
	return visitKeyHit(manager, key, visit, hidden)
}

func visitKeyOwner(key store.Key, owner Owner, visit func(ResolvedRange) bool, foreign func(start, length uint32)) bool {
	if visit == nil || owner.ID == 0 || owner.Generation == 0 {
		return false
	}
	manager := processManager.Load()
	if manager == nil || manager.used.Load() == 0 || !manager.store.MayContain(key) {
		return false
	}
	if manager.store.Confirm(key.Pointer, key.Length) == store.ConfirmClean {
		return false
	}
	return visitKeyOwnerHit(manager, key, owner, visit, foreign)
}

// ActiveStore returns the process taint store when at least one analysis is
// active, or nil otherwise. It is a cheap fast gate for propagation; callers
// must still use Store.MayContain before any lookup. It performs no allocation.
func ActiveStore() *store.Store {
	manager := processManager.Load()
	if manager == nil || manager.used.Load() == 0 {
		return nil
	}
	return manager.store
}

//go:noinline
func visitKeyHit(manager *Manager, key store.Key, visit func(ResolvedRange) bool, hidden func(start, length uint32)) bool {
	var snapshot store.Snapshot
	if !manager.store.Lookup(key, &snapshot) {
		return false
	}
	if hidden != nil && snapshot.Partial() {
		hidden(0, key.Length)
	}
	delivered := false
	for ownerIndex := 0; ownerIndex < snapshot.Len(); ownerIndex++ {
		entry, ok := snapshot.At(ownerIndex)
		if !ok {
			continue
		}
		entryDelivered, keepGoing, copied := deliverEntry(manager, entry, visit)
		delivered = delivered || entryDelivered
		if !copied && hidden != nil {
			// The bytes of entry are not visited. They can be data of a
			// different owner. deliverForeign copies no source.
			deliverForeign(entry, hidden)
		}
		if !keepGoing {
			return delivered
		}
	}
	return delivered
}

//go:noinline
func visitKeyOwnerHit(manager *Manager, key store.Key, owner Owner, visit func(ResolvedRange) bool, foreign func(start, length uint32)) bool {
	var snapshot store.Snapshot
	if !manager.store.Lookup(key, &snapshot) {
		return false
	}
	if foreign != nil && snapshot.Partial() {
		foreign(0, key.Length)
	}
	delivered := false
	for ownerIndex := 0; ownerIndex < snapshot.Len(); ownerIndex++ {
		entry, ok := snapshot.At(ownerIndex)
		if !ok {
			continue
		}
		if entry.OwnerIndex != owner.Index || entry.OwnerID != owner.ID || entry.OwnerGen != owner.Generation {
			if foreign != nil {
				deliverForeign(entry, foreign)
			}
			continue
		}
		entryDelivered, keepGoing, _ := deliverEntry(manager, entry, visit)
		delivered = delivered || entryDelivered
		// A lookup has one entry for each owner. The other entries are only
		// necessary for foreign.
		if !keepGoing && foreign == nil {
			return delivered
		}
	}
	return delivered
}

// deliverForeign gives the byte intervals of entry to foreign. It copies no
// source: the source table of a different owner is not necessary.
func deliverForeign(entry *store.Entry, foreign func(start, length uint32)) {
	var compact [ranges.HardLimit]ranges.Range
	count := entry.Ranges.CopyTo(compact[:])
	for i := 0; i < count; i++ {
		foreign(compact[i].Start, compact[i].Length)
	}
}

// deliverEntry gives the ranges of entry to visit. copied is false when the
// sources of entry cannot be copied: then visit gets no range of entry.
//
//go:noinline
func deliverEntry(manager *Manager, entry *store.Entry, visit func(ResolvedRange) bool) (delivered, keepGoing, copied bool) {
	var compact [ranges.HardLimit]ranges.Range
	count := entry.Ranges.CopyTo(compact[:])
	if count == 0 {
		return false, true, true
	}
	var ids [ranges.HardLimit]SourceID
	for i := 0; i < count; i++ {
		ids[i] = compact[i].SourceID
	}
	var sources [ranges.HardLimit]Source
	if !manager.copySources(entry.OwnerIndex, entry.OwnerID, entry.OwnerGen, ids[:count], sources[:count]) {
		return false, true, false
	}
	for i := 0; i < count; i++ {
		delivered = true
		if !visit(ResolvedRange{
			Start:        compact[i].Start,
			Length:       compact[i].Length,
			Source:       sources[i],
			Marks:        compact[i].Marks,
			OwnerID:      entry.OwnerID,
			OwnerGen:     entry.OwnerGen,
			OwnerIndex:   entry.OwnerIndex,
			RangeOrdinal: uint8(i),
		}) {
			return true, false, true
		}
	}
	return delivered, true, true
}

func (m *Manager) copySources(ownerIndex uint8, ownerID, ownerGen uint64, ids []SourceID, dst []Source) bool {
	if m == nil || ownerIndex >= MaxAnalyses || ownerID == 0 || ownerGen == 0 || len(ids) == 0 || len(dst) < len(ids) || len(ids) > ranges.HardLimit {
		return false
	}
	slot := m.directory[ownerIndex].Load()
	if slot == nil || !slot.active.Load() || slot.ownerID.Load() != ownerID || slot.ownerGen.Load() != ownerGen {
		return false
	}
	if !slot.sourceMu.TryLock() {
		return false
	}
	valid := slot.active.Load() && slot.ownerID.Load() == ownerID && slot.ownerGen.Load() == ownerGen && m.directory[ownerIndex].Load() == slot
	if valid {
		for sourceIndex, id := range ids {
			var ok bool
			dst[sourceIndex], ok = slot.table.Get(id)
			if !ok {
				valid = false
				break
			}
		}
	}
	slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !valid {
		clear(dst[:len(ids)])
	}
	return valid
}

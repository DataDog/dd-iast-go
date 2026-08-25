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
	Start  uint32
	Length uint32
	Source Source
	Marks  uint64
}

// VisitString visits complete live provenance for value. It returns true if it
// delivered at least one range.
func VisitString(value string, visit func(ResolvedRange) bool) bool {
	key, ok := store.StringKey(value)
	if !ok {
		return false
	}
	return visitKey(key, visit)
}

// VisitBytes visits complete live provenance for value. It returns true if it
// delivered at least one range.
func VisitBytes(value []byte, visit func(ResolvedRange) bool) bool {
	key, ok := store.BytesKey(value)
	if !ok {
		return false
	}
	return visitKey(key, visit)
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

func visitKey(key store.Key, visit func(ResolvedRange) bool) bool {
	if visit == nil {
		return false
	}
	manager := processManager.Load()
	if manager == nil || manager.used.Load() == 0 || !manager.store.MayContain(key) {
		return false
	}
	return visitKeyHit(manager, key, visit)
}

//go:noinline
func visitKeyHit(manager *Manager, key store.Key, visit func(ResolvedRange) bool) bool {
	var snapshot store.Snapshot
	if !manager.store.Lookup(key, &snapshot) {
		return false
	}
	delivered := false
	for ownerIndex := 0; ownerIndex < snapshot.Len(); ownerIndex++ {
		entry, ok := snapshot.At(ownerIndex)
		if !ok {
			continue
		}
		entryDelivered, keepGoing := deliverEntry(manager, entry, visit)
		delivered = delivered || entryDelivered
		if !keepGoing {
			return delivered
		}
	}
	return delivered
}

//go:noinline
func deliverEntry(manager *Manager, entry *store.Entry, visit func(ResolvedRange) bool) (delivered, keepGoing bool) {
	var compact [ranges.HardLimit]ranges.Range
	count := entry.Ranges.CopyTo(compact[:])
	if count == 0 {
		return false, true
	}
	var ids [ranges.HardLimit]SourceID
	for i := 0; i < count; i++ {
		ids[i] = compact[i].SourceID
	}
	var sources [ranges.HardLimit]Source
	if !manager.copySources(entry.OwnerIndex, entry.OwnerID, entry.OwnerGen, ids[:count], sources[:count]) {
		return false, true
	}
	for i := 0; i < count; i++ {
		delivered = true
		if !visit(ResolvedRange{
			Start:  compact[i].Start,
			Length: compact[i].Length,
			Source: sources[i],
			Marks:  compact[i].Marks,
		}) {
			return true, false
		}
	}
	return delivered, true
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

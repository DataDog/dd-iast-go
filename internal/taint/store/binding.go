// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"sync"
	"unsafe"
)

const (
	MaxBindings       = 256
	bindingIndexSlots = 512
)

// BindingKind identifies a supported typed object relationship.
type BindingKind uint8

const (
	BindingInvalid BindingKind = iota
	BindingURL
	BindingReader
)

type binding struct {
	// Bindings retain arbitrary typed objects outside the managed-root byte
	// charge. Their count and fixed table are bounded; Phase 4 must bind only
	// small URL/reader wrapper objects, never request payload graphs.
	object  any // strong typed pointer
	pointer uintptr
	kind    BindingKind
}

type bindingTable struct {
	mu      sync.RWMutex
	entries [MaxBindings]binding
	index   [bindingIndexSlots]uint16 // entry index + 1
	count   uint16
}

// OwnerRef is a compact generation-captured binding result.
type OwnerRef struct {
	store      *Store
	generation uint64
	index      uint8
	Kind       BindingKind
}

// Handle returns a revalidated owner handle by value, without allocation.
func (r OwnerRef) Handle() (Owner, bool) {
	if r.store == nil || r.index >= MaxOwners {
		return Owner{}, false
	}
	record := &r.store.owners[r.index]
	if record.generation.Load() != r.generation || ownerState(record.state.Load()) != stateActive {
		return Owner{}, false
	}
	return Owner{store: r.store, owner: record, index: r.index, gen: r.generation}, true
}

// BindObject strongly binds a typed heap object to owner. It never derives a
// pointer from an interface data word.
func BindObject[T any](owner *Owner, object *T, kind BindingKind) bool {
	if owner == nil || object == nil || kind == BindingInvalid || !owner.beginWrite() {
		return false
	}
	defer owner.endWrite()
	table := &owner.owner.bindings
	if !table.mu.TryLock() {
		owner.owner.drops.contention.Add(1)
		return false
	}
	defer table.mu.Unlock() // +checklocksforce: TryLock.
	pointer := uintptr(unsafe.Pointer(object))
	start := bindingHash(pointer) & (bindingIndexSlots - 1)
	for probe := 0; probe < bindingIndexSlots; probe++ {
		slot := (start + probe) & (bindingIndexSlots - 1)
		encoded := table.index[slot]
		if encoded == 0 {
			if table.count >= MaxBindings {
				owner.owner.drops.full.Add(1)
				return false
			}
			entry := table.count
			table.entries[entry] = binding{object: object, pointer: pointer, kind: kind}
			table.index[slot] = entry + 1
			table.count++
			return true
		}
		entry := &table.entries[encoded-1]
		if entry.pointer == pointer {
			entry.object = object
			entry.kind = kind
			return true
		}
	}
	owner.owner.drops.full.Add(1)
	return false
}

// LookupObject returns active owners bound to object. out bounds owner fanout;
// extra owners are dropped with telemetry.
func LookupObject[T any](store *Store, object *T, out []OwnerRef) int {
	if store == nil || object == nil || len(out) == 0 {
		return 0
	}
	pointer := uintptr(unsafe.Pointer(object))
	count := 0
	for i := range store.owners {
		record := &store.owners[i]
		if ownerState(record.state.Load()) != stateActive || !record.lifecycleMu.TryRLock() {
			continue
		}
		generation := record.generation.Load()
		if ownerState(record.state.Load()) != stateActive {
			record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
			continue
		}
		table := &record.bindings
		if !table.mu.TryRLock() {
			record.drops.contention.Add(1)
			record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
			continue
		}
		kind, found := table.find(pointer)
		table.mu.RUnlock()           // +checklocksforce: TryRLock.
		record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		if !found {
			continue
		}
		if count >= len(out) {
			record.drops.fanout.Add(1)
			continue
		}
		out[count] = OwnerRef{store: store, index: uint8(i), generation: generation, Kind: kind}
		count++
	}
	return count
}

func (t *bindingTable) find(pointer uintptr) (BindingKind, bool) {
	start := bindingHash(pointer) & (bindingIndexSlots - 1)
	for probe := 0; probe < bindingIndexSlots; probe++ {
		encoded := t.index[(start+probe)&(bindingIndexSlots-1)]
		if encoded == 0 {
			return BindingInvalid, false
		}
		entry := t.entries[encoded-1]
		if entry.pointer == pointer {
			return entry.kind, true
		}
	}
	return BindingInvalid, false
}

func (t *bindingTable) reset() {
	t.mu.Lock()
	clear(t.entries[:])
	clear(t.index[:])
	t.count = 0
	t.mu.Unlock()
}

func bindingHash(pointer uintptr) int {
	hash := uint64(pointer)
	hash ^= hash >> 30
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 27
	return int(hash)
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import "github.com/DataDog/dd-iast-go/internal/taint/ranges"

const MaxSnapshotOwners = 4

type lookupWindow struct {
	ownerIdx uint8
	ownerGen uint64
	rootID   uint16
	rootGen  uint32
	rootOff  uint32
	length   uint32
}

// Entry is an immutable owner-separated lookup result.
type Entry struct {
	OwnerID  uint64
	OwnerGen uint64
	Root     RootRef
	Ranges   ranges.Set
}

// Snapshot is caller-owned fixed lookup storage.
type Snapshot struct {
	entries [MaxSnapshotOwners]Entry
	count   uint8
}

// Len returns the number of complete entries.
func (s *Snapshot) Len() int {
	if s == nil {
		return 0
	}
	return int(s.count)
}

// At returns an entry without allocation.
func (s *Snapshot) At(index int) (*Entry, bool) {
	if s == nil || index < 0 || index >= int(s.count) {
		return nil, false
	}
	return &s.entries[index], true
}

func (s *Snapshot) reset() {
	if s == nil {
		return
	}
	for i := 0; i < int(s.count); i++ {
		s.entries[i] = Entry{}
	}
	s.count = 0
}

// Lookup copies complete live owner contributions into out. It never returns
// live root storage. The boolean is false only when the shard read lock could
// not be acquired; an acquired lookup with no match returns true and Len zero.
func (s *Store) Lookup(key Key, out *Snapshot) bool {
	if s == nil || out == nil || !validKey(key) {
		return false
	}
	out.reset()
	hash := keyHash(key)
	shard := &s.shards[shardIndex(hash)]
	if !shard.mu.TryRLock() {
		return false
	}
	var windows [MaxSnapshotOwners]lookupWindow
	windowCount := 0
	start := initialSlot(hash)
	for probe := 0; probe < ProbeLimit; probe++ {
		slot := &shard.slots[(start+uint8(probe))%SlotsPerShard]
		if slot.pointer == 0 {
			break
		}
		if slot.pointer == tombstone || slot.pointer != key.Pointer || slot.length != key.Length || slot.kind != key.Kind {
			continue
		}
		if windowCount >= len(windows) {
			if slot.ownerIdx < MaxOwners {
				s.owners[slot.ownerIdx].drops.fanout.Add(1)
			}
			continue
		}
		windows[windowCount] = lookupWindow{
			ownerIdx: slot.ownerIdx, ownerGen: slot.ownerGen, rootID: slot.rootID,
			rootGen: slot.rootGen, rootOff: slot.rootOff, length: slot.length,
		}
		windowCount++
	}
	shard.mu.RUnlock() // +checklocksforce: TryRLock.

	for i := 0; i < windowCount; i++ {
		window := windows[i]
		if window.ownerIdx >= MaxOwners {
			continue
		}
		owner := &s.owners[window.ownerIdx]
		if !owner.lifecycleMu.TryRLock() {
			owner.drops.contention.Add(1)
			continue
		}
		if owner.generation.Load() != window.ownerGen || ownerState(owner.state.Load()) != stateActive || window.rootID >= MaxRootsPerOwner {
			owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
			continue
		}
		if !owner.rootsMu.TryRLock() {
			owner.drops.contention.Add(1)
			owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
			continue
		}
		root := &owner.roots[window.rootID]
		if root.generation.Load() != window.rootGen || root.setGen != window.rootGen || root.count == 0 {
			owner.rootsMu.RUnlock()     // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
			owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
			continue
		}
		var compact [MaxRanges]ranges.Range
		count := int(root.count)
		inlineCount := min(count, GuaranteedRanges)
		copy(compact[:inlineCount], root.inline[:inlineCount])
		if count > GuaranteedRanges {
			if root.overflow == 0 {
				count = GuaranteedRanges
			} else {
				copy(compact[GuaranteedRanges:count], s.overflow[root.overflow-1].ranges[:count-GuaranteedRanges])
			}
		}
		var canonical ranges.Set
		adopted := ranges.AdoptCanonical(&canonical, root.limit, compact[:count], root.span)
		var windowSet ranges.Set
		end := uint64(window.rootOff) + uint64(window.length)
		valid := adopted.Valid && end <= uint64(root.span) && ranges.Slice(&windowSet, root.limit, &canonical, root.span, window.rootOff, uint32(end)).Valid && root.generation.Load() == window.rootGen && root.setGen == window.rootGen
		ownerID := owner.id.Load()
		owner.rootsMu.RUnlock()     // +checklocksforce: TryRLock.
		owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		if !valid || out.count >= MaxSnapshotOwners {
			continue
		}
		entry := &out.entries[out.count]
		entry.OwnerID = ownerID
		entry.OwnerGen = window.ownerGen
		entry.Root = RootRef{ID: window.rootID, Generation: window.rootGen}
		entry.Ranges = windowSet
		out.count++
	}
	return true
}

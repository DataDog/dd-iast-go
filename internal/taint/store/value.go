// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import "sync/atomic"

var forceCollision atomic.Bool      // test seam
var forceWriterLockFail atomic.Bool // test seam

func keyHash(key Key) uint64 {
	if forceCollision.Load() {
		return 0
	}
	hash := uint64(key.Pointer)
	hash ^= hash >> 30
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 27
	hash *= 0x94d049bb133111eb
	hash ^= hash >> 31
	hash ^= uint64(key.Length) * 0x9e3779b97f4a7c15
	hash ^= uint64(key.Kind) << 56
	return hash
}

func shardIndex(hash uint64) uint8  { return uint8(hash % Shards) }
func initialSlot(hash uint64) uint8 { return uint8((hash >> 16) % SlotsPerShard) }

func validKey(key Key) bool {
	return key.Pointer != 0 && key.Pointer != tombstone && key.Length > 0 && (key.Kind == KindString || key.Kind == KindBytes)
}

func inWindow(pointer uintptr, length uint32, base uintptr, span uint32) (uint32, bool) {
	rootEnd := base + uintptr(span)
	if rootEnd < base || pointer < base {
		return 0, false
	}
	valueEnd := pointer + uintptr(length)
	if valueEnd < pointer || valueEnd > rootEnd {
		return 0, false
	}
	offset := pointer - base
	if offset > uintptr(^uint32(0)) {
		return 0, false
	}
	return uint32(offset), true
}

func reserveInt64(counter *atomic.Int64, amount, limit int64) bool {
	for {
		current := counter.Load()
		if amount < 0 || amount > limit-current {
			return false
		}
		if counter.CompareAndSwap(current, current+amount) {
			return true
		}
	}
}

func reserveInt32(counter *atomic.Int32, limit int32) bool {
	for {
		current := counter.Load()
		if current >= limit {
			return false
		}
		if counter.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func reserveRootValue(root *rootRecord, generation uint32) bool {
	for {
		current := root.valueQuota.Load()
		currentGeneration := uint32(current >> 32)
		count := uint32(current)
		if currentGeneration != generation {
			if generation < currentGeneration {
				return false
			}
			if root.valueQuota.CompareAndSwap(current, uint64(generation)<<32|1) {
				return true
			}
			continue
		}
		if count >= MaxValuesPerRoot {
			return false
		}
		if root.valueQuota.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func releaseRootValue(root *rootRecord, generation uint32) {
	for {
		current := root.valueQuota.Load()
		if uint32(current>>32) != generation || uint32(current) == 0 {
			return
		}
		if root.valueQuota.CompareAndSwap(current, current-1) {
			return
		}
	}
}

func (o *Owner) putWindow(key Key, rootID uint16, rootGen uint32) bool {
	if !validKey(key) || rootID >= MaxRootsPerOwner {
		o.owner.drops.full.Add(1)
		return false
	}
	record := o.owner
	if !record.rootsMu.TryRLock() {
		record.drops.contention.Add(1)
		return false
	}
	root := &record.roots[rootID]
	if root.generation.Load() != rootGen || root.setGen != rootGen {
		record.rootsMu.RUnlock() // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
		record.drops.stale.Add(1)
		return false
	}
	offset, valid := inWindow(key.Pointer, key.Length, root.base, root.span)
	record.rootsMu.RUnlock() // +checklocksforce: TryRLock.
	if !valid {
		record.drops.full.Add(1)
		return false
	}

	hash := keyHash(key)
	shard := &o.store.shards[shardIndex(hash)]
	if !shard.mu.TryLock() {
		record.drops.contention.Add(1)
		return false
	}
	defer shard.mu.Unlock() // +checklocksforce: TryLock.
	if !o.alive() {
		record.drops.late.Add(1)
		return false
	}

	start := initialSlot(hash)
	firstTombstone := -1
	for probe := 0; probe < ProbeLimit; probe++ {
		index := (start + uint8(probe)) % SlotsPerShard
		slot := &shard.slots[index]
		switch slot.pointer {
		case 0:
			target := index
			if firstTombstone >= 0 {
				target = uint8(firstTombstone)
			}
			return o.insertWindow(&shard.slots[target], shard, key, offset, rootID, rootGen, probe+1, firstTombstone >= 0)
		case tombstone:
			if firstTombstone < 0 {
				firstTombstone = int(index)
			}
			continue
		}
		if o.store.stale(slot) && o.store.reclaim(slot) {
			slot.pointer = tombstone
			slot.ownerGen = 0
			shard.tombstones++
			if firstTombstone < 0 {
				firstTombstone = int(index)
			}
			continue
		}
		if slot.pointer == key.Pointer && slot.length == key.Length && slot.kind == key.Kind && slot.ownerIdx == o.index && slot.ownerGen == o.gen {
			if slot.rootID != rootID || slot.rootGen != rootGen {
				newRoot := &o.owner.roots[rootID]
				if newRoot.generation.Load() != rootGen || !reserveRootValue(newRoot, rootGen) {
					o.owner.drops.full.Add(1)
					return false
				}
				if slot.rootID < MaxRootsPerOwner {
					releaseRootValue(&o.owner.roots[slot.rootID], slot.rootGen)
				}
			}
			slot.rootID = rootID
			slot.rootGen = rootGen
			slot.rootOff = offset
			o.recordProbe(shard, probe+1)
			return true
		}
	}
	// Reaching the probe bound does not prove that this key is absent beyond the
	// window. Inserting into a tombstone could create a duplicate owner/key slot.
	record.drops.full.Add(1)
	return false
}

func (o *Owner) insertWindow(slot *valueSlot, shard *shard, key Key, offset uint32, rootID uint16, rootGen uint32, probes int, reused bool) bool {
	root := &o.owner.roots[rootID]
	if !reserveInt32(&o.owner.values, RequestValueLimit) {
		o.owner.drops.full.Add(1)
		return false
	}
	if !reserveInt32(&o.store.values, ProcessValueLimit) {
		o.owner.values.Add(-1)
		o.owner.drops.full.Add(1)
		return false
	}
	// Reserve the generation quota last. A concurrent generation claim can now
	// bulk-subtract only reservations whose value counters are already owned.
	if root.generation.Load() != rootGen || !reserveRootValue(root, rootGen) {
		o.store.values.Add(-1)
		o.owner.values.Add(-1)
		o.owner.drops.full.Add(1)
		return false
	}
	*slot = valueSlot{
		pointer: key.Pointer, length: key.Length, kind: key.Kind,
		ownerIdx: o.index, ownerGen: o.gen, rootID: rootID, rootGen: rootGen, rootOff: offset,
	}
	if reused && shard.tombstones > 0 {
		shard.tombstones--
	}
	o.recordProbe(shard, probes)
	if shard.tombstones >= compactionThreshold {
		o.store.compact(shard)
	}
	return true
}

func (s *Store) stale(slot *valueSlot) bool {
	if slot.ownerIdx >= MaxOwners {
		return true
	}
	owner := &s.owners[slot.ownerIdx]
	if owner.generation.Load() != slot.ownerGen || ownerState(owner.state.Load()) == stateDead {
		return true
	}
	if slot.rootID >= MaxRootsPerOwner {
		return true
	}
	return owner.roots[slot.rootID].generation.Load() != slot.rootGen
}

func (s *Store) reclaim(slot *valueSlot) bool {
	if slot.ownerIdx >= MaxOwners {
		return true
	}
	owner := &s.owners[slot.ownerIdx]
	if owner.generation.Load() != slot.ownerGen || ownerState(owner.state.Load()) == stateDead {
		return true
	}
	if !owner.lifecycleMu.TryRLock() {
		return false
	}
	defer owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
	if owner.generation.Load() != slot.ownerGen {
		return true
	}
	if ownerState(owner.state.Load()) != stateActive || slot.rootID >= MaxRootsPerOwner {
		return false
	}
	root := &owner.roots[slot.rootID]
	if root.generation.Load() == slot.rootGen {
		return false
	}
	owner.drops.stale.Add(1)
	// claimMutation already bulk-reconciled the prior generation's value count.
	// Never decrement counters or the current generation's quota here.
	return true
}

func (o *Owner) recordProbe(shard *shard, probes int) {
	shard.probeSum += uint64(probes)
	shard.probeN++
	if uint8(probes) > shard.probeMax {
		shard.probeMax = uint8(probes)
	}
}

func (s *Store) compact(shard *shard) {
	var candidate [SlotsPerShard]valueSlot
	for i := range shard.slots {
		slot := shard.slots[i]
		if slot.pointer == 0 || slot.pointer == tombstone {
			continue
		}
		if slot.ownerIdx >= MaxOwners {
			continue
		}
		owner := &s.owners[slot.ownerIdx]
		if owner.generation.Load() != slot.ownerGen || ownerState(owner.state.Load()) == stateDead {
			continue
		}
		hash := keyHash(Key{Pointer: slot.pointer, Length: slot.length, Kind: slot.kind})
		start := initialSlot(hash)
		placed := false
		for probe := 0; probe < ProbeLimit; probe++ {
			index := (start + uint8(probe)) % SlotsPerShard
			if candidate[index].pointer == 0 {
				candidate[index] = slot
				placed = true
				break
			}
		}
		if !placed {
			s.compactAborts.Add(1)
			return
		}
	}
	shard.slots = candidate
	shard.tombstones = 0
	s.compactions.Add(1)
}

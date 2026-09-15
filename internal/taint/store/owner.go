// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

// Owner is a generation-captured request handle. A non-nil disabled handle is
// returned when capacity or acquisition contention prevents tracking.
type Owner struct {
	store    *Store
	owner    *owner
	index    uint8
	gen      uint64
	disabled bool
}

// Acquire obtains one of the fixed owner slots without waiting. The returned
// handle is always non-nil; Disabled reports whether it can track values.
func (s *Store) Acquire() *Owner {
	if s == nil {
		return &Owner{disabled: true}
	}
	if !s.ownerMu.TryLock() {
		s.acquireDrops.Add(1)
		return &Owner{store: s, disabled: true}
	}
	defer s.ownerMu.Unlock() // +checklocksforce: TryLock.
	for i := range s.owners {
		record := &s.owners[i]
		state := ownerState(record.state.Load())
		if state != stateUnused && state != stateDead {
			continue
		}
		if !record.writersMu.TryLock() {
			continue
		}
		record.writerVersion.Add(1)
		if record.writerCount > 0 {
			delta := -int32(record.writerCount)
			s.addWriterStates(delta)
		}
		clear(record.writers[:])
		for writerIndex := range record.writerPointers {
			record.writerPointers[writerIndex].Store(0)
		}
		record.writerCount = 0
		record.writerDirty.Store(false)
		record.writerVersion.Add(1)
		record.writersMu.Unlock() // +checklocksforce: TryLock.
		generation := record.generation.Add(1)
		record.id.Store(s.nextOwnerID.Add(1))
		record.charged.Store(0)
		record.values.Store(0)
		record.rootCount.Store(0)
		resetDropCounters(&record.drops)
		record.state.Store(uint32(stateActive))
		return &Owner{store: s, owner: record, index: uint8(i), gen: generation}
	}
	s.acquireDrops.Add(1)
	return &Owner{store: s, disabled: true}
}

// Disabled reports whether this handle cannot track data.
func (o *Owner) Disabled() bool {
	return o == nil || o.disabled || o.owner == nil || o.store == nil
}

// ID returns the process-unique owner ID, or zero for a disabled handle.
func (o *Owner) ID() uint64 {
	if o.Disabled() {
		return 0
	}
	return o.owner.id.Load()
}

// Generation returns the captured owner-slot generation.
func (o *Owner) Generation() uint64 {
	if o == nil {
		return 0
	}
	return o.gen
}

// Index returns the fixed process owner-slot index.
func (o *Owner) Index() (uint8, bool) {
	if o.Disabled() || o.index >= MaxOwners {
		return 0, false
	}
	return o.index, true
}

// Charged returns this owner's charged root bytes.
func (o *Owner) Charged() int64 {
	if o.Disabled() {
		return 0
	}
	return o.owner.charged.Load()
}

// Values returns value slots charged to this owner's live root generations.
// Superseded pointer-free slots are reclaimed lazily and are not counted.
func (o *Owner) Values() int32 {
	if o.Disabled() {
		return 0
	}
	return o.owner.values.Load()
}

// RecordBytesDrop records one byte-root rejection for an active owner.
func (o *Owner) RecordBytesDrop() {
	if o != nil && !o.Disabled() {
		o.owner.drops.bytes.Add(1)
	}
}

// Counters returns this owner's bounded-loss counters.
func (o *Owner) Counters() Counters {
	if o.Disabled() {
		return Counters{}
	}
	return snapshotDrops(&o.owner.drops)
}

func (o *Owner) alive() bool {
	return !o.Disabled() && o.gen == o.owner.generation.Load() && ownerState(o.owner.state.Load()) == stateActive
}

func (o *Owner) beginWrite() bool {
	if o.Disabled() {
		return false
	}
	if o.gen != o.owner.generation.Load() {
		o.owner.drops.disabled.Add(1)
		return false
	}
	if !o.owner.lifecycleMu.TryRLock() {
		o.owner.drops.contention.Add(1)
		return false
	}
	if !o.alive() {
		o.owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
		o.owner.drops.late.Add(1)
		return false
	}
	return true
}

func (o *Owner) endWrite() {
	o.owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
}

// Finish synchronously releases all strong roots and reconciles counters. It is
// idempotent and cannot finish a later generation that reused the owner slot.
func (o *Owner) Finish() {
	if o.Disabled() || o.gen != o.owner.generation.Load() {
		return
	}
	record := o.owner
	if !record.state.CompareAndSwap(uint32(stateActive), uint32(stateFinishing)) {
		return
	}
	record.lifecycleMu.Lock()
	defer record.lifecycleMu.Unlock()

	// Clear every writer anchor and release its capacity charge before the
	// root-charge swap below. The swap then sees only root charges, so the
	// process charge is never double-subtracted.
	record.writersMu.Lock()
	writerCharged := releaseWritersForFinishLocked(o.store, record)
	record.writerCount = 0
	record.writerDirty.Store(false)
	record.writersMu.Unlock()
	if writerCharged != 0 {
		record.charged.Add(-writerCharged)
		o.store.charged.Add(-writerCharged)
	}

	record.rootsMu.Lock()
	o.store.overflowMu.Lock()
	for i := range record.roots {
		root := &record.roots[i]
		if root.generation.Load() == 0 {
			continue
		}
		if root.overflow != 0 {
			o.store.freeOverflowLocked(root.overflow)
		}
		root.stringAnchor = ""
		root.bytesAnchor = nil
		root.base = 0
		root.span = 0
		root.setGen = 0
		root.overflow = 0
		root.count = 0
		root.limit = 0
		clear(root.inline[:])
		root.valueQuota.Store(0)
		root.generation.Store(0)
	}
	o.store.overflowMu.Unlock()
	record.rootNext = 0
	record.rootFreeN = 0
	record.rootCount.Store(0)
	charged := record.charged.Swap(0)
	values := record.values.Swap(0)
	record.rootsMu.Unlock()

	o.store.charged.Add(-charged)
	o.store.values.Add(-values)
	o.store.addOperatorValues(-values)
	record.bindings.reset()
	record.state.Store(uint32(stateDead))
}

func resetDropCounters(c *dropCounters) {
	c.full.Store(0)
	c.bytes.Store(0)
	c.ranges.Store(0)
	c.contention.Store(0)
	c.late.Store(0)
	c.stale.Store(0)
	c.disabled.Store(0)
	c.oneByte.Store(0)
	c.fanout.Store(0)
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import "github.com/DataDog/dd-iast-go/internal/taint/ranges"

type preparedRanges struct {
	inline    [GuaranteedRanges]ranges.Range
	overflow  uint16
	count     uint8
	limit     ranges.Limit
	truncated bool
}

// PublishBytesMutation publishes root-relative provenance after an in-place
// byte mutation and records the result window. value must still start at the
// managed root base and remain within its charged capacity.
//
// After this method claims the current generation, publication failure leaves
// that generation invalid because the application mutation has already
// occurred. Returning false never restores stale pre-mutation provenance.
func (o *Owner) PublishBytesMutation(ref RootRef, value []byte, set *ranges.Set) (RootRef, bool) {
	if ref.ID >= MaxRootsPerOwner || !o.beginWrite() {
		return RootRef{}, false
	}
	defer o.endWrite()
	generation, claimed := o.claimMutation(ref)
	if !claimed {
		return RootRef{}, false
	}
	if set == nil || len(value) == 0 || len(value) > MaxRootBytes || cap(value) > MaxRootBytes {
		return RootRef{}, false
	}
	key, ok := BytesKey(value)
	if !ok || !set.ValidFor(uint32(cap(value))) {
		o.owner.drops.ranges.Add(1)
		return RootRef{}, false
	}
	prepared := o.prepareRanges(set)
	if !o.owner.rootsMu.TryLock() {
		if prepared.overflow != 0 {
			o.store.freeOverflow(prepared.overflow)
		}
		o.owner.drops.contention.Add(1)
		return RootRef{}, false
	}
	root := &o.owner.roots[ref.ID]
	if root.generation.Load() != generation || root.bytesAnchor == nil || root.base != key.Pointer || root.span != uint32(cap(value)) {
		o.owner.rootsMu.Unlock() // +checklocksforce: TryLock. // +checklocksforce: TryLock.
		if prepared.overflow != 0 {
			o.store.freeOverflow(prepared.overflow)
		}
		return RootRef{}, false
	}
	oldOverflow := root.overflow
	root.bytesAnchor = value
	root.overflow = prepared.overflow
	root.count = prepared.count
	root.limit = prepared.limit
	root.inline = prepared.inline
	root.setGen = generation
	root.valueQuota.Store(uint64(generation) << 32)
	o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
	if oldOverflow != 0 {
		o.store.freeOverflow(oldOverflow)
	}
	if prepared.truncated {
		o.owner.drops.ranges.Add(1)
	}
	if !o.putWindow(key, ref.ID, generation) {
		return RootRef{}, false
	}
	return RootRef{ID: ref.ID, Generation: generation}, true
}

func (o *Owner) claimMutation(ref RootRef) (uint32, bool) {
	if o.Disabled() || ref.ID >= MaxRootsPerOwner || ref.Generation == 0 {
		return 0, false
	}
	next := ref.Generation + 1
	if next == 0 {
		next = 1
	}
	root := &o.owner.roots[ref.ID]
	if !root.generation.CompareAndSwap(ref.Generation, next) {
		return 0, false
	}
	previousQuota := root.valueQuota.Swap(uint64(next) << 32)
	if uint32(previousQuota>>32) == ref.Generation {
		count := int32(uint32(previousQuota))
		o.owner.values.Add(-count)
		o.store.values.Add(-count)
		o.store.addOperatorValues(-count)
	}
	return next, true
}

func (o *Owner) prepareRanges(set *ranges.Set) preparedRanges {
	var all [MaxRanges]ranges.Range
	count := set.CopyTo(all[:])
	prepared := preparedRanges{count: uint8(count), limit: set.Limit()}
	copy(prepared.inline[:], all[:min(count, GuaranteedRanges)])
	if count <= GuaranteedRanges {
		return prepared
	}
	prepared.overflow = o.store.allocateOverflow()
	if prepared.overflow == 0 {
		prepared.count = GuaranteedRanges
		prepared.truncated = true
		return prepared
	}
	copy(o.store.overflow[prepared.overflow-1].ranges[:], all[GuaranteedRanges:count])
	return prepared
}

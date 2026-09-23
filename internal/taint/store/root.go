// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// RootRef identifies one owner-local root generation.
type RootRef struct {
	ID         uint16
	Generation uint32
}

// TaintString clones value into a managed root and taints the complete clone.
func (o *Owner) TaintString(value string, source ranges.SourceID) (string, RootRef, bool) {
	if !o.beginWrite() {
		return value, RootRef{}, false
	}
	defer o.endWrite()
	if len(value) < 2 {
		o.owner.drops.oneByte.Add(1)
		return value, RootRef{}, false
	}
	if len(value) > MaxRootBytes {
		o.owner.drops.bytes.Add(1)
		return value, RootRef{}, false
	}
	charge := sizeClass(len(value))
	rootID, ok := o.reserveRootSlot(charge)
	if !ok {
		return value, RootRef{}, false
	}
	clone := strings.Clone(value)
	key, valid := StringKey(clone)
	if !valid {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.Limit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(clone)), SourceID: source}}, uint32(len(clone))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	generation, ok := o.publishRoot(rootID, key.Pointer, uint32(len(clone)), charge, clone, nil, &set)
	if !ok || !o.putWindow(key, rootID, generation) {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	return clone, RootRef{ID: rootID, Generation: generation}, true
}

// TaintSourceString publishes a new source value and returns managed metadata.
// The source table must retain managedName for exactly the root lifetime; its
// allocation is included in the root charge.
func (o *Owner) TaintSourceString(value, name string, source ranges.SourceID) (managed, managedName string, ref RootRef, ok bool) {
	if !o.beginWrite() {
		return value, "", RootRef{}, false
	}
	defer o.endWrite()
	if len(value) < 2 {
		o.owner.drops.oneByte.Add(1)
		return value, "", RootRef{}, false
	}
	if len(value) > MaxRootBytes || len(name) > MaxRootBytes {
		o.owner.drops.bytes.Add(1)
		return value, "", RootRef{}, false
	}
	charge := sizeClass(len(value)) + sizeClass(len(name))
	rootID, reserved := o.reserveRootSlot(charge)
	if !reserved {
		return value, "", RootRef{}, false
	}
	managed = strings.Clone(value)
	managedName = strings.Clone(name)
	key, valid := StringKey(managed)
	if !valid {
		o.rollbackRoot(rootID, charge)
		return value, "", RootRef{}, false
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.Limit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(managed)), SourceID: source}}, uint32(len(managed))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, "", RootRef{}, false
	}
	generation, published := o.publishRoot(rootID, key.Pointer, uint32(len(managed)), charge, managed, nil, &set)
	if !published || !o.putWindow(key, rootID, generation) {
		o.rollbackRoot(rootID, charge)
		return value, "", RootRef{}, false
	}
	return managed, managedName, RootRef{ID: rootID, Generation: generation}, true
}

// TaintBytes clones value into a managed complete backing allocation and taints
// the bytes in its current length. Capacity is charged and bounded.
func (o *Owner) TaintBytes(value []byte, source ranges.SourceID) ([]byte, RootRef, bool) {
	if !o.beginWrite() {
		return value, RootRef{}, false
	}
	defer o.endWrite()
	if len(value) < 2 {
		o.owner.drops.oneByte.Add(1)
		return value, RootRef{}, false
	}
	if len(value) > MaxRootBytes || cap(value) > MaxRootBytes {
		o.owner.drops.bytes.Add(1)
		return value, RootRef{}, false
	}
	charge := sizeClass(cap(value))
	rootID, ok := o.reserveRootSlot(charge)
	if !ok {
		return value, RootRef{}, false
	}
	clone := make([]byte, len(value), cap(value))
	copy(clone, value)
	key, valid := BytesKey(clone)
	if !valid {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.Limit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(clone)), SourceID: source}}, uint32(cap(clone))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	generation, ok := o.publishRoot(rootID, key.Pointer, uint32(cap(clone)), charge, "", clone, &set)
	if !ok || !o.putWindow(key, rootID, generation) {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	return clone, RootRef{ID: rootID, Generation: generation}, true
}

// TaintSourceBytes publishes a mutable source value and returns immutable,
// managed source metadata. The source table must retain managedName and
// managedValue for exactly the root lifetime; both allocations are included in
// the root charge.
func (o *Owner) TaintSourceBytes(value []byte, name string, source ranges.SourceID) (managed []byte, managedName, managedValue string, ref RootRef, ok bool) {
	if !o.beginWrite() {
		return value, "", "", RootRef{}, false
	}
	defer o.endWrite()
	if len(value) < 2 {
		o.owner.drops.oneByte.Add(1)
		return value, "", "", RootRef{}, false
	}
	if len(value) > MaxRootBytes || cap(value) > MaxRootBytes || len(name) > MaxRootBytes {
		o.owner.drops.bytes.Add(1)
		return value, "", "", RootRef{}, false
	}
	charge := sizeClass(cap(value)) + sizeClass(len(name)) + sizeClass(len(value))
	rootID, reserved := o.reserveRootSlot(charge)
	if !reserved {
		return value, "", "", RootRef{}, false
	}
	managed = make([]byte, len(value), cap(value))
	copy(managed, value)
	managedName = strings.Clone(name)
	managedValue = string(value)
	key, valid := BytesKey(managed)
	if !valid {
		o.rollbackRoot(rootID, charge)
		return value, "", "", RootRef{}, false
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.Limit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(managed)), SourceID: source}}, uint32(cap(managed))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, "", "", RootRef{}, false
	}
	generation, published := o.publishRoot(rootID, key.Pointer, uint32(cap(managed)), charge, "", managed, &set)
	if !published || !o.putWindow(key, rootID, generation) {
		o.rollbackRoot(rootID, charge)
		return value, "", "", RootRef{}, false
	}
	return managed, managedName, managedValue, RootRef{ID: rootID, Generation: generation}, true
}

// AdoptSourceBytes adopts an audited complete mutable allocation and returns
// immutable source metadata. Value must start at its allocation base, and its
// capacity must describe the complete retained allocation. Later writes require
// normal root-generation invalidation. The source table must retain managedName
// and managedValue for exactly the root lifetime; both are included in the
// charge.
func (o *Owner) AdoptSourceBytes(value []byte, name string, source ranges.SourceID) (managedName, managedValue string, ref RootRef, ok bool) {
	if !o.beginWrite() {
		return "", "", RootRef{}, false
	}
	defer o.endWrite()
	if len(value) < 2 {
		o.owner.drops.oneByte.Add(1)
		return "", "", RootRef{}, false
	}
	if len(value) > MaxRootBytes || cap(value) > MaxRootBytes || len(name) > MaxRootBytes {
		o.owner.drops.bytes.Add(1)
		return "", "", RootRef{}, false
	}
	charge := sizeClass(cap(value)) + sizeClass(len(name)) + sizeClass(len(value))
	rootID, reserved := o.reserveRootSlot(charge)
	if !reserved {
		return "", "", RootRef{}, false
	}
	managedName = strings.Clone(name)
	managedValue = string(value)
	key, valid := BytesKey(value)
	if !valid {
		o.rollbackRoot(rootID, charge)
		return "", "", RootRef{}, false
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.Limit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(value)), SourceID: source}}, uint32(cap(value))).Valid {
		o.rollbackRoot(rootID, charge)
		return "", "", RootRef{}, false
	}
	generation, published := o.publishRoot(rootID, key.Pointer, uint32(cap(value)), charge, "", value, &set)
	if !published || !o.putWindow(key, rootID, generation) {
		o.rollbackRoot(rootID, charge)
		return "", "", RootRef{}, false
	}
	return managedName, managedValue, RootRef{ID: rootID, Generation: generation}, true
}

// AdoptString adopts an audited complete allocation without cloning it. The
// caller must prove that value starts at the allocation base; an interior
// substring can retain more memory than the store charges and must not be used.
func (o *Owner) AdoptString(value string, set *ranges.Set) (RootRef, bool) {
	key, ok := StringKey(value)
	if !ok || len(value) < 2 || len(value) > MaxRootBytes {
		return RootRef{}, false
	}
	return o.adopt(key, uint32(len(value)), sizeClass(len(value)), value, nil, set)
}

// AdoptBytes adopts an audited complete allocation without cloning it. The
// caller must prove that value starts at the allocation base; capacity is the
// retained span and charged size.
func (o *Owner) AdoptBytes(value []byte, set *ranges.Set) (RootRef, bool) {
	key, ok := BytesKey(value)
	if !ok || len(value) < 2 || len(value) > MaxRootBytes || cap(value) > MaxRootBytes {
		return RootRef{}, false
	}
	return o.adopt(key, uint32(cap(value)), sizeClass(cap(value)), "", value, set)
}

func (o *Owner) adopt(key Key, span uint32, charge int64, stringAnchor string, bytesAnchor []byte, set *ranges.Set) (RootRef, bool) {
	if !o.beginWrite() {
		return RootRef{}, false
	}
	defer o.endWrite()
	if set == nil || !set.ValidFor(span) {
		o.owner.drops.ranges.Add(1)
		return RootRef{}, false
	}
	rootID, ok := o.reserveRootSlot(charge)
	if !ok {
		return RootRef{}, false
	}
	generation, ok := o.publishRoot(rootID, key.Pointer, span, charge, stringAnchor, bytesAnchor, set)
	if !ok || !o.putWindow(key, rootID, generation) {
		o.rollbackRoot(rootID, charge)
		return RootRef{}, false
	}
	return RootRef{ID: rootID, Generation: generation}, true
}

// Derive records a managed substring or subslice window. key must be inside the
// referenced root allocation.
func (o *Owner) Derive(key Key, root RootRef) bool {
	if !o.beginWrite() {
		return false
	}
	defer o.endWrite()
	return o.putWindow(key, root.ID, root.Generation)
}

func (o *Owner) reserveRootSlot(charge int64) (uint16, bool) {
	if charge <= 0 || charge > MaxRootChargeBytes {
		o.owner.drops.bytes.Add(1)
		return 0, false
	}
	if !o.owner.rootsMu.TryLock() {
		o.owner.drops.contention.Add(1)
		return 0, false
	}
	defer o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
	if o.owner.rootCount.Load() >= MaxRootsPerOwner {
		o.owner.drops.full.Add(1)
		return 0, false
	}
	var rootID uint16
	if o.owner.rootFreeN > 0 {
		o.owner.rootFreeN--
		rootID = o.owner.rootFree[o.owner.rootFreeN]
	} else if o.owner.rootNext < MaxRootsPerOwner {
		rootID = o.owner.rootNext
		o.owner.rootNext++
	} else {
		o.owner.drops.full.Add(1)
		return 0, false
	}
	if !reserveInt64(&o.owner.charged, charge, RequestRootBytes) {
		o.owner.rootFree[o.owner.rootFreeN] = rootID
		o.owner.rootFreeN++
		o.owner.drops.bytes.Add(1)
		return 0, false
	}
	if !reserveInt64(&o.store.charged, charge, ProcessRootBytes) {
		o.owner.charged.Add(-charge)
		o.owner.rootFree[o.owner.rootFreeN] = rootID
		o.owner.rootFreeN++
		o.owner.drops.bytes.Add(1)
		return 0, false
	}
	o.owner.rootCount.Add(1)
	return rootID, true
}

func (o *Owner) publishRoot(rootID uint16, base uintptr, span uint32, charge int64, stringAnchor string, bytesAnchor []byte, set *ranges.Set) (uint32, bool) {
	if !o.owner.rootsMu.TryLock() {
		o.owner.drops.contention.Add(1)
		return 0, false
	}
	defer o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
	root := &o.owner.roots[rootID]
	generation := root.generation.Load() + 1
	if generation == 0 {
		generation = 1
	}
	root.stringAnchor = stringAnchor
	root.bytesAnchor = bytesAnchor
	root.base = base
	root.span = span
	root.valueQuota.Store(uint64(generation) << 32)
	truncated := o.publishRangesLocked(root, set, generation)
	if truncated {
		o.owner.drops.ranges.Add(1)
	}
	root.generation.Store(generation)
	return generation, true
}

func (o *Owner) publishRangesLocked(root *rootRecord, set *ranges.Set, generation uint32) bool {
	var all [MaxRanges]ranges.Range
	count := set.CopyTo(all[:])
	if count > MaxRanges {
		count = MaxRanges
	}
	limit := set.Limit()
	if count > GuaranteedRanges {
		block := o.store.allocateOverflow()
		if block == 0 {
			count = GuaranteedRanges
		} else {
			root.overflow = block
			copy(o.store.overflow[block-1].ranges[:], all[GuaranteedRanges:count])
		}
	}
	copy(root.inline[:], all[:min(count, GuaranteedRanges)])
	root.count = uint8(count)
	root.limit = limit
	root.setGen = generation
	return set.Len() > count
}

func (o *Owner) rollbackRoot(rootID uint16, charge int64) {
	if !o.owner.rootsMu.TryLock() {
		o.owner.drops.contention.Add(1)
		// The bounded reservation and any published anchor remain owned until
		// Finish reconciles the aggregate charge and clears every root.
		return
	}
	root := &o.owner.roots[rootID]
	if root.overflow != 0 {
		o.store.freeOverflow(root.overflow)
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
	o.owner.rootFree[o.owner.rootFreeN] = rootID
	o.owner.rootFreeN++
	o.owner.rootCount.Add(-1)
	o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
	o.owner.charged.Add(-charge)
	o.store.charged.Add(-charge)
}

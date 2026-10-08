// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"strings"
	"unsafe"

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
	if !ranges.AdoptCanonical(&set, ranges.ClampLimit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(clone)), SourceID: source}}, uint32(len(clone))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	generation, ok := o.publishRoot(rootID, key.Pointer, uint32(len(clone)), charge, clone, nil, &set, KindString)
	if !ok || !o.indexRoot(rootID, generation, key.Pointer, uint32(len(clone)), KindString) {
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
	if !ranges.AdoptCanonical(&set, ranges.ClampLimit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(managed)), SourceID: source}}, uint32(len(managed))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, "", RootRef{}, false
	}
	generation, published := o.publishRoot(rootID, key.Pointer, uint32(len(managed)), charge, managed, nil, &set, KindString)
	if !published || !o.indexRoot(rootID, generation, key.Pointer, uint32(len(managed)), KindString) {
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
	if !ranges.AdoptCanonical(&set, ranges.ClampLimit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(clone)), SourceID: source}}, uint32(cap(clone))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, RootRef{}, false
	}
	generation, ok := o.publishRoot(rootID, key.Pointer, uint32(cap(clone)), charge, "", clone, &set, KindBytes)
	if !ok || !o.indexRoot(rootID, generation, key.Pointer, uint32(cap(clone)), KindBytes) {
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
	if !ranges.AdoptCanonical(&set, ranges.ClampLimit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(managed)), SourceID: source}}, uint32(cap(managed))).Valid {
		o.rollbackRoot(rootID, charge)
		return value, "", "", RootRef{}, false
	}
	generation, published := o.publishRoot(rootID, key.Pointer, uint32(cap(managed)), charge, "", managed, &set, KindBytes)
	if !published || !o.indexRoot(rootID, generation, key.Pointer, uint32(cap(managed)), KindBytes) {
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
// charge. A second adoption of the same allocation by the same owner extends
// the first root (see "Extension" in the package doc) and returns its RootRef.
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
	key, valid := BytesKey(value)
	if !valid {
		return "", "", RootRef{}, false
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.ClampLimit(config.MaxRangeCount), []ranges.Range{{Length: uint32(len(value)), SourceID: source}}, uint32(cap(value))).Valid {
		return "", "", RootRef{}, false
	}
	existing, found, known := o.ownRoot(key.Pointer)
	if !known {
		o.owner.drops.contention.Add(1)
		return "", "", RootRef{}, false
	}
	if found {
		ref, ok = o.extendRoot(existing, key.Pointer, uint32(cap(value)), charge, "", value, &set)
		if !ok {
			return "", "", RootRef{}, false
		}
		return strings.Clone(name), string(value), ref, true
	}
	rootID, reserved := o.reserveRootSlot(charge)
	if !reserved {
		return "", "", RootRef{}, false
	}
	managedName = strings.Clone(name)
	managedValue = string(value)
	generation, published := o.publishRoot(rootID, key.Pointer, uint32(cap(value)), charge, "", value, &set, KindBytes)
	if !published || !o.indexRoot(rootID, generation, key.Pointer, uint32(cap(value)), KindBytes) {
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

// AdoptStringAlloc adopts an audited complete string allocation whose size is
// at most allocBound bytes. The span is len(value) and the charge is
// sizeClass(allocBound). It refuses allocBound values above MaxRootBytes or
// below len(value)+3.
func (o *Owner) AdoptStringAlloc(value string, allocBound int, set *ranges.Set) (RootRef, bool) {
	key, ok := StringKey(value)
	if !ok || len(value) < 2 {
		return RootRef{}, false
	}
	if allocBound > MaxRootBytes || allocBound < len(value)+3 {
		o.RecordBytesDrop()
		return RootRef{}, false
	}
	return o.adopt(key, uint32(len(value)), sizeClass(allocBound), value, nil, set)
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

// AdoptRunes adopts an audited complete []rune allocation without cloning it
// The caller must prove that value starts at the allocation base. The root uses
// the byte coordinates of the rune array: span and charge are 4*cap(value)
// bytes, and set must be valid for that span.
func (o *Owner) AdoptRunes(value []rune, set *ranges.Set) (RootRef, bool) {
	key, ok := RunesKey(value)
	if !ok {
		return RootRef{}, false
	}
	if cap(value) > MaxRootBytes/4 {
		o.RecordBytesDrop()
		return RootRef{}, false
	}
	span := 4 * cap(value)
	anchor := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(value))), span)
	return o.adopt(key, uint32(span), sizeClass(span), "", anchor, set)
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
	existing, found, known := o.ownRoot(key.Pointer)
	if !known {
		o.owner.drops.contention.Add(1)
		return RootRef{}, false
	}
	if found {
		return o.extendRoot(existing, key.Pointer, span, charge, stringAnchor, bytesAnchor, set)
	}
	rootID, ok := o.reserveRootSlot(charge)
	if !ok {
		return RootRef{}, false
	}
	generation, ok := o.publishRoot(rootID, key.Pointer, span, charge, stringAnchor, bytesAnchor, set, key.Kind)
	if !ok || !o.indexRoot(rootID, generation, key.Pointer, span, key.Kind) {
		o.rollbackRoot(rootID, charge)
		return RootRef{}, false
	}
	return RootRef{ID: rootID, Generation: generation}, true
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

// publishRoot stores a new root with indexed == false. No lookup can see it
// before indexRoot commits.
func (o *Owner) publishRoot(rootID uint16, base uintptr, span uint32, charge int64, stringAnchor string, bytesAnchor []byte, set *ranges.Set, kind Kind) (uint32, bool) {
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
	root.indexed = false
	root.kind = kind
	truncated := o.publishRangesLocked(root, set, generation)
	if truncated {
		o.owner.drops.ranges.Add(1)
	}
	root.generation.Store(generation)
	return generation, true
}

func (o *Owner) publishRangesLocked(root *rootRecord, set *ranges.Set, generation uint32) bool {
	truncated := o.storeRangesLocked(root, set)
	root.setGen = generation
	return truncated
}

// storeRangesLocked stores the ranges of set in root. It does not change the
// root generation or setGen. The caller holds rootsMu and frees the earlier
// overflow block of root.
func (o *Owner) storeRangesLocked(root *rootRecord, set *ranges.Set) bool {
	var all [MaxRanges]ranges.Range
	count := set.CopyTo(all[:])
	if count > MaxRanges {
		count = MaxRanges
	}
	limit := set.Limit()
	root.overflow = 0
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
	root.indexed = false
	root.kind = KindInvalid
	clear(root.inline[:])
	root.generation.Store(0)
	o.owner.rootFree[o.owner.rootFreeN] = rootID
	o.owner.rootFreeN++
	o.owner.rootCount.Add(-1)
	o.owner.rootsMu.Unlock() // +checklocksforce: TryLock.
	o.owner.charged.Add(-charge)
	o.store.charged.Add(-charge)
}

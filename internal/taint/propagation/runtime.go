// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// This file has the tainted-path callbacks of the runtime bridge. The bridge
// calls them only after a filter hit, in a function that recovers a panic.
// The runtime hook rules in the internal/taint/runtimebridge package doc give
// the full contract.
//
// Conversion rules:
//
//   - string(b) and []byte(s): the result gets the ranges of the input window.
//     A one-byte result is not tainted (string(b) of one byte returns shared
//     static memory, and a root has at least 2 bytes).
//   - []byte(s) and []rune(s): the result is a new mutable root. Writes that
//     dd-iast-go does not see (b[i] = x, copy, append in capacity) keep the
//     old ranges, so they can over-report. The string-to-slice switch
//     (DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED, on by default) turns these
//     two conversions off. It does not gate []byte(a + b).
//   - []rune values use the byte coordinates of the rune array: rune i is
//     bytes [4i, 4i+4). runes.go maps the ranges between the two forms.
//
// Contract (escape and GC): a callback reads operands and inputs only
// during the call, and only through store keys (a uintptr and a length). It
// never keeps them. It can keep the result, because the result is a fresh
// heap allocation from the runtime that starts at its allocation base: it
// adopts the result as a root, and it never clones it.
//
// The callbacks use store.RuntimeStore(), so they always use the store of the
// bridge filter and confirm function.
//
// The init function registers the callbacks. The runtime declarations aspect
// of iast/runtime must name this package in its links list (rule 6 of the
// runtime hook rules in the internal/taint/runtimebridge package doc).
// Orchestrion then imports it in the main package, so this init function
// runs also when no other code imports this package.

func init() {
	runtimebridge.Register(&runtimebridge.Callbacks{
		Concat:      runtimeConcat,
		ConcatBytes: runtimeConcatBytes,
		FromBytes:   runtimeFromBytes,
		ToBytes:     runtimeToBytes,
		FromRunes:   runtimeFromRunes,
		ToRunes:     runtimeToRunes,
	})
}

// runtimeResult is the result of a runtime operation: a string or a []byte.
type runtimeResult struct {
	str   string
	bytes []byte
}

func (r *runtimeResult) length() int {
	if r.bytes != nil {
		return len(r.bytes)
	}
	return len(r.str)
}

// tooLarge reports whether the store cannot adopt the result.
func (r *runtimeResult) tooLarge() bool {
	return r.length() > store.MaxRootBytes || cap(r.bytes) > store.MaxRootBytes
}

func (r *runtimeResult) adopt(owner *store.Owner, set *ranges.Set) bool {
	if r.bytes != nil {
		_, ok := owner.AdoptBytes(r.bytes, set)
		return ok
	}
	_, ok := owner.AdoptString(r.str, set)
	return ok
}

func (r *runtimeResult) pointer() uintptr {
	if r.bytes != nil {
		return uintptr(unsafe.Pointer(unsafe.SliceData(r.bytes)))
	}
	return uintptr(unsafe.Pointer(unsafe.StringData(r.str)))
}

func runtimeConcat(result string, operands []string) {
	runtimeConcatResult(&runtimeResult{str: result}, operands)
}

func runtimeConcatBytes(result []byte, operands []string) {
	if len(result) == 0 {
		return
	}
	runtimeConcatResult(&runtimeResult{bytes: result}, operands)
}

func runtimeConcatResult(result *runtimeResult, operands []string) {
	s := store.RuntimeStore()
	if s == nil || result.length() < 2 {
		return
	}
	// Identity: concatstrings returns the only non-empty operand. The
	// interior index already finds the taint of that operand.
	pointer := result.pointer()
	for _, operand := range operands {
		if len(operand) == result.length() && uintptr(unsafe.Pointer(unsafe.StringData(operand))) == pointer {
			return
		}
	}
	if result.tooLarge() {
		recordStringsBytesDrop(s, operands)
		return
	}
	if len(operands) > maxInputs {
		coarseConcatHit(s, result, operands)
		return
	}
	exactConcatHit(s, result, operands)
}

// concatOwner accumulates the ranges of one owner in a concatenation.
type concatOwner struct {
	ownerID   uint64
	ownerGen  uint64
	index     uint8
	limit     ranges.Limit
	valid     bool
	truncated bool // the range limit dropped a tail range
	set       ranges.Set
}

func (o *concatOwner) handle(s *store.Store) (store.Owner, bool) {
	identity := store.Entry{OwnerID: o.ownerID, OwnerGen: o.ownerGen, OwnerIndex: o.index}
	return identity.Handle(s)
}

// exactConcatHit composes, for each owner, the operand ranges shifted by the
// cumulative operand lengths, with one Lookup for each operand. It shares the
// result between at most store.MaxSnapshotOwners owners. An owner after that
// bound is a fanout drop. A range that the range limit of the owner drops is
// a ranges drop, recorded once for each owner.
//
//go:noinline
func exactConcatHit(s *store.Store, result *runtimeResult, operands []string) {
	var owners [store.MaxSnapshotOwners]concatOwner
	ownerCount := 0
	var dropped uint64 // owner indexes with a recorded fanout drop
	var offset uint64
	for _, operand := range operands {
		length := uint64(len(operand))
		if length == 0 {
			continue
		}
		if offset+length > uint64(result.length()) {
			return
		}
		key, ok := store.StringKey(operand)
		var snapshot store.Snapshot
		if ok && s.MayContain(key) && s.Lookup(key, &snapshot) {
			for i := 0; i < snapshot.Len(); i++ {
				entry, ok := snapshot.At(i)
				if !ok {
					continue
				}
				owner := findConcatOwner(owners[:ownerCount], entry)
				if owner == nil {
					if ownerCount >= len(owners) {
						recordFanout(s, entry, &dropped)
						continue
					}
					owner = &owners[ownerCount]
					ownerCount++
					owner.ownerID, owner.ownerGen, owner.index = entry.OwnerID, entry.OwnerGen, entry.OwnerIndex
					owner.limit = entry.Ranges.Limit()
					owner.valid = true
				}
				if !owner.valid {
					continue
				}
				var next ranges.Set
				outcome := ranges.Concat(&next, owner.limit, setPointer(&owner.set), uint32(offset), &entry.Ranges, uint32(length))
				if !outcome.Valid {
					owner.valid = false
					continue
				}
				owner.truncated = owner.truncated || outcome.Truncated
				owner.set = next
			}
		}
		offset += length
	}
	if offset != uint64(result.length()) {
		return
	}
	published := false
	for i := 0; i < ownerCount; i++ {
		owner := &owners[i]
		if !owner.valid || owner.set.Len() == 0 {
			continue
		}
		handle, ok := owner.handle(s)
		if !ok {
			continue
		}
		if owner.truncated {
			handle.RecordRangesDrop()
		}
		if result.adopt(&handle, &owner.set) {
			published = true
		}
	}
	if published {
		recordExecuted()
	}
}

func findConcatOwner(owners []concatOwner, entry *store.Entry) *concatOwner {
	for i := range owners {
		owner := &owners[i]
		if owner.index == entry.OwnerIndex && owner.ownerGen == entry.OwnerGen && owner.ownerID == entry.OwnerID {
			return &owners[i]
		}
	}
	return nil
}

// recordFanout records one fanout drop for the owner of entry, once for each
// owner.
func recordFanout(s *store.Store, entry *store.Entry, dropped *uint64) {
	bit := uint64(1) << (entry.OwnerIndex % 64)
	if *dropped&bit != 0 {
		return
	}
	*dropped |= bit
	if handle, ok := entry.Handle(s); ok {
		handle.RecordFanoutDrop()
	}
}

// coarseInterval is the position in the result of one or more touching
// ranges of one owner.
type coarseInterval struct {
	start, end uint32
}

// coarseConcatOwner accumulates the coarse provenance of one owner in a
// concatenation with more than maxInputs operands. It has at most limit
// intervals, so its size is fixed.
type coarseConcatOwner struct {
	coarseOwner
	limit     ranges.Limit
	count     int
	intervals [ranges.HardLimit]coarseInterval
}

// add records the interval [start, end) of the result. The operands come in
// result order, and the ranges of one operand are sorted and do not overlap,
// so start is never before the end of the last interval. An interval that
// touches the last one extends it: all ranges of an owner have the same
// source and marks, so they merge. An interval with a gap before it does not
// merge, because the gap can contain bytes of a different owner. When the
// range limit is full, add drops the interval. The caller records one ranges
// drop for each owner, which also counts this truncation.
func (o *coarseConcatOwner) add(start, end uint32) {
	if start >= end {
		return
	}
	if o.count > 0 {
		last := &o.intervals[o.count-1]
		if start < last.end {
			// An overlap is not possible for sorted, disjoint ranges.
			// Ignore the interval, so that the intervals stay sorted.
			return
		}
		if start == last.end {
			last.end = end
			return
		}
	}
	if o.count >= int(o.limit) || o.count >= len(o.intervals) {
		return
	}
	o.intervals[o.count] = coarseInterval{start: start, end: end}
	o.count++
}

func findCoarseConcatOwner(owners []coarseConcatOwner, entry *store.Entry) *coarseConcatOwner {
	for i := range owners {
		owner := &owners[i]
		if owner.entry.OwnerIndex == entry.OwnerIndex && owner.entry.OwnerGen == entry.OwnerGen && owner.entry.OwnerID == entry.OwnerID {
			return owner
		}
	}
	return nil
}

// coarseConcatHit is the provenance of a concatenation with more than
// maxInputs operands (the exact path handles at most maxInputs). It scans all operands, not a
// prefix, so a taint in a late operand is not lost. It keeps at most
// store.MaxSnapshotOwners owners.
//
// Each owner gets its own ranges of each operand, shifted by the offset of
// the operand in the result. Ranges of the owner that touch merge. Thus a
// range of an owner never covers a byte that the owner does not taint, and a
// report for this owner masks the bytes of a different owner, also in a
// shared operand. All ranges of an owner have the source of its first range
// and the marks that all its ranges have. The range limit of the first match
// of the owner bounds the range count; the ranges after the limit are
// dropped. The function records one ranges drop for each owner, because the
// sources and marks are not exact.
//
//go:noinline
func coarseConcatHit(s *store.Store, result *runtimeResult, operands []string) {
	var owners [store.MaxSnapshotOwners]coarseConcatOwner
	ownerCount := 0
	var dropped uint64
	resultLength := uint64(result.length())
	var offset uint64
	for _, operand := range operands {
		length := uint64(len(operand))
		if length == 0 {
			continue
		}
		if offset+length > resultLength {
			return
		}
		start := offset
		offset += length
		key, ok := store.StringKey(operand)
		if !ok || !s.MayContain(key) {
			continue
		}
		var snapshot store.Snapshot
		if !s.Lookup(key, &snapshot) {
			continue
		}
		for i := 0; i < snapshot.Len(); i++ {
			entry, ok := snapshot.At(i)
			if !ok || entry.Ranges.Len() == 0 {
				continue
			}
			if !entry.Ranges.ValidFor(uint32(length)) {
				continue
			}
			owner := findCoarseConcatOwner(owners[:ownerCount], entry)
			if owner == nil {
				if ownerCount >= len(owners) {
					recordFanout(s, entry, &dropped)
					continue
				}
				owner = &owners[ownerCount]
				ownerCount++
				owner.entry = store.Entry{OwnerID: entry.OwnerID, OwnerGen: entry.OwnerGen, OwnerIndex: entry.OwnerIndex}
				owner.limit = entry.Ranges.Limit()
			}
			coarseAccumulate(&owner.coarseOwner, &entry.Ranges)
			for j := 0; j < entry.Ranges.Len(); j++ {
				r, ok := entry.Ranges.At(j)
				if !ok {
					continue
				}
				owner.add(uint32(start+uint64(r.Start)), uint32(start+uint64(r.Start)+uint64(r.Length)))
			}
		}
	}
	if offset != resultLength {
		return
	}
	published := false
	var raw [ranges.HardLimit]ranges.Range
	for i := 0; i < ownerCount; i++ {
		owner := &owners[i]
		if !owner.found || owner.count == 0 {
			continue
		}
		handle, ok := owner.entry.Handle(s)
		if !ok {
			continue
		}
		for j := 0; j < owner.count; j++ {
			interval := owner.intervals[j]
			raw[j] = ranges.Range{Start: interval.start, Length: interval.end - interval.start, SourceID: owner.source, Marks: owner.marks}
		}
		var set ranges.Set
		if !ranges.AdoptCanonical(&set, owner.limit, raw[:owner.count], uint32(resultLength)).Valid {
			continue
		}
		handle.RecordRangesDrop()
		if result.adopt(&handle, &set) {
			published = true
		}
	}
	if published {
		recordExecuted()
		recordCoarse()
		recordDropped()
	}
}

// recordStringsBytesDrop records a bytes drop for each owner of the operands,
// when the result is too large to be a root.
//
//go:noinline
func recordStringsBytesDrop(s *store.Store, operands []string) {
	var dropped uint64
	for _, operand := range operands {
		key, ok := store.StringKey(operand)
		if ok {
			recordKeyBytesDrop(s, key, &dropped)
		}
	}
	recordDropped()
}

func recordKeyBytesDrop(s *store.Store, key store.Key, dropped *uint64) {
	if !s.MayContain(key) {
		return
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return
	}
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		bit := uint64(1) << (entry.OwnerIndex % 64)
		if *dropped&bit != 0 {
			continue
		}
		*dropped |= bit
		if handle, ok := entry.Handle(s); ok {
			handle.RecordBytesDrop()
		}
	}
}

// runtimeFromBytes is the callback of string(b).
func runtimeFromBytes(result string, input []byte) {
	s := store.RuntimeStore()
	key, ok := store.BytesKey(input)
	if s == nil || !ok || len(result) < 2 || !s.MayContain(key) {
		return
	}
	if len(result) > store.MaxRootBytes {
		var dropped uint64
		recordKeyBytesDrop(s, key, &dropped)
		recordDropped()
		return
	}
	publishBytesToString(s, key, result)
}

// runtimeToBytes is the callback of []byte(s).
// The result is a new mutable bytes root: its ranges cover [0, len) and its
// span is cap(result).
func runtimeToBytes(result []byte, input string) {
	s := store.RuntimeStore()
	key, ok := store.StringKey(input)
	if s == nil || !ok || len(result) < 2 || !s.MayContain(key) {
		return
	}
	if len(result) > store.MaxRootBytes || cap(result) > store.MaxRootBytes {
		var dropped uint64
		recordKeyBytesDrop(s, key, &dropped)
		recordDropped()
		return
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return
	}
	published := false
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		var set ranges.Set
		if !ranges.Copy(&set, entry.Ranges.Limit(), &entry.Ranges, uint32(len(input))).Valid || !set.ValidFor(uint32(len(result))) {
			continue
		}
		if handle, ok := entry.Handle(s); ok {
			if _, ok := handle.AdoptBytes(result, &set); ok {
				published = true
			}
		}
	}
	if published {
		recordExecuted()
	}
}

// runtimeFromRunes is the callback of string(rs). The
// charge comes from len(input), which cannot change during the conversion:
// sizeClass(4*len(input)+3).
func runtimeFromRunes(result string, input []rune) {
	s := store.RuntimeStore()
	key, ok := store.RunesKey(input)
	if s == nil || !ok || len(result) < 2 || !s.MayContain(key) {
		return
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return
	}
	allocBound := 4*len(input) + 3
	published := false
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		var set ranges.Set
		if !runeRangesToString(&set, entry.Ranges.Limit(), &entry.Ranges, input, uint32(len(result))) || set.Len() == 0 {
			continue
		}
		if handle, ok := entry.Handle(s); ok {
			if _, ok := handle.AdoptStringAlloc(result, allocBound, &set); ok {
				published = true
			}
		}
	}
	if published {
		recordExecuted()
	}
}

// runtimeToRunes is the callback of []rune(s).
func runtimeToRunes(result []rune, input string) {
	s := store.RuntimeStore()
	key, ok := store.StringKey(input)
	if s == nil || !ok || len(result) == 0 || !s.MayContain(key) {
		return
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return
	}
	published := false
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		if !ok {
			continue
		}
		var set ranges.Set
		if !stringRangesToRunes(&set, entry.Ranges.Limit(), &entry.Ranges, input, len(result)) || set.Len() == 0 {
			continue
		}
		if handle, ok := entry.Handle(s); ok {
			if _, ok := handle.AdoptRunes(result, &set); ok {
				published = true
			}
		}
	}
	if published {
		recordExecuted()
	}
}

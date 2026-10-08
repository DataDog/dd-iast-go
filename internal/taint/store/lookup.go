// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
)

const MaxSnapshotOwners = 4

// Entry is an immutable owner-separated lookup result.
type Entry struct {
	OwnerID    uint64
	OwnerGen   uint64
	OwnerIndex uint8
	// Kind is the kind of the first adoption of the root. A lookup ignores
	// Key.Kind: a string view of a bytes root reads the same bytes.
	Kind Kind
	// WholeRoot is true when the key starts at the root base and has the
	// root span: the value is the complete root, not a window of it.
	WholeRoot bool
	Root      RootRef
	Ranges    ranges.Set
}

// Handle revalidates this entry against s and returns a live owner by value.
// It validates the store, owner index, owner generation, active state, and
// owner ID before returning. A mismatch returns a disabled zero handle, so a
// stale snapshot cannot publish into a reused slot. Numeric addresses remain
// comparison keys and are never converted back to pointers.
func (e *Entry) Handle(s *Store) (Owner, bool) {
	if s == nil || e == nil || e.OwnerIndex >= MaxOwners || e.OwnerID == 0 || e.OwnerGen == 0 {
		return Owner{}, false
	}
	record := &s.owners[e.OwnerIndex]
	if record.generation.Load() != e.OwnerGen || ownerState(record.state.Load()) != stateActive || record.id.Load() != e.OwnerID {
		return Owner{}, false
	}
	return Owner{store: s, owner: record, index: e.OwnerIndex, gen: e.OwnerGen}, true
}

// Snapshot is caller-owned fixed lookup storage.
type Snapshot struct {
	entries [MaxSnapshotOwners]Entry
	count   uint8
	partial bool
}

// Partial reports whether the lookup can have skipped the contribution of an
// owner: an index shard or an owner lock was contended, or the fan-out bound
// was reached. Then an owner that is not in the snapshot can have bytes in the
// value.
func (s *Snapshot) Partial() bool {
	return s != nil && s.partial
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
	s.partial = false
}

// MayContain reports whether a root can contain key. It reads only the two
// filter counters of the granule of key.Pointer (tier S first, then tier L),
// with no lock. A false result proves that no visible root contains key: every
// visible root is indexed and counted in the filter. Callers must use Lookup
// after a true result.
func (s *Store) MayContain(key Key) bool {
	if s == nil || !validKey(key) {
		return false
	}
	return runtimebridge.FilterHit(&s.filter, key.Pointer)
}

// IndexProbes returns the number of index shards that a Lookup of key reads:
// one for each tier whose filter counter is not zero. It is for telemetry and
// benchmarks, not for the propagation hot path.
func (s *Store) IndexProbes(key Key) int {
	if s == nil || !validKey(key) {
		return 0
	}
	probes := 0
	if s.filterHit(granuleKey(key.Pointer, false)) {
		probes++
	}
	if s.filterHit(granuleKey(key.Pointer, true)) {
		probes++
	}
	return probes
}

// Lookup copies complete live owner contributions for the value key into out:
// for each owner, the ranges of its root that contains key, sliced to the
// window of key. It never returns live root storage. The boolean is false only
// when an index shard read lock could not be acquired and no contribution was
// found; an acquired lookup with no match returns true and Len zero.
func (s *Store) Lookup(key Key, out *Snapshot) bool {
	if s == nil || out == nil || !validKey(key) {
		return false
	}
	out.reset()
	var candidates [maxProbeRefs]candidate
	count, acquired, overflow := s.probeBoth(key.Pointer, key.Length, &candidates)
	if !acquired {
		s.drops.contention.Add(1)
	}
	out.partial = !acquired || overflow
	for i := 0; i < count; i++ {
		s.lookupCandidate(key, candidates[i], out)
	}
	return acquired || out.count > 0
}

// lookupCandidate validates one copied ref (see "Lookup and validation" in the
// package doc) and appends its window ranges to out. It keeps one contribution
// for each owner.
func (s *Store) lookupCandidate(key Key, c candidate, out *Snapshot) {
	ref := c.ref
	if ref.ownerIdx >= MaxOwners || ref.rootID >= MaxRootsPerOwner {
		return
	}
	owner := &s.owners[ref.ownerIdx]
	for i := 0; i < int(out.count); i++ {
		if out.entries[i].OwnerIndex == ref.ownerIdx {
			owner.drops.dupOwner.Add(1)
			return
		}
	}
	if out.count >= MaxSnapshotOwners {
		owner.drops.fanout.Add(1)
		out.partial = true
		return
	}
	if !owner.lifecycleMu.TryRLock() {
		owner.drops.contention.Add(1)
		out.partial = true
		return
	}
	ownerGen := owner.generation.Load()
	if uint32(ownerGen) != ref.ownerGen || ownerState(owner.state.Load()) != stateActive {
		owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		return
	}
	if !owner.rootsMu.TryRLock() {
		owner.drops.contention.Add(1)
		out.partial = true
		owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		return
	}
	var window ranges.Set
	root := &owner.roots[ref.rootID]
	generation, valid := s.sliceRootLocked(root, c.base, key.Pointer, key.Length, &window)
	whole := key.Pointer == root.base && key.Length == root.span
	ownerID := owner.id.Load()
	owner.rootsMu.RUnlock()     // +checklocksforce: TryRLock.
	owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
	if !valid || window.Len() == 0 {
		return
	}
	entry := &out.entries[out.count]
	entry.OwnerID = ownerID
	entry.OwnerGen = ownerGen
	entry.OwnerIndex = ref.ownerIdx
	entry.Kind = ref.kind
	entry.WholeRoot = whole
	entry.Root = RootRef{ID: ref.rootID, Generation: generation}
	entry.Ranges = window
	out.count++
}

// validRootLocked checks that root is indexed, has the entry base, contains
// [p, p+n), and has valid ranges now. The caller holds rootsMu for reading.
func validRootLocked(root *rootRecord, base, p uintptr, n uint32) (uint32, uint32, bool) {
	if !root.indexed || root.base != base {
		return 0, 0, false
	}
	offset, inside := inWindow(p, n, base, root.span)
	if !inside {
		return 0, 0, false
	}
	generation := root.generation.Load()
	if generation == 0 || root.setGen != generation || root.count == 0 {
		return 0, 0, false
	}
	runHook(hookValidate, 0)
	return offset, generation, true
}

// rootRangesLocked copies the stored ranges of root into dst. The caller holds
// rootsMu.
func (s *Store) rootRangesLocked(root *rootRecord, dst *[MaxRanges]ranges.Range) int {
	count := int(root.count)
	inlineCount := min(count, GuaranteedRanges)
	copy(dst[:inlineCount], root.inline[:inlineCount])
	if count > GuaranteedRanges {
		if root.overflow == 0 {
			return GuaranteedRanges
		}
		copy(dst[GuaranteedRanges:count], s.overflow[root.overflow-1].ranges[:count-GuaranteedRanges])
	}
	return count
}

// sliceRootLocked writes the ranges of root in the window [p, p+n) to dst.
// The caller holds rootsMu for reading.
func (s *Store) sliceRootLocked(root *rootRecord, base, p uintptr, n uint32, dst *ranges.Set) (uint32, bool) {
	offset, generation, valid := validRootLocked(root, base, p, n)
	if !valid {
		return 0, false
	}
	var compact [MaxRanges]ranges.Range
	count := s.rootRangesLocked(root, &compact)
	var canonical ranges.Set
	if !ranges.AdoptCanonical(&canonical, root.limit, compact[:count], root.span).Valid {
		return 0, false
	}
	if !ranges.Slice(dst, root.limit, &canonical, root.span, offset, offset+n).Valid {
		return 0, false
	}
	return generation, root.generation.Load() == generation && root.setGen == generation
}

// ConfirmResult is the result of Store.Confirm. The runtime bridge owns the
// type, because its pre-checks call Confirm.
type ConfirmResult = runtimebridge.ConfirmResult

const (
	// ConfirmClean: no live root contains the value, or no range of the root
	// overlaps the value window.
	ConfirmClean = runtimebridge.ConfirmClean
	// ConfirmTainted: a live root contains the value and one of its ranges
	// overlaps the value window.
	ConfirmTainted = runtimebridge.ConfirmTainted
	// ConfirmUnknown: a TryRLock failed. A caller must treat the value as
	// tainted when a false "clean" answer can lose taint.
	ConfirmUnknown = runtimebridge.ConfirmUnknown
)

// Confirm reports whether the value [p, p+n) is tainted. It runs the interior
// probe and the validation of Lookup, then scans the root ranges for an overlap
// with the value window. It does not allocate, does not copy ranges, and never
// waits for a lock. It takes the data pointer as a uintptr, so it cannot keep
// the value live.
func (s *Store) Confirm(p uintptr, n uint32) ConfirmResult {
	if s == nil || p == 0 || n == 0 {
		return ConfirmClean
	}
	var candidates [maxProbeRefs]candidate
	count, acquired, _ := s.probeBoth(p, n, &candidates)
	result := ConfirmClean
	if !acquired {
		s.drops.preContention.Add(1)
		result = ConfirmUnknown
	}
	for i := 0; i < count; i++ {
		switch s.confirmCandidate(p, n, candidates[i]) {
		case ConfirmTainted:
			return ConfirmTainted
		case ConfirmUnknown:
			result = ConfirmUnknown
		}
	}
	return result
}

func (s *Store) confirmCandidate(p uintptr, n uint32, c candidate) ConfirmResult {
	ref := c.ref
	if ref.ownerIdx >= MaxOwners || ref.rootID >= MaxRootsPerOwner {
		return ConfirmClean
	}
	owner := &s.owners[ref.ownerIdx]
	if !owner.lifecycleMu.TryRLock() {
		owner.drops.preContention.Add(1)
		return ConfirmUnknown
	}
	if uint32(owner.generation.Load()) != ref.ownerGen || ownerState(owner.state.Load()) != stateActive {
		owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		return ConfirmClean
	}
	if !owner.rootsMu.TryRLock() {
		owner.drops.preContention.Add(1)
		owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		return ConfirmUnknown
	}
	result := ConfirmClean
	root := &owner.roots[ref.rootID]
	if offset, generation, valid := validRootLocked(root, c.base, p, n); valid {
		if s.overlapLocked(root, offset, offset+n) {
			result = ConfirmTainted
		}
		if root.generation.Load() != generation {
			// A mutation claimed the root during the scan. Its new ranges
			// are not published yet.
			result = ConfirmUnknown
		}
	}
	owner.rootsMu.RUnlock()     // +checklocksforce: TryRLock.
	owner.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
	return result
}

// overlapLocked reports whether a stored range of root overlaps [low, high).
// The caller holds rootsMu for reading.
func (s *Store) overlapLocked(root *rootRecord, low, high uint32) bool {
	count := int(root.count)
	for i := 0; i < min(count, GuaranteedRanges); i++ {
		if rangeOverlaps(root.inline[i], low, high) {
			return true
		}
	}
	if count > GuaranteedRanges && root.overflow != 0 {
		block := &s.overflow[root.overflow-1]
		for i := 0; i < count-GuaranteedRanges; i++ {
			if rangeOverlaps(block.ranges[i], low, high) {
				return true
			}
		}
	}
	return false
}

func rangeOverlaps(r ranges.Range, low, high uint32) bool {
	return r.Length != 0 && r.Start < high && uint64(r.Start)+uint64(r.Length) > uint64(low)
}

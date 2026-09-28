// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package store implements the bounded request-owned taint identity store.
// Numeric data addresses are comparison keys only and are never converted back
// to pointers. Strong managed roots are released synchronously when their owner
// finishes. Adoption APIs are only for audited results known to begin at their
// complete allocation base; ordinary callers must use cloning APIs.
package store

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// Kind identifies the managed value representation.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindString
	KindBytes
	// KindRunes is a []rune value. Its key and its root use the byte
	// coordinates of the rune array: rune i is bytes [4i, 4i+4).
	KindRunes
)

type ownerState uint32

const (
	stateUnused ownerState = iota
	stateActive
	stateFinishing
	stateDead
)

// Key is a non-owning identity key. Pointer is never converted back to a Go
// pointer. The matching managed root is the only lifetime anchor.
type Key struct {
	Pointer uintptr
	Length  uint32
	Kind    Kind
}

// StringKey returns a key for a non-empty string whose size fits the store.
func StringKey(value string) (Key, bool) {
	if len(value) == 0 || uint64(len(value)) > uint64(^uint32(0)) {
		return Key{}, false
	}
	return Key{Pointer: uintptr(unsafe.Pointer(unsafe.StringData(value))), Length: uint32(len(value)), Kind: KindString}, true
}

// BytesKey returns a key for a non-empty byte slice whose size fits the store.
func BytesKey(value []byte) (Key, bool) {
	if len(value) == 0 || uint64(len(value)) > uint64(^uint32(0)) {
		return Key{}, false
	}
	return Key{Pointer: uintptr(unsafe.Pointer(unsafe.SliceData(value))), Length: uint32(len(value)), Kind: KindBytes}, true
}

// RunesKey returns a key for a non-empty rune slice whose byte size fits the
// store. The key length is the byte length of the rune array (4 bytes for each
// rune).
func RunesKey(value []rune) (Key, bool) {
	if len(value) == 0 || uint64(len(value)) > uint64(^uint32(0))/4 {
		return Key{}, false
	}
	return Key{Pointer: uintptr(unsafe.Pointer(unsafe.SliceData(value))), Length: uint32(4 * len(value)), Kind: KindRunes}, true
}

type rootRecord struct {
	stringAnchor string
	bytesAnchor  []byte
	base         uintptr
	span         uint32
	generation   atomic.Uint32
	setGen       uint32
	overflow     uint16 // block index + 1
	count        uint8
	limit        ranges.Limit
	// indexed is true only after all index refs of this root are published
	// (plan section 5.2.2). Lookups ignore a root that is not indexed. It is
	// guarded by owner.rootsMu.
	indexed bool
	// kind is the kind of the first adoption of this root.
	kind   Kind
	inline [GuaranteedRanges]ranges.Range
}

type owner struct {
	id          atomic.Uint64
	generation  atomic.Uint64
	state       atomic.Uint32
	lifecycleMu sync.RWMutex
	rootsMu     sync.RWMutex
	roots       [MaxRootsPerOwner]rootRecord
	rootNext    uint16
	rootFree    [MaxRootsPerOwner]uint16
	rootFreeN   uint16
	charged     atomic.Int64
	rootCount   atomic.Int32
	// extending is true while an extension of a root of this owner runs
	// (plan section 5.2.2, "Extension"). It is guarded by rootsMu.
	extending      bool
	bindings       bindingTable
	writersMu      sync.RWMutex
	writers        [MaxWriters]writerRecord
	writerPointers [MaxWriters]atomic.Uintptr
	writerStarts   [MaxWriters]atomic.Uintptr
	writerEnds     [MaxWriters]atomic.Uintptr
	writerCount    uint8
	writerDirty    atomic.Bool
	writerVersion  atomic.Uint64
	drops          dropCounters
}

type overflowBlock struct {
	ranges [overflowRanges]ranges.Range
}

type dropCounters struct {
	full       atomic.Uint64
	bytes      atomic.Uint64
	ranges     atomic.Uint64
	contention atomic.Uint64
	late       atomic.Uint64
	stale      atomic.Uint64
	disabled   atomic.Uint64
	oneByte    atomic.Uint64
	fanout     atomic.Uint64
	// indexFull counts root admissions that failed because the probe window
	// of one granule key had no empty place.
	indexFull atomic.Uint64
	// preContention counts Confirm calls that returned ConfirmUnknown because
	// a TryRLock failed.
	preContention atomic.Uint64
	// preStale counts runtime pre-checks that found a tainted operand whose
	// owner finished before the result hook ran (runtime bridge, step 4).
	preStale atomic.Uint64
	// dupOwner counts lookup refs that were skipped because the snapshot
	// already had a contribution of the same owner.
	dupOwner atomic.Uint64
}

// Counters is a point-in-time loss snapshot.
type Counters struct {
	Full       uint64
	Bytes      uint64
	Ranges     uint64
	Contention uint64
	Late       uint64
	Stale      uint64
	Disabled   uint64
	OneByte    uint64
	Fanout     uint64
	IndexFull  uint64
	// PreContention counts Confirm results that are ConfirmUnknown.
	PreContention uint64
	PreStale      uint64
	DupOwner      uint64
}

// Stats is a bounded store-health snapshot.
type Stats struct {
	OverflowFree uint16
	// IndexEntries is the number of interior index entries in use.
	IndexEntries uint32
	// IndexRefs is the number of owner refs in the interior index.
	IndexRefs uint32
	// MaxProbe is the largest bucket distance (0 to IndexBucketProbe-1) that
	// an insert used since the store was created.
	MaxProbe uint8
	// FilterSum is the sum of all filter counters. It is equal to the number
	// of published (ref, granule key) pairs.
	FilterSum uint64
	// IndexedRoots is the number of roots that have indexed == true.
	IndexedRoots int32
}

// Store owns all fixed-capacity process storage.
type Store struct {
	owners      [MaxOwners]owner
	ownerMu     sync.Mutex
	nextOwnerID atomic.Uint64
	// drops counts events that no owner can own, for example a contended
	// index shard in a reader.
	drops        dropCounters
	acquireDrops atomic.Uint64
	charged      atomic.Int64
	// indexedRoots is the number of roots with indexed == true. It is
	// incremented before a root becomes indexed and decremented after it
	// stops being indexed (plan section 5.2.2), so it is never lower than
	// the number of visible roots.
	indexedRoots atomic.Int32
	// indexMaxProbe is the largest bucket distance that an insert used.
	indexMaxProbe  atomic.Uint32
	writerStates   atomic.Int32
	writerActive   *atomic.Int32
	operatorActive atomic.Pointer[atomic.Int32]
	overflow       [OverflowBlocks]overflowBlock
	overflowFree   [OverflowBlocks]uint16
	overflowN      uint16
	overflowMu     sync.Mutex
	index          [IndexShards]indexShard
	filter         [FilterBuckets]atomic.Uint32
}

// BindOperatorActive binds a mirror counter used by operator fast gates. The
// store changes the mirror at the same time as the indexed-root counter.
func (s *Store) BindOperatorActive(active *atomic.Int32) {
	if active != nil {
		s.operatorActive.Store(active)
	}
}

// addIndexedRoots changes the indexed-root counter and its operator mirror.
func (s *Store) addIndexedRoots(delta int32) {
	s.indexedRoots.Add(delta)
	if active := s.operatorActive.Load(); active != nil {
		active.Add(delta)
	}
}

// IndexedRoots returns the process indexed-root counter for allocation-free
// bridge gates. It is not zero while a root is visible to lookups. Callers may
// only load the counter; the store owns all updates.
func (s *Store) IndexedRoots() *atomic.Int32 { return &s.indexedRoots }

// New allocates and initializes a bounded store.
func New() *Store {
	store := new(Store)
	for i := range store.overflowFree {
		store.overflowFree[i] = uint16(i)
	}
	store.overflowN = OverflowBlocks
	return store
}

// ProcessCharged returns charged managed-root bytes.
func (s *Store) ProcessCharged() int64 {
	if s == nil {
		return 0
	}
	return s.charged.Load()
}

// AcquireDrops returns owner acquisitions dropped by contention or capacity.
func (s *Store) AcquireDrops() uint64 {
	if s == nil {
		return 0
	}
	return s.acquireDrops.Load()
}

// Counters returns the store-wide loss counters: the events that no owner can
// own (for example a contended index shard in a reader).
func (s *Store) Counters() Counters {
	if s == nil {
		return Counters{}
	}
	return snapshotDrops(&s.drops)
}

// Stats returns fixed-table health counters. It is intended for telemetry and
// validation, not the propagation hot path.
func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	stats := Stats{IndexedRoots: s.indexedRoots.Load(), MaxProbe: uint8(s.indexMaxProbe.Load())}
	for i := range s.index {
		shard := &s.index[i]
		shard.mu.RLock()
		for bucket := range shard.buckets {
			for slot := range shard.buckets[bucket] {
				entry := &shard.buckets[bucket][slot]
				if entry.key != 0 {
					stats.IndexEntries++
					stats.IndexRefs += uint32(entry.n)
				}
			}
		}
		shard.mu.RUnlock()
	}
	for i := range s.filter {
		stats.FilterSum += uint64(s.filter[i].Load())
	}
	s.overflowMu.Lock()
	stats.OverflowFree = s.overflowN
	s.overflowMu.Unlock()
	return stats
}

func snapshotDrops(d *dropCounters) Counters {
	return Counters{
		Full: d.full.Load(), Bytes: d.bytes.Load(), Ranges: d.ranges.Load(),
		Contention: d.contention.Load(), Late: d.late.Load(), Stale: d.stale.Load(),
		Disabled: d.disabled.Load(), OneByte: d.oneByte.Load(), Fanout: d.fanout.Load(),
		IndexFull: d.indexFull.Load(), PreContention: d.preContention.Load(),
		PreStale: d.preStale.Load(), DupOwner: d.dupOwner.Load(),
	}
}

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

type valueSlot struct {
	pointer  uintptr
	ownerGen uint64
	length   uint32
	rootOff  uint32
	rootGen  uint32
	rootID   uint16
	ownerIdx uint8
	kind     Kind
}

type rootRecord struct {
	stringAnchor string
	bytesAnchor  []byte
	base         uintptr
	span         uint32
	generation   atomic.Uint32
	setGen       uint32
	valueQuota   atomic.Uint64 // generation in high 32 bits, count in low 32 bits
	overflow     uint16        // block index + 1
	count        uint8
	limit        ranges.Limit
	inline       [GuaranteedRanges]ranges.Range
}

type owner struct {
	id             atomic.Uint64
	generation     atomic.Uint64
	state          atomic.Uint32
	lifecycleMu    sync.RWMutex
	rootsMu        sync.RWMutex
	roots          [MaxRootsPerOwner]rootRecord
	rootNext       uint16
	rootFree       [MaxRootsPerOwner]uint16
	rootFreeN      uint16
	charged        atomic.Int64
	values         atomic.Int32
	rootCount      atomic.Int32
	bindings       bindingTable
	writersMu      sync.RWMutex
	writers        [MaxWriters]writerRecord
	writerPointers [MaxWriters]atomic.Uintptr
	writerCount    uint8
	writerDirty    atomic.Bool
	writerVersion  atomic.Uint64
	drops          dropCounters
}

type shard struct {
	mu         sync.RWMutex
	slots      [SlotsPerShard]valueSlot
	tombstones uint16
	probeSum   uint64
	probeN     uint64
	probeMax   uint8
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
}

// Stats is a bounded store-health snapshot.
type Stats struct {
	Compactions   uint64
	CompactAborts uint64
	OverflowFree  uint16
	Tombstones    uint32
	MaxTombstones uint16
	ProbeCount    uint64
	AverageProbe  float64
	MaxProbe      uint8
}

// Store owns all fixed-capacity process storage.
type Store struct {
	shards        [Shards]shard
	owners        [MaxOwners]owner
	ownerMu       sync.Mutex
	nextOwnerID   atomic.Uint64
	acquireDrops  atomic.Uint64
	charged       atomic.Int64
	values        atomic.Int32
	writerStates  atomic.Int32
	overflow      [OverflowBlocks]overflowBlock
	overflowFree  [OverflowBlocks]uint16
	overflowN     uint16
	overflowMu    sync.Mutex
	compactions   atomic.Uint64
	compactAborts atomic.Uint64
}

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

// ProcessValues returns value slots charged to live root generations. Stale
// pointer-free slots remain physically resident until lazy reclamation.
func (s *Store) ProcessValues() int32 {
	if s == nil {
		return 0
	}
	return s.values.Load()
}

// Stats returns fixed-table health counters. It is intended for telemetry and
// validation, not the propagation hot path.
func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	stats := Stats{Compactions: s.compactions.Load(), CompactAborts: s.compactAborts.Load()}
	for i := range s.shards {
		shard := &s.shards[i]
		shard.mu.RLock()
		stats.Tombstones += uint32(shard.tombstones)
		stats.MaxTombstones = max(stats.MaxTombstones, shard.tombstones)
		stats.ProbeCount += shard.probeN
		stats.AverageProbe += float64(shard.probeSum)
		stats.MaxProbe = max(stats.MaxProbe, shard.probeMax)
		shard.mu.RUnlock()
	}
	if stats.ProbeCount != 0 {
		stats.AverageProbe /= float64(stats.ProbeCount)
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
	}
}

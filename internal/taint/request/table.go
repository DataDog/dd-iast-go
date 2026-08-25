// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"hash/maphash"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

const (
	// MaxSources is the hard maximum number of sources a [Table] can hold. The
	// table never grows beyond this and drops new sources once it is full.
	MaxSources = 256

	// indexSlots is the fixed number of slots in the deduplication index. It is
	// a power of two so a slot is computed with a bitmask, and it keeps the load
	// factor at or below 50% (MaxSources/indexSlots) when the table is full.
	indexSlots = 512
	// indexMask folds a hash into a slot index.
	indexMask = indexSlots - 1
	// maxProbe is the hard bound on the number of slots a single add inspects.
	// At <=50% load an empty slot is always found within indexSlots probes (a
	// contiguous cluster is at most MaxSources long), so this bound is never
	// reached in practice; it guarantees bounded, allocation-free probe work even
	// if the table is degraded.
	maxProbe = indexSlots
)

// AddStatus is the outcome of a [Table].Add operation. It disambiguates a
// returned identifier (including the valid ID 0) from a capacity failure or
// rejected input.
type AddStatus uint8

const (
	// AddAdded means a new source was inserted and assigned [AddResult].ID. The
	// ID is valid and may be 0.
	AddAdded AddStatus = iota
	// AddDuplicate means an equal source already existed; [AddResult].ID is the
	// existing source's ID. The table was not modified. The ID may be 0.
	AddDuplicate
	// AddFull means the table is at capacity and the source is new. Nothing was
	// stored and [AddResult].ID is not valid.
	AddFull
	// AddRejected means the input was rejected (invalid origin or nil receiver).
	// Nothing was stored and [AddResult].ID is not valid.
	AddRejected
)

// AddResult is returned by [Table].Add. Callers must inspect [AddResult].Status
// before using [AddResult].ID: only AddAdded and AddDuplicate carry a valid ID.
type AddResult struct {
	ID     SourceID
	Status AddStatus
}

// Table is a fixed-capacity, deduplicating table of request sources. It has no
// global state and no dependency on the request owner, store, instrumentation,
// redaction, or model serialization. The zero value is ready for use; [New]
// initializes the randomized seed eagerly.
//
// Deduplication uses a fixed-size open-addressing index kept at or below 50%
// load. The index stores ID+1 so the zero slot value denotes an empty slot, and
// a per-table randomized hash/maphash seed prevents attacker-controlled inputs
// from forcing deterministic collision chains. Every occupied probe compares
// the full origin, name, and value. Probe work is bounded and does not allocate.
// A Table must not be copied after
// its first use and is not safe for concurrent access; the future request owner
// provides synchronization.
type Table struct {
	sources [MaxSources]Source
	index   [indexSlots]uint16 // source ID + 1; 0 means empty
	count   int
	seed    maphash.Seed
	seeded  bool
}

// New returns a ready-to-use [Table] with a fresh randomized hash seed.
func New() *Table {
	t := new(Table)
	t.initSeed()
	return t
}

// Add inserts the source (origin, name, value) unless an equal source already
// exists, in which case it returns the existing ID. A new source at capacity is
// rejected with AddFull and leaves the table unchanged. An invalid origin (or a
// nil receiver) is rejected with AddRejected without panic.
//
// Equality is exact over (origin, name, full unredacted value). The table keeps
// the full strings; it does not clone them in Phase 1.
func (t *Table) Add(origin constants.Origin, name, value string) AddResult {
	if t == nil {
		return AddResult{Status: AddRejected}
	}
	if !validOrigin(origin) {
		return AddResult{Status: AddRejected}
	}
	t.initSeed()
	start := t.hash(origin, name, value)
	for probe := 0; probe < maxProbe; probe++ {
		slot := (start + uint32(probe)) & indexMask
		entry := t.index[slot]
		if entry == 0 {
			// Empty slot: no equal source exists on this probe chain. Linear
			// probing keeps an equal source ahead of any empty slot, so reaching
			// an empty slot proves the source is new.
			if t.count >= MaxSources {
				return AddResult{Status: AddFull}
			}
			id := SourceID(t.count)
			t.sources[id] = Source{Origin: origin, Name: name, Value: value}
			t.count++
			t.index[slot] = uint16(id) + 1
			return AddResult{ID: id, Status: AddAdded}
		}
		existing := t.sources[entry-1]
		if existing.Origin == origin && existing.Name == name && existing.Value == value {
			return AddResult{ID: SourceID(entry - 1), Status: AddDuplicate}
		}
	}
	// Probe bound exhausted (cannot happen at <=50% load); drop the source.
	return AddResult{Status: AddFull}
}

// Get returns the source recorded at id. ok is false if id was never assigned
// or the receiver is nil.
func (t *Table) Get(id SourceID) (s Source, ok bool) {
	if t == nil || int(id) >= t.count {
		return Source{}, false
	}
	return t.sources[id], true
}

// Len returns the number of sources currently stored. It returns 0 for a nil
// receiver.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return t.count
}

// Reset releases all retained strings, clears the deduplication index, and
// reinitializes the hash seed. The work is bounded (O(MaxSources+indexSlots)).
// A nil receiver is a no-op. After Reset, IDs restart from 0.
func (t *Table) Reset() {
	if t == nil {
		return
	}
	clear(t.sources[:])
	clear(t.index[:])
	t.count = 0
	t.seed = maphash.MakeSeed()
	t.seeded = true
}

func (t *Table) initSeed() {
	if t.seeded {
		return
	}
	t.seed = maphash.MakeSeed()
	t.seeded = true
}

// hash returns the deduplication index slot for (origin, name, value) using the
// table's randomized seed. It is unexported so that forced-collision tests stay
// in a same-package test file and the production hash is not weakened. Hash
// collisions are resolved by full equality comparison in [Add].
func (t *Table) hash(origin constants.Origin, name, value string) uint32 {
	var h maphash.Hash
	h.SetSeed(t.seed)
	h.WriteByte(byte(origin))
	h.WriteString(name)
	h.WriteByte(0)
	h.WriteString(value)
	return uint32(h.Sum64()) & indexMask
}

// validOrigin reports whether origin is a recognized source origin. The zero
// origin is invalid.
func validOrigin(origin constants.Origin) bool {
	return origin != 0 && uint(origin) <= uint(constants.OriginCount)
}

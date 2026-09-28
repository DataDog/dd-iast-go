// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"slices"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// fuzzRoot is the expected state of the root of one owner for one allocation:
// the source of each byte (0 is clean). An adoption sets the bytes of its
// ranges (the union rule: the new ranges win on the bytes that they describe),
// a tracked mutation replaces all bytes, and a failed mutation makes the root
// invalid until Finish.
type fuzzRoot struct {
	ref     RootRef
	span    int
	sources []ranges.SourceID
	valid   bool
}

// truncate keeps the first MaxRanges ranges, as the store does when a union
// has more ranges than the range limit.
func (r *fuzzRoot) truncate() {
	runs := expectedRanges(r.sources)
	if len(runs) > MaxRanges {
		clear(r.sources[runs[MaxRanges-1].Start+runs[MaxRanges-1].Length:])
	}
}

type fuzzOwner struct {
	owner *Owner
	roots map[int]*fuzzRoot // allocation index -> root
}

// FuzzInteriorIndex runs a sequence of adoptions, shared adoptions, extensions,
// mutations and finishes that the input encodes. After each operation it
// checks the index invariants of plan section 5.2.2, and it compares Lookup of
// a random window of each allocation with the expected ranges of every live
// owner.
func FuzzInteriorIndex(f *testing.F) {
	f.Add([]byte{0, 10, 0, 200, 1, 0, 150, 3, 0, 1})
	f.Add([]byte{0, 250, 0, 40, 1, 0, 255, 2, 0, 3, 0})
	f.Add([]byte{0, 0, 0, 1, 0, 1, 4, 0, 0, 7, 9, 1, 1, 0, 30, 5, 2, 1, 0, 0, 1, 2, 3, 0})
	// Adoption, then an extension with a different range: the union must
	// keep both ranges.
	f.Add([]byte{0, 0, 0, 5, 3, 0, 16, 0, 1, 0, 10, 7, 0, 16})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > 256 {
			encoded = encoded[:256]
		}
		s := New()
		var allocations [][]byte
		var owners [3]*fuzzOwner
		next := func() int {
			if len(encoded) == 0 {
				return 0
			}
			b := int(encoded[0])
			encoded = encoded[1:]
			return b
		}
		step := ranges.SourceID(0)
		for len(encoded) != 0 {
			step++
			slot := next() % len(owners)
			current := owners[slot]
			if current == nil {
				owners[slot] = &fuzzOwner{owner: s.Acquire(), roots: map[int]*fuzzRoot{}}
				continue
			}
			switch next() % 6 {
			case 0: // first adoption of a new allocation
				size := 2 + next()*3
				data := make([]byte, size)
				start := next() % (size - 1)
				if ref, ok := current.owner.AdoptBytes(data, fuzzSet(uint32(size), start, step)); ok {
					allocations = append(allocations, data)
					root := &fuzzRoot{ref: ref, span: size, sources: make([]ranges.SourceID, size), valid: true}
					root.sources[start] = step
					current.roots[len(allocations)-1] = root
				}
			case 1, 2: // adoption of a view of any allocation (shared or extension)
				if len(allocations) == 0 {
					continue
				}
				index := next() % len(allocations)
				data := allocations[index]
				span := 2 + next()%(cap(data)-1)
				start := next() % (span - 1)
				root := current.roots[index]
				ref, ok := current.owner.AdoptBytes(data[:span:span], fuzzSet(uint32(span), start, step))
				if !ok {
					continue
				}
				if root == nil {
					root = &fuzzRoot{ref: ref, span: span, sources: make([]ranges.SourceID, cap(data)), valid: true}
					current.roots[index] = root
				} else if ref.ID != root.ref.ID {
					t.Fatalf("an extension made a second root: %d != %d", ref.ID, root.ref.ID)
				}
				if !root.valid {
					t.Fatal("an extension of an invalid root succeeded")
				}
				root.ref = ref
				root.span = max(root.span, span)
				root.sources[start] = step
				root.truncate()
			case 3: // tracked mutation of the complete allocation
				index, root := anyRoot(current, next())
				if root == nil {
					continue
				}
				data := allocations[index]
				if ref, ok := current.owner.PublishBytesMutation(root.ref, data[:root.span:root.span], fuzzSet(uint32(root.span), 0, step)); ok {
					root.ref = ref
					clear(root.sources)
					root.sources[0] = step
					root.valid = true
				} else {
					root.valid = false
				}
			case 4: // finish
				current.owner.Finish()
				owners[slot] = nil
				continue
			default: // lookups only
			}
			checkIndexInvariants(t, s)
			for index, data := range allocations {
				low := next() % cap(data)
				high := low + 1 + next()%(cap(data)-low)
				checkWindow(t, s, owners[:], index, data, low, high)
			}
		}
		for _, current := range owners {
			if current != nil {
				current.owner.Finish()
			}
		}
		checkIndexInvariants(t, s)
		if stats := s.Stats(); stats.IndexedRoots != 0 || stats.IndexRefs != 0 || stats.FilterSum != 0 {
			t.Fatalf("index state after Finish: %+v", stats)
		}
	})
}

func fuzzSet(span uint32, start int, source ranges.SourceID) *ranges.Set {
	var set ranges.Set
	ranges.Canonicalize(&set, ranges.HardLimit, []ranges.Range{r(uint32(start), 1, source)}, span)
	return &set
}

func anyRoot(owner *fuzzOwner, choice int) (int, *fuzzRoot) {
	if len(owner.roots) == 0 {
		return 0, nil
	}
	keys := make([]int, 0, len(owner.roots))
	for key := range owner.roots {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	key := keys[choice%len(keys)]
	return key, owner.roots[key]
}

// checkWindow compares Lookup of data[low:high] with the expected ranges of
// every live owner.
func checkWindow(t *testing.T, s *Store, owners []*fuzzOwner, index int, data []byte, low, high int) {
	t.Helper()
	key := Key{Pointer: bytesBase(data) + uintptr(low), Length: uint32(high - low), Kind: KindBytes}
	var snapshot Snapshot
	if !s.Lookup(key, &snapshot) {
		t.Fatal("an uncontended lookup failed")
	}
	got := map[uint8][]ranges.Range{}
	for i := 0; i < snapshot.Len(); i++ {
		entry, _ := snapshot.At(i)
		if _, duplicate := got[entry.OwnerIndex]; duplicate {
			t.Fatal("two contributions of one owner")
		}
		got[entry.OwnerIndex] = rangeSlice(&entry.Ranges)
	}
	for _, current := range owners {
		if current == nil {
			continue
		}
		ownerIndex, _ := current.owner.Index()
		var want []ranges.Range
		if root := current.roots[index]; root != nil && root.valid && high <= root.span {
			want = expectedRanges(root.sources[low:high])
		}
		if !slices.Equal(want, got[ownerIndex]) {
			t.Fatalf("allocation %d window [%d, %d) owner %d: got %v, want %v", index, low, high, ownerIndex, got[ownerIndex], want)
		}
		delete(got, ownerIndex)
	}
	if len(got) != 0 {
		t.Fatalf("contributions of owners that are not live: %v", got)
	}
}

// expectedRanges encodes the byte sources as canonical ranges: adjacent bytes
// with the same source are one range.
func expectedRanges(sources []ranges.SourceID) []ranges.Range {
	var result []ranges.Range
	for i := 0; i < len(sources); i++ {
		if sources[i] == 0 {
			continue
		}
		if n := len(result); n != 0 && result[n-1].SourceID == sources[i] && int(result[n-1].Start+result[n-1].Length) == i {
			result[n-1].Length++
			continue
		}
		result = append(result, r(uint32(i), 1, sources[i]))
	}
	return result
}

func checkIndexInvariants(t *testing.T, s *Store) {
	t.Helper()
	var expected [FilterBuckets]uint32
	for i := range s.index {
		for bucket := range s.index[i].buckets {
			for slot := range s.index[i].buckets[bucket] {
				entry := &s.index[i].buckets[bucket][slot]
				if entry.key == 0 {
					continue
				}
				expected[filterBucket(indexHash(entry.key))] += uint32(entry.n)
				for a := 0; a < int(entry.n); a++ {
					for b := a + 1; b < int(entry.n); b++ {
						if entry.refs[a].ownerIdx == entry.refs[b].ownerIdx && entry.refs[a].ownerGen == entry.refs[b].ownerGen {
							t.Fatal("two refs of one owner in one entry")
						}
					}
				}
			}
		}
	}
	for i := range expected {
		if s.filter[i].Load() != expected[i] {
			t.Fatalf("filter bucket %d: got %d, want %d", i, s.filter[i].Load(), expected[i])
		}
	}
	indexed := int32(0)
	for i := range s.owners {
		for j := range s.owners[i].roots {
			if s.owners[i].roots[j].indexed {
				indexed++
			}
		}
	}
	if indexed != s.IndexedRoots().Load() {
		t.Fatalf("indexed roots: counter %d, roots %d", s.IndexedRoots().Load(), indexed)
	}
}

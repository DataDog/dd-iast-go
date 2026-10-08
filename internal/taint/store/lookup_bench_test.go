// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"fmt"
	"strings"
	"testing"
	"unsafe"
)

// The benchmarks in this file measure the lookup path under three index loads:
//   - sparse: 100 roots;
//   - typical: 2 500 roots;
//   - full: 63 owners of 512 roots each (32 256 roots; the 64th owner holds
//     the test values). Each root is a 128-byte string, which uses two tier
//     S granules, so the full load asks for 64 512 entries and fills the
//     index until it refuses roots. The exact-key value table (the base
//     store) is full at 16 384 values.
//
// Each benchmark reports the index occupancy (index-entries, occupancy%), the
// filter hit rate and the number of shard probes for each operation.
//
// The "check" benchmarks run the same operation on the base store and on the
// interior store: MayContain, then Lookup on a hit, and report whether the
// value is tainted. They give the same answer on both stores, so they are the
// old-versus-new comparison. The "maycontain" benchmarks measure MayContain
// alone. MayContain is an exact probe on the base store and a filter check on
// the interior store, so these rows are not equivalent across the stores; they
// are the 9.3 gate rows of the interior store.

type lookupLoad struct {
	name  string
	roots int
	size  int
}

var lookupLoads = [...]lookupLoad{
	{"sparse", 100, 64},
	{"typical", 2500, 64},
	{"full", (MaxOwners - 1) * MaxRootsPerOwner, 128},
}

type loadedStore struct {
	store    *Store
	owners   []*Owner
	tainted  Key   // a complete root
	window   Key   // a window of a root
	neighbor Key   // a clean allocation in the same 64-byte granule as a root
	clean    []Key // clean 64-byte allocations, one granule each
	miss     []Key // the clean keys that are filter misses
	roots    int
	entries  int
	keep     []any

	// The values of neighbor, clean and miss, for the runtime bridge
	// benchmarks (they take values, not keys). otherNeighborValue is a
	// second neighbor, in the granule of another root.
	neighborValue      string
	otherNeighborValue string
	cleanValues        []string
	missValues         []string
}

func newLoadedStore(tb testing.TB, load lookupLoad) *loadedStore {
	tb.Helper()
	return newLoadedStoreIn(tb, New(), load)
}

// newLoadedStoreIn loads s. The owners finish in the cleanup of tb.
func newLoadedStoreIn(tb testing.TB, s *Store, load lookupLoad) *loadedStore {
	tb.Helper()
	loaded := &loadedStore{store: s}
	// The tainted root, its window and the neighbor are published first, so
	// a full store cannot refuse them.
	owner := s.Acquire()
	loaded.owners = append(loaded.owners, owner)
	managed, ref, ok := owner.TaintString(strings.Repeat("w", 64), 1)
	if !ok {
		tb.Fatal("the store refused the tainted root")
	}
	loaded.tainted, _ = StringKey(managed)
	loaded.window, _ = StringKey(managed[4:12])
	if !benchPublishWindow(owner, loaded.window, ref) {
		tb.Fatal("the window is not published")
	}
	loaded.keep = append(loaded.keep, managed)
	// Two 16-byte allocations in one 64-byte granule: one is a root, the
	// other stays clean. Two such pairs, in different granules.
	var neighbors []Key
	for attempt := 0; attempt < 1000 && len(neighbors) < 2; attempt++ {
		batch := make([][]byte, 16)
		for i := range batch {
			batch[i] = make([]byte, 16)
			batch[i][0], batch[i][1] = 'n', 'n'
		}
		for i := 1; i < len(batch); i++ {
			first, second := bytesPointer(batch[i-1]), bytesPointer(batch[i])
			if first>>6 != second>>6 || len(neighbors) == 1 && neighbors[0].Pointer>>6 == second>>6 {
				continue
			}
			if _, _, _, ok := owner.AdoptSourceBytes(batch[i-1], "n", 1); ok {
				neighbors = append(neighbors, Key{Pointer: second, Length: 16, Kind: KindBytes})
				if len(neighbors) == 1 {
					loaded.neighborValue = unsafe.String(&batch[i][0], len(batch[i]))
				} else {
					loaded.otherNeighborValue = unsafe.String(&batch[i][0], len(batch[i]))
				}
				loaded.keep = append(loaded.keep, batch)
				break
			}
		}
	}
	if len(neighbors) != 2 {
		tb.Fatal("no neighbor allocation")
	}
	loaded.neighbor = neighbors[0]
	for remaining := load.roots; remaining > 0; remaining -= MaxRootsPerOwner {
		owner := s.Acquire()
		if owner.Disabled() {
			break
		}
		loaded.owners = append(loaded.owners, owner)
		for range min(remaining, MaxRootsPerOwner) {
			if _, _, ok := owner.TaintString(strings.Repeat("t", load.size), 1); ok {
				loaded.roots++
			}
		}
	}
	loaded.clean = make([]Key, 4096)
	values := make([]string, len(loaded.clean))
	for i := range values {
		values[i] = strings.Clone(strings.Repeat("k", 64))
		loaded.clean[i], _ = StringKey(values[i])
	}
	loaded.keep = append(loaded.keep, values)
	loaded.cleanValues = values
	for i, key := range loaded.clean {
		if !s.MayContain(key) {
			loaded.miss = append(loaded.miss, key)
			loaded.missValues = append(loaded.missValues, values[i])
		}
	}
	loaded.entries, _ = benchOccupancy(s)
	tb.Cleanup(func() { finishAll(loaded.owners) })
	return loaded
}

func bytesPointer(value []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(value))) }

// rates returns the filter hit rate (in percent) and the mean number of shard
// probes of the keys. The benchmarks call it outside the timed loop.
func (l *loadedStore) rates(keys []Key) (hitRate, probes float64) {
	hits, total := 0, 0
	for _, key := range keys {
		if l.store.MayContain(key) {
			hits++
		}
		total += benchProbes(l.store, key)
	}
	return 100 * float64(hits) / float64(len(keys)), float64(total) / float64(len(keys))
}

func (l *loadedStore) report(b *testing.B) {
	b.ReportMetric(float64(l.roots), "roots")
	b.ReportMetric(float64(l.entries), "index-entries")
	b.ReportMetric(100*float64(l.entries)/benchCapacity, "occupancy%")
}

// check is the sink-level question: is key tainted? It is the same operation
// on both stores.
func (l *loadedStore) check(key Key, snapshot *Snapshot) bool {
	return l.store.MayContain(key) && l.store.Lookup(key, snapshot) && snapshot.Len() != 0
}

func BenchmarkLookupCheck(b *testing.B) {
	for _, load := range lookupLoads {
		loaded := newLoadedStore(b, load)
		cases := []struct {
			name    string
			keys    []Key
			tainted bool
		}{
			{"clean-random", loaded.clean, false},
			{"clean-neighbor", []Key{loaded.neighbor}, false},
			{"tainted-root", []Key{loaded.tainted}, true},
			{"tainted-window", []Key{loaded.window}, true},
		}
		for _, c := range cases {
			b.Run(fmt.Sprintf("%s/%s", c.name, load.name), func(b *testing.B) {
				var snapshot Snapshot
				// The diagnostic rates use a separate pass, before the timed
				// loop, so the timed loop runs exactly one check.
				hitRate, probes := loaded.rates(c.keys)
				i := 0
				for b.Loop() {
					if loaded.check(c.keys[i%len(c.keys)], &snapshot) != c.tainted {
						b.Fatalf("key %d: tainted is not %v", i%len(c.keys), c.tainted)
					}
					i++
				}
				loaded.report(b)
				b.ReportMetric(hitRate, "filter-hit%")
				b.ReportMetric(probes, "probes/op")
			})
		}
	}
}

func BenchmarkMayContain(b *testing.B) {
	for _, load := range lookupLoads {
		loaded := newLoadedStore(b, load)
		for _, c := range []struct {
			name string
			keys []Key
		}{
			{"clean-random", loaded.clean},
			// Filter misses only, at each load. At the full load, most random
			// keys are filter hits.
			{"clean-miss", loaded.miss},
			{"clean-neighbor", []Key{loaded.neighbor}},
			{"tainted-root", []Key{loaded.tainted}},
		} {
			b.Run(fmt.Sprintf("%s/%s", c.name, load.name), func(b *testing.B) {
				if len(c.keys) == 0 {
					b.Skip("no key")
				}
				hitRate, probes := loaded.rates(c.keys)
				// The index goes back to 0 at the end of the keys. A modulo
				// is an integer division, and on amd64 a division costs more
				// than the filter check.
				i := 0
				for b.Loop() {
					benchSink = loaded.store.MayContain(c.keys[i])
					if i++; i == len(c.keys) {
						i = 0
					}
				}
				loaded.report(b)
				b.ReportMetric(hitRate, "filter-hit%")
				// MayContain does no shard probe. This is the probe count
				// of a Lookup that follows a filter hit.
				b.ReportMetric(probes, "lookup-probes/op")
			})
		}
	}
}

// benchSink keeps the compiler from removing a timed call.
var benchSink bool

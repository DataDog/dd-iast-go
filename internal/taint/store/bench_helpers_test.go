// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

// The functions in this file adapt the benchmarks of admission_bench_test.go
// and lookup_bench_test.go to one store implementation. The baseline run of
// plan section 9.2 uses a copy of the benchmarks on the parent revision, with
// a version of this file for the exact-key value table.

// benchCapacity is the number of index entries of the store.
const benchCapacity = IndexShards * IndexBucketsPerShard * IndexBucketSize

// benchOccupancy returns the number of index entries and refs in use.
func benchOccupancy(s *Store) (entries, refs int) {
	stats := s.Stats()
	return int(stats.IndexEntries), int(stats.IndexRefs)
}

// benchProbes returns the number of index shards that a Lookup of key reads:
// one for each tier whose filter counter is not zero.
func benchProbes(s *Store, key Key) int { return s.IndexProbes(key) }

// benchPublishWindow makes a window of a root visible to Lookup. The interior
// index finds every window, so it has nothing to do.
func benchPublishWindow(*Owner, Key, RootRef) bool { return true }

// benchIndexShard is the index shard of the tier S granule key of address.
func benchIndexShard(address uintptr) uint64 { return indexHash(granuleKey(address, false)) >> 56 }

// benchIndexFull returns the indexFull drop counter.
func benchIndexFull(c Counters) uint64 { return c.IndexFull }

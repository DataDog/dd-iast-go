// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

// requireIndexEmpty checks that no root is indexed and that the index and the
// filter are empty.
func requireIndexEmpty(t testing.TB, s *Store) {
	t.Helper()
	stats := s.Stats()
	require.Zero(t, stats.IndexedRoots, "indexed roots")
	require.Zero(t, stats.IndexRefs, "index refs")
	require.Zero(t, stats.IndexEntries, "index entries")
	require.Zero(t, stats.FilterSum, "filter sum")
}

// requireFilterConsistent checks that every filter bucket counts exactly the
// (ref, key) pairs of the index that hash to it.
func requireFilterConsistent(t testing.TB, s *Store) {
	t.Helper()
	var expected [FilterBuckets]uint32
	for i := range s.index {
		shard := &s.index[i]
		shard.mu.RLock()
		for bucket := range shard.buckets {
			for slot := range shard.buckets[bucket] {
				entry := &shard.buckets[bucket][slot]
				if got, want := slotTag(shard, bucket, slot), entryTagOf(entry); got != want {
					require.Failf(t, "tag mismatch", "shard %d bucket %d slot %d: tag %d, want %d", i, bucket, slot, got, want)
				}
				if entry.key != 0 {
					expected[filterBucket(indexHash(entry.key))] += uint32(entry.n)
				}
			}
		}
		shard.mu.RUnlock()
	}
	for i := range expected {
		if got := s.filter[i].Load(); got != expected[i] {
			require.Failf(t, "filter mismatch", "bucket %d: got %d, want %d", i, got, expected[i])
		}
	}
}

// slotTag returns the tag byte of a slot.
func slotTag(shard *indexShard, bucket, slot int) uint8 {
	return uint8(shard.tags[bucket] >> (8 * uint(slot)))
}

// entryTagOf returns the tag that the slot of entry must have: 0 for an empty
// slot.
func entryTagOf(entry *indexEntry) uint8 {
	if entry.key == 0 {
		return 0
	}
	return entryTag(indexHash(entry.key))
}

// indexState returns the store statistics without the monotonic MaxProbe.
func indexState(s *Store) Stats {
	stats := s.Stats()
	stats.MaxProbe = 0
	return stats
}

// setHook installs a test hook until the end of the test.
func setHook(t testing.TB, hook func(stage hookStage, arg int) bool) {
	t.Helper()
	require.True(t, testHook.CompareAndSwap(nil, &hook), "one hook at a time")
	t.Cleanup(func() { testHook.Store(nil) })
}

func mustSet(t testing.TB, limit ranges.Limit, span uint32, raw ...ranges.Range) *ranges.Set {
	t.Helper()
	var set ranges.Set
	require.True(t, ranges.Canonicalize(&set, limit, raw, span).Valid)
	return &set
}

// lookupRanges returns the ranges of the only contribution for key, or nil.
func lookupRanges(t testing.TB, s *Store, key Key) []ranges.Range {
	t.Helper()
	var snapshot Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.LessOrEqual(t, snapshot.Len(), 1)
	if snapshot.Len() == 0 {
		return nil
	}
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	return rangeSlice(&entry.Ranges)
}

func windowKey(base uintptr, offset, length int, kind Kind) Key {
	return Key{Pointer: base + uintptr(offset), Length: uint32(length), Kind: kind}
}

func bytesBase(value []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(value))) }

func stringBase(value string) uintptr { return uintptr(unsafe.Pointer(unsafe.StringData(value))) }

// alignedBuffer returns a buffer whose element offset is aligned to align
// bytes, and the buffer that holds it.
func alignedBuffer(size, align int) (aligned, backing []byte) {
	backing = make([]byte, size+align)
	first := (align - int(bytesBase(backing)%uintptr(align))) % align
	return backing[first : first+size : first+size], backing
}

func r(start, length uint32, source ranges.SourceID) ranges.Range {
	return ranges.Range{Start: start, Length: length, SourceID: source}
}

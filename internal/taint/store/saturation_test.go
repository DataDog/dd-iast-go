// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestRequestRootByteLimit(t *testing.T) {
	store := New()
	owner := store.Acquire()
	for i := 0; i < RequestRootBytes/MaxRootBytes; i++ {
		_, _, ok := owner.TaintString(strings.Repeat(string(rune('a'+i%20)), MaxRootBytes), 0)
		require.Truef(t, ok, "root %d", i)
	}
	_, _, ok := owner.TaintString(strings.Repeat("z", MaxRootBytes), 0)
	require.False(t, ok)
	require.Equal(t, int64(RequestRootBytes), owner.Charged())
	require.Greater(t, owner.Counters().Bytes, uint64(0))
	owner.Finish()
}

func TestProcessRootByteLimit(t *testing.T) {
	store := New()
	owners := make([]*Owner, ProcessRootBytes/RequestRootBytes)
	for i := range owners {
		owners[i] = store.Acquire()
		for root := 0; root < RequestRootBytes/MaxRootBytes; root++ {
			_, _, ok := owners[i].TaintString(strings.Repeat(string(rune('a'+root%20)), MaxRootBytes), 0)
			require.True(t, ok)
		}
	}
	extra := store.Acquire()
	_, _, ok := extra.TaintString(strings.Repeat("z", MaxRootBytes), 0)
	require.False(t, ok)
	require.Equal(t, int64(ProcessRootBytes), store.ProcessCharged())
	for _, owner := range owners {
		owner.Finish()
	}
	extra.Finish()
	require.Zero(t, store.ProcessCharged())
}

func TestRootCountLimit(t *testing.T) {
	store := New()
	owner := store.Acquire()
	for i := 0; i < MaxRootsPerOwner; i++ {
		value := strings.Clone(string([]byte{byte(i), byte(i >> 8), 'x'}))
		_, _, ok := owner.TaintString(value, 0)
		require.Truef(t, ok, "root %d", i)
	}
	_, _, ok := owner.TaintString("one-root-too-many", 0)
	require.False(t, ok)
	require.Greater(t, owner.Counters().Full, uint64(0))
	owner.Finish()
}

// TestIndexCapacityLimitsProcessRoots fills the index with heap roots. The
// heap addresses are not controlled, so the hash can put more keys in one
// probe window (5 buckets of one shard) than the window holds, while other
// windows have free slots. Thus the number of admitted roots is not a fixed
// value (a run on a loaded machine admitted 29 270 of 32 768, 89.3 %). This
// test checks only the invariants: each refusal is an indexFull drop, the
// counts agree, and nothing leaks. TestIndexHoldsFullCapacity checks the
// capacity with a controlled address distribution.
func TestIndexCapacityLimitsProcessRoots(t *testing.T) {
	store := New()
	owners := make([]*Owner, 0, MaxOwners)
	admitted := 0
	for range MaxOwners {
		owner := store.Acquire()
		require.False(t, owner.Disabled())
		owners = append(owners, owner)
		for range MaxRootsPerOwner {
			// 16-byte roots use one tier S granule each.
			if _, _, ok := owner.TaintString("0123456789abcdef", 0); ok {
				admitted++
			}
		}
	}
	stats := store.Stats()
	require.Equal(t, int32(admitted), stats.IndexedRoots)
	require.Equal(t, uint32(admitted), stats.IndexRefs)
	require.LessOrEqual(t, admitted, IndexShards*IndexBucketsPerShard*IndexBucketSize)
	require.Positive(t, admitted)
	var refused, other uint64
	for _, owner := range owners {
		counters := owner.Counters()
		refused += counters.IndexFull
		other += counters.Contention + counters.Full + counters.Bytes + counters.Fanout
	}
	require.Equal(t, uint64(MaxOwners*MaxRootsPerOwner-admitted), refused, "each refused root is an indexFull drop")
	require.Zero(t, other, "no other drop")
	require.Equal(t, int64(admitted)*sizeClass(16), store.ProcessCharged(), "only admitted roots are charged")
	requireFilterConsistent(t, store)
	for _, owner := range owners {
		owner.Finish()
	}
	requireIndexEmpty(t, store)
	require.Zero(t, store.ProcessCharged())
}

// TestIndexHoldsFullCapacity checks that the index can hold one root in each
// of its IndexShards*IndexBucketsPerShard*IndexBucketSize (32 768) entries,
// and that it refuses a root only when the probe window of the root is full.
// The test controls the address distribution: it selects 16-byte windows of
// one large allocation, one window for each 64-byte granule, so that exactly
// IndexBucketSize granule keys have each home bucket. Then no root must use a
// bucket that is not its home bucket, and the index can admit all roots. The
// windows are not allocation bases, which the store does not check; each
// window has its own granule key, so the density bound of the index is not
// used.
func TestIndexHoldsFullCapacity(t *testing.T) {
	const capacity = IndexShards * IndexBucketsPerShard * IndexBucketSize
	require.Equal(t, capacity, MaxOwners*MaxRootsPerOwner, "the owners can fill the index")
	store := New()
	// 8 MiB has 131 072 granules, approx. 32 for each of the 4 096 home
	// buckets. The multiplicative hash spreads consecutive keys evenly.
	backing := make([]byte, 8<<20+64)
	start := (-int(uintptr(unsafe.Pointer(unsafe.SliceData(backing))))) & 63
	home := func(offset int) int {
		address := uintptr(unsafe.Pointer(&backing[offset]))
		shard, bucket := store.shardOf(indexHash(granuleKey(address, false)))
		index := (uintptr(unsafe.Pointer(shard)) - uintptr(unsafe.Pointer(&store.index[0]))) / unsafe.Sizeof(store.index[0])
		return int(index)*IndexBucketsPerShard + bucket
	}
	var perHome [IndexShards * IndexBucketsPerShard][]int
	var spare []int // windows whose home bucket already has IndexBucketSize keys
	for offset := start; offset+64 <= len(backing); offset += 64 {
		h := home(offset)
		if len(perHome[h]) < IndexBucketSize {
			perHome[h] = append(perHome[h], offset)
		} else if len(spare) < 1 && h/IndexBucketsPerShard != 0 {
			spare = append(spare, offset)
		}
	}
	for h := range perHome {
		require.Lenf(t, perHome[h], IndexBucketSize, "home bucket %d has too few granules", h)
	}
	require.Len(t, spare, 1, "a window outside shard 0")
	// The last window of home bucket 0 (shard 0) is kept for the end.
	last := perHome[0][IndexBucketSize-1]
	perHome[0] = perHome[0][:IndexBucketSize-1]
	adopt := func(owner *Owner, offset int) bool {
		_, ok := owner.AdoptBytes(backing[offset:offset+16:offset+16], mustSet(t, ranges.DefaultLimit, 16, r(0, 16, 1)))
		return ok
	}

	owners := make([]*Owner, MaxOwners)
	for i := range owners {
		owners[i] = store.Acquire()
		require.False(t, owners[i].Disabled())
	}
	admitted := 0
	for h := range perHome {
		for _, offset := range perHome[h] {
			owner := owners[admitted/MaxRootsPerOwner]
			require.Truef(t, adopt(owner, offset), "root %d (home bucket %d): %+v", admitted, h, owner.Counters())
			admitted++
		}
	}
	require.Equal(t, capacity-1, admitted)
	stats := store.Stats()
	require.Equal(t, int32(admitted), stats.IndexedRoots)
	require.Equal(t, uint32(admitted), stats.IndexRefs)
	require.Zero(t, stats.MaxProbe, "each root is in its home bucket")

	// The last owner has one free root slot. The window of the spare root
	// is full (all its buckets are full), so the index refuses it.
	final := owners[MaxOwners-1]
	require.False(t, adopt(final, spare[0]), "a root with a full probe window is refused")
	require.Equal(t, uint64(1), final.Counters().IndexFull)
	// Home bucket 0 has one free entry: the last root uses it.
	require.True(t, adopt(final, last), "the last free entry is used")
	stats = store.Stats()
	require.Equal(t, int32(capacity), stats.IndexedRoots)
	require.Equal(t, uint32(capacity), stats.IndexRefs)
	require.Equal(t, int64(capacity)*sizeClass(16), store.ProcessCharged())
	requireFilterConsistent(t, store)
	for _, owner := range owners {
		owner.Finish()
	}
	requireIndexEmpty(t, store)
	require.Zero(t, store.ProcessCharged())
	runtime.KeepAlive(backing)
}

func TestBindingLimit(t *testing.T) {
	type object struct{ index int }
	store := New()
	owner := store.Acquire()
	objects := make([]*object, MaxBindings+1)
	for i := 0; i < MaxBindings; i++ {
		objects[i] = &object{index: i}
		require.True(t, BindObject(owner, objects[i], BindingURL))
	}
	objects[MaxBindings] = &object{index: MaxBindings}
	require.False(t, BindObject(owner, objects[MaxBindings], BindingURL))
	require.Greater(t, owner.Counters().Full, uint64(0))
	owner.Finish()
}

func TestReaderBindingLimit(t *testing.T) {
	type reader struct{ index int }
	store := New()
	owner := store.Acquire()
	readers := make([]*reader, MaxReaderBindings+1)
	for i := 0; i < MaxReaderBindings; i++ {
		readers[i] = &reader{index: i}
		require.True(t, BindObject(owner, readers[i], BindingReader))
	}
	readers[MaxReaderBindings] = &reader{index: MaxReaderBindings}
	require.False(t, BindObject(owner, readers[MaxReaderBindings], BindingReader))
	require.Greater(t, owner.Counters().Full, uint64(0))
	owner.Finish()
}

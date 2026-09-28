// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestRootAdmissionRollbackOnIndexContention(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	var set, overflowSet ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: 4, SourceID: 7}}, 8).Valid)
	overflowRanges := make([]ranges.Range, GuaranteedRanges+1)
	for index := range overflowRanges {
		overflowRanges[index] = ranges.Range{Start: uint32(index * 2), Length: 1, SourceID: ranges.SourceID(index)}
	}
	require.True(t, ranges.AdoptCanonical(&overflowSet, ranges.Limit(GuaranteedRanges+1), overflowRanges, 22).Valid)
	require.Equal(t, len(overflowRanges), overflowSet.Len())
	adopted := make([]byte, 4, 8)
	copy(adopted, "data")
	overflowValue := make([]byte, 22)
	forceIndexCollision.Store(true)
	t.Cleanup(func() { forceIndexCollision.Store(false) })
	shard := &store.index[0]
	shard.mu.Lock()
	_, _, taintStringOK := owner.TaintString("value", 1)
	_, _, _, sourceStringOK := owner.TaintSourceString("value", "name", 1)
	_, _, taintBytesOK := owner.TaintBytes(make([]byte, 4, 8), 2)
	_, _, _, _, sourceBytesOK := owner.TaintSourceBytes(make([]byte, 4, 8), "name", 3)
	_, _, _, adoptSourceOK := owner.AdoptSourceBytes(adopted, "name", 4)
	_, adoptStringOK := owner.AdoptString(strings.Clone("text"), &set)
	_, adoptOverflowOK := owner.AdoptBytes(overflowValue, &overflowSet)
	shard.mu.Unlock()
	require.False(t, taintStringOK)
	require.False(t, sourceStringOK)
	require.False(t, taintBytesOK)
	require.False(t, sourceBytesOK)
	require.False(t, adoptSourceOK)
	require.False(t, adoptStringOK)
	require.False(t, adoptOverflowOK)
	require.Zero(t, owner.Charged())
	require.Equal(t, uint16(OverflowBlocks), store.overflowN)
	require.Zero(t, owner.owner.rootCount.Load())
	requireIndexEmpty(t, store)
	require.Equal(t, uint64(7), owner.Counters().Contention)
}

func TestInteriorWindowBoundsAndGeneration(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	managed, root, ok := owner.TaintBytes(make([]byte, 258), 1)
	require.True(t, ok)
	base, ok := BytesKey(managed)
	require.True(t, ok)
	// Windows outside the root are a miss.
	require.Nil(t, lookupRanges(t, store, Key{Pointer: base.Pointer - 1, Length: 2, Kind: KindBytes}))
	require.Nil(t, lookupRanges(t, store, Key{Pointer: base.Pointer + uintptr(cap(managed)-1), Length: 2, Kind: KindBytes}))
	// Every window of the root is found with no derivation.
	for offset := 0; offset+2 <= len(managed); offset++ {
		key, valid := BytesKey(managed[offset : offset+2])
		require.True(t, valid)
		require.Equalf(t, []ranges.Range{{Length: 2, SourceID: 1}}, lookupRanges(t, store, key), "offset %d", offset)
	}
	contended, ok := BytesKey(managed[1:3])
	require.True(t, ok)
	owner.owner.rootsMu.Lock()
	var snapshot Snapshot
	found := store.Lookup(contended, &snapshot)
	owner.owner.rootsMu.Unlock()
	require.True(t, found, "a busy owner is a safe miss, not a failed lookup")
	require.Zero(t, snapshot.Len())

	managed[0] = 1
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Start: 2, Length: 2, SourceID: 2}}, uint32(cap(managed))).Valid)
	next, ok := owner.PublishBytesMutation(root, managed, &set)
	require.True(t, ok)
	require.Equal(t, root.ID, next.ID)
	require.Equal(t, []ranges.Range{{Start: 1, Length: 1, SourceID: 2}}, lookupRanges(t, store, contended))

	// A busy index shard fails the lookup.
	shard, _ := store.shardOf(indexHash(granuleKey(contended.Pointer, true)))
	shard.mu.Lock()
	found = store.Lookup(contended, &snapshot)
	shard.mu.Unlock()
	require.False(t, found)
	require.Zero(t, snapshot.Len())
	counters := owner.Counters()
	require.GreaterOrEqual(t, counters.Contention, uint64(1))
	require.GreaterOrEqual(t, store.Counters().Contention, uint64(1))
}

func TestRepeatedAdoptionExtendsOneRoot(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	value := make([]byte, 8)
	var firstSet, secondSet ranges.Set
	require.True(t, ranges.AdoptCanonical(&firstSet, ranges.DefaultLimit, []ranges.Range{{Length: 4, SourceID: 1}}, 8).Valid)
	require.True(t, ranges.AdoptCanonical(&secondSet, ranges.DefaultLimit, []ranges.Range{{Start: 4, Length: 4, SourceID: 2}}, 8).Valid)
	first, ok := owner.AdoptBytes(value, &firstSet)
	require.True(t, ok)
	stats := store.Stats()
	second, ok := owner.AdoptBytes(value, &secondSet)
	require.True(t, ok)
	require.Equal(t, first, second, "a second adoption extends the first root")
	require.Equal(t, int32(1), owner.owner.rootCount.Load())
	require.Equal(t, stats, store.Stats())
	key, ok := BytesKey(value)
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 1}, {Start: 4, Length: 4, SourceID: 2}}, lookupRanges(t, store, key))
	require.Equal(t, 2*sizeClass(8), owner.Charged(), "each adoption keeps its charge until Finish")
}

func TestSourceAdmissionsObserveRootByteQuota(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	fillOwnerRootQuota(t, owner)
	_, _, _, ok := owner.TaintSourceString("value", "name", 1)
	require.False(t, ok)
	_, _, ok = owner.TaintBytes([]byte("value"), 1)
	require.False(t, ok)
	_, _, _, _, ok = owner.TaintSourceBytes([]byte("value"), "name", 1)
	require.False(t, ok)
	_, _, _, ok = owner.AdoptSourceBytes([]byte("value"), "name", 1)
	require.False(t, ok)
	require.Equal(t, int64(RequestRootBytes), owner.Charged())
	require.GreaterOrEqual(t, owner.Counters().Bytes, uint64(4))
}

func TestMutationKeepsInteriorWindowsAndFinishedOwnerRefuses(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintBytes(make([]byte, 16), 1)
	require.True(t, ok)
	sibling, ok := BytesKey(managed[2:6])
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 1}}, lookupRanges(t, store, sibling))

	managed[0] = 1
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: 16, SourceID: 2}}, 16).Valid)
	next, ok := owner.PublishBytesMutation(root, managed, &set)
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 2}}, lookupRanges(t, store, sibling))
	_, ok = owner.PublishBytesMutation(root, managed, &set)
	require.False(t, ok, "a stale reference cannot claim the root")
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 2}}, lookupRanges(t, store, sibling))
	owner.Finish()

	_, _, _, ok = owner.TaintSourceString("value", "name", 1)
	require.False(t, ok)
	_, ok = owner.AdoptBytes(managed, &set)
	require.False(t, ok)
	_, ok = owner.PublishBytesMutation(next, managed, &set)
	require.False(t, ok)
	require.Nil(t, lookupRanges(t, store, sibling))
	requireIndexEmpty(t, store)
}

func TestOversizedStringAdmissionDoesNotReserveRoot(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	value := strings.Repeat("x", MaxRootBytes+1)
	managed, ref, ok := owner.TaintString(value, 1)
	require.False(t, ok)
	require.Equal(t, value, managed)
	require.Equal(t, RootRef{}, ref)
	require.Zero(t, owner.Charged())
	require.Equal(t, uint64(1), owner.Counters().Bytes)
}

func fillOwnerRootQuota(t *testing.T, owner *Owner) {
	t.Helper()
	for index := 0; index < RequestRootBytes/MaxRootBytes; index++ {
		value := make([]byte, MaxRootBytes)
		value[0], value[1] = byte(index), byte(index>>8)
		_, _, ok := owner.TaintBytes(value, 1)
		require.Truef(t, ok, "root %d", index)
	}
}

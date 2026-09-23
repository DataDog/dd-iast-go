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

func TestRootAdmissionRollbackOnValueTableContention(t *testing.T) {
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
	forceCollision.Store(true)
	t.Cleanup(func() { forceCollision.Store(false) })
	shard := &store.shards[0]
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
	require.Zero(t, owner.Values())
	require.Equal(t, uint64(7), owner.Counters().Contention)
}

func TestDerivedWindowBoundsQuotaAndGeneration(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	managed, root, ok := owner.TaintBytes(make([]byte, MaxValuesPerRoot+2), 1)
	require.True(t, ok)
	base, ok := BytesKey(managed)
	require.True(t, ok)
	require.False(t, owner.Derive(Key{Pointer: base.Pointer - 1, Length: 2, Kind: KindBytes}, root))
	require.False(t, owner.Derive(Key{Pointer: base.Pointer + uintptr(cap(managed)-1), Length: 2, Kind: KindBytes}, root))
	contended, ok := BytesKey(managed[1:3])
	require.True(t, ok)
	owner.owner.rootsMu.Lock()
	derived := owner.Derive(contended, root)
	owner.owner.rootsMu.Unlock()
	require.False(t, derived)
	for offset := 1; offset < MaxValuesPerRoot; offset++ {
		key, valid := BytesKey(managed[offset : offset+2])
		require.True(t, valid)
		require.Truef(t, owner.Derive(key, root), "offset %d", offset)
	}
	extra, ok := BytesKey(managed[MaxValuesPerRoot : MaxValuesPerRoot+2])
	require.True(t, ok)
	require.False(t, owner.Derive(extra, root))
	require.Equal(t, int32(MaxValuesPerRoot), owner.Values())
	managed[0] = 1
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(managed)), SourceID: 2}}, uint32(cap(managed))).Valid)
	next, ok := owner.PublishBytesMutation(root, managed, &set)
	require.True(t, ok)
	require.False(t, owner.Derive(contended, root))
	require.True(t, owner.Derive(contended, next))
	require.Equal(t, int32(2), owner.Values())
	forceCollision.Store(true)
	t.Cleanup(func() { forceCollision.Store(false) })
	blocked, ok := BytesKey(managed[2:4])
	require.True(t, ok)
	shard := &store.shards[0]
	shard.mu.Lock()
	derived = owner.Derive(blocked, next)
	shard.mu.Unlock()
	require.False(t, derived)
	counters := owner.Counters()
	require.GreaterOrEqual(t, counters.Full, uint64(3))
	require.GreaterOrEqual(t, counters.Contention, uint64(2))
	require.GreaterOrEqual(t, counters.Stale, uint64(1))
}

func TestExistingWindowTransfersRootReservation(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	value := make([]byte, 8)
	var firstSet, secondSet ranges.Set
	require.True(t, ranges.AdoptCanonical(&firstSet, ranges.DefaultLimit, []ranges.Range{{Length: 4, SourceID: 1}}, 8).Valid)
	require.True(t, ranges.AdoptCanonical(&secondSet, ranges.DefaultLimit, []ranges.Range{{Start: 4, Length: 4, SourceID: 2}}, 8).Valid)
	first, ok := owner.AdoptBytes(value, &firstSet)
	require.True(t, ok)
	second, ok := owner.AdoptBytes(value, &secondSet)
	require.True(t, ok)
	require.NotEqual(t, first.ID, second.ID)
	require.Zero(t, uint32(owner.owner.roots[first.ID].valueQuota.Load()))
	require.Equal(t, uint32(1), uint32(owner.owner.roots[second.ID].valueQuota.Load()))
	require.Equal(t, int32(1), owner.Values())
	key, ok := BytesKey(value)
	require.True(t, ok)
	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Start: 4, Length: 4, SourceID: 2}}, rangeSlice(&entry.Ranges))
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

func TestStaleOwnerRootAndLazyGenerationReclamation(t *testing.T) {
	store := New()
	owner := store.Acquire()
	forceCollision.Store(true)
	t.Cleanup(func() { forceCollision.Store(false) })
	managed, root, ok := owner.TaintBytes(make([]byte, 16), 1)
	require.True(t, ok)
	sibling, ok := BytesKey(managed[2:6])
	require.True(t, ok)
	require.True(t, owner.Derive(sibling, root))

	managed[0] = 1
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: 16, SourceID: 2}}, 16).Valid)
	next, ok := owner.PublishBytesMutation(root, managed, &set)
	require.True(t, ok, "publishing the base lazily reclaims its old-generation slot")
	require.True(t, owner.Derive(sibling, next), "publishing the sibling lazily reclaims its stale slot")
	require.Equal(t, int32(2), owner.Values())

	key, ok := BytesKey(managed)
	require.True(t, ok)
	require.False(t, owner.Derive(Key{}, next))
	require.False(t, owner.Derive(key, RootRef{ID: MaxRootsPerOwner, Generation: next.Generation}))
	require.False(t, owner.Derive(Key{Pointer: ^uintptr(0), Length: 2, Kind: KindBytes}, next))
	require.False(t, owner.Derive(key, root))
	owner.Finish()

	_, _, _, ok = owner.TaintSourceString("value", "name", 1)
	require.False(t, ok)
	_, ok = owner.AdoptBytes(managed, &set)
	require.False(t, ok)
	require.False(t, owner.Derive(key, next))
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

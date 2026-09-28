// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"strings"
	"testing"

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
	require.Greater(t, admitted, MaxOwners*MaxRootsPerOwner*9/10, "the index must hold most of the roots")
	refused := uint64(0)
	for _, owner := range owners {
		refused += owner.Counters().IndexFull
	}
	require.Equal(t, uint64(MaxOwners*MaxRootsPerOwner-admitted), refused)
	requireFilterConsistent(t, store)
	for _, owner := range owners {
		owner.Finish()
	}
	requireIndexEmpty(t, store)
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

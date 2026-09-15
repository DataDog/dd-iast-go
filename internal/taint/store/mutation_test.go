// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestByteMutationPublishesRootRangesAndInvalidatesSiblings(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintBytes([]byte("abcd"), 0)
	require.True(t, ok)
	sibling := managed[1:3]
	siblingKey, _ := BytesKey(sibling)
	require.True(t, owner.Derive(siblingKey, root))

	managed[1] = 'X'
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, 10, []ranges.Range{
		{Length: 1, SourceID: 0},
		{Start: 2, Length: 2, SourceID: 0},
	}, uint32(cap(managed))).Valid)
	newRoot, ok := owner.PublishBytesMutation(root, managed, &set)
	require.True(t, ok)
	require.NotEqual(t, root.Generation, newRoot.Generation)

	key, _ := BytesKey(managed)
	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	require.Equal(t, []ranges.Range{
		{Length: 1, SourceID: 0},
		{Start: 2, Length: 2, SourceID: 0},
	}, rangeSlice(&entry.Ranges))

	require.True(t, store.Lookup(siblingKey, &snapshot))
	require.Zero(t, snapshot.Len(), "old-generation sibling windows must be invisible")
	owner.Finish()
}

func TestMutationQuotaResetsAcrossGenerations(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintBytes([]byte("abcd"), 0)
	require.True(t, ok)
	for i := 0; i < MaxValuesPerRoot+50; i++ {
		managed[0]++
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: uint32(len(managed)), SourceID: 0}}, uint32(cap(managed))).Valid)
		root, ok = owner.PublishBytesMutation(root, managed, &set)
		require.Truef(t, ok, "mutation %d", i)
	}
	owner.Finish()
	require.Zero(t, store.ProcessValues())
}

func TestFailedMutationInvalidatesOldTaint(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintBytes([]byte("abcd"), 0)
	require.True(t, ok)
	managed[0] = 'X'
	_, ok = owner.PublishBytesMutation(root, managed, nil)
	require.False(t, ok)
	key, _ := BytesKey(managed)
	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	require.Zero(t, snapshot.Len(), "pre-mutation provenance must not survive failed publication")
	owner.Finish()
}

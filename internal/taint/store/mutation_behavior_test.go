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

func TestMutationOverflowReplacementReleasesPreviousBlock(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value, root, ok := owner.TaintBytes(make([]byte, 2*(GuaranteedRanges+1)), 0)
	require.True(t, ok)
	raw := make([]ranges.Range, GuaranteedRanges+1)
	for index := range raw {
		raw[index] = ranges.Range{Start: uint32(2 * index), Length: 1, SourceID: ranges.SourceID(index)}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.Limit(len(raw)), raw, uint32(cap(value))).Valid)
	key, ok := BytesKey(value)
	require.True(t, ok)
	for generation := range 2 {
		value[1] = byte(generation + 1)
		root, ok = owner.PublishBytesMutation(root, value, &set)
		require.True(t, ok)
		require.Equal(t, uint16(OverflowBlocks-1), s.overflowN)
		var snapshot Snapshot
		require.True(t, s.Lookup(key, &snapshot))
		entry, found := snapshot.At(0)
		require.True(t, found)
		require.Equal(t, raw, rangeSlice(&entry.Ranges))
	}
	owner.Finish()
	require.Equal(t, uint16(OverflowBlocks), s.overflowN)
	require.Zero(t, s.ProcessCharged())
}

func TestMutationOverflowContentionKeepsOnlyGuaranteedRanges(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value, root, ok := owner.TaintBytes(make([]byte, 2*(GuaranteedRanges+1)), 0)
	require.True(t, ok)
	raw := make([]ranges.Range, GuaranteedRanges+1)
	for index := range raw {
		raw[index] = ranges.Range{Start: uint32(2 * index), Length: 1, SourceID: ranges.SourceID(index)}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.Limit(len(raw)), raw, uint32(cap(value))).Valid)
	value[1] = 'X'
	s.overflowMu.Lock()
	_, published := owner.PublishBytesMutation(root, value, &set)
	s.overflowMu.Unlock()
	require.True(t, published)
	key, ok := BytesKey(value)
	require.True(t, ok)
	var snapshot Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	entry, found := snapshot.At(0)
	require.True(t, found)
	require.Equal(t, raw[:GuaranteedRanges], rangeSlice(&entry.Ranges))
	require.Equal(t, uint64(1), owner.Counters().Ranges)
	require.Equal(t, uint16(OverflowBlocks), s.overflowN)
}

func TestMutationRootContentionReleasesPreparedOverflow(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value, root, ok := owner.TaintBytes(make([]byte, 2*(GuaranteedRanges+1)), 0)
	require.True(t, ok)
	raw := make([]ranges.Range, GuaranteedRanges+1)
	for index := range raw {
		raw[index] = ranges.Range{Start: uint32(2 * index), Length: 1, SourceID: ranges.SourceID(index)}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.Limit(len(raw)), raw, uint32(cap(value))).Valid)
	value[1] = 'X'
	owner.owner.rootsMu.Lock()
	_, published := owner.PublishBytesMutation(root, value, &set)
	owner.owner.rootsMu.Unlock()
	require.False(t, published)
	require.Equal(t, uint16(OverflowBlocks), s.overflowN)
	require.Equal(t, uint64(1), owner.Counters().Contention)
	key, ok := BytesKey(value)
	require.True(t, ok)
	var snapshot Snapshot
	s.Lookup(key, &snapshot)
	require.Zero(t, snapshot.Len(), "failed publication must not restore pre-mutation taint")
}

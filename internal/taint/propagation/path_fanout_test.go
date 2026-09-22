// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestPathOwnerFanoutStopsAtFourOwners(t *testing.T) {
	s, _ := beginScope(t)
	owners := make([]*store.Owner, store.MaxSnapshotOwners+1)
	for index := range owners {
		owners[index] = acquireOwner(t, s)
	}

	firstString := strings.Clone("first-input")
	secondString := strings.Clone("second-input")
	firstBytes := bytes.Clone([]byte("first-bytes"))
	secondBytes := bytes.Clone([]byte("second-bytes"))
	var firstStringSet, secondStringSet, firstByteSet, secondByteSet ranges.Set
	require.True(t, ranges.AdoptCanonical(&firstStringSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(firstString)), SourceID: 10}}, uint32(len(firstString))).Valid)
	require.True(t, ranges.AdoptCanonical(&secondStringSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(secondString)), SourceID: 99}}, uint32(len(secondString))).Valid)
	require.True(t, ranges.AdoptCanonical(&firstByteSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(firstBytes)), SourceID: 11}}, uint32(cap(firstBytes))).Valid)
	require.True(t, ranges.AdoptCanonical(&secondByteSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(secondBytes)), SourceID: 98}}, uint32(cap(secondBytes))).Valid)

	for _, owner := range owners[:store.MaxSnapshotOwners] {
		_, ok := owner.AdoptString(firstString, &firstStringSet)
		require.True(t, ok)
		_, ok = owner.AdoptBytes(firstBytes, &firstByteSet)
		require.True(t, ok)
	}
	excluded := owners[store.MaxSnapshotOwners]
	_, ok := excluded.AdoptString(secondString, &secondStringSet)
	require.True(t, ok)
	_, ok = excluded.AdoptBytes(secondBytes, &secondByteSet)
	require.True(t, ok)
	excludedCharged := excluded.Charged()
	excludedValues := excluded.Values()

	joinedStringNative := strings.Join([]string{firstString, secondString}, ":")
	joinedString := propagation.JoinString([]string{firstString, secondString}, ":", joinedStringNative)
	require.Equal(t, joinedStringNative, joinedString)
	requirePublishedOwners(t, s, joinedString, owners[:store.MaxSnapshotOwners], ranges.Range{Length: uint32(len(firstString)), SourceID: 10})

	coarseStringNative := strings.Join([]string{"coarse", firstString, secondString}, "|")
	coarseString := propagation.CoarseString(coarseStringNative, firstString, secondString)
	require.Equal(t, coarseStringNative, coarseString)
	requirePublishedOwners(t, s, coarseString, owners[:store.MaxSnapshotOwners], ranges.Range{Length: uint32(len(coarseStringNative)), SourceID: 10})

	formatNative := fmt.Sprint(firstString, secondString)
	formatted := propagation.CoarseFormatString(formatNative, []any{firstString, secondString})
	require.Equal(t, formatNative, formatted)
	requirePublishedOwners(t, s, formatted, owners[:store.MaxSnapshotOwners], ranges.Range{Length: uint32(len(formatNative)), SourceID: 10})

	joinedBytesNative := bytes.Join([][]byte{firstBytes, secondBytes}, []byte(":"))
	joinedBytes := propagation.JoinBytes([][]byte{firstBytes, secondBytes}, []byte(":"), joinedBytesNative)
	require.Equal(t, joinedBytesNative, joinedBytes)
	requirePublishedByteOwners(t, s, joinedBytes, owners[:store.MaxSnapshotOwners], ranges.Range{Length: uint32(len(firstBytes)), SourceID: 11})

	coarseBytesNative := []byte("coarse-byte-result")
	coarseBytes := propagation.CoarseBytes(coarseBytesNative, firstBytes, secondBytes)
	require.Equal(t, coarseBytesNative, coarseBytes)
	requirePublishedByteOwners(t, s, coarseBytes, owners[:store.MaxSnapshotOwners], ranges.Range{Length: uint32(len(coarseBytesNative)), SourceID: 11})
	require.Equal(t, excludedCharged, excluded.Charged(), "the bounded-out owner must not retain result anchors")
	require.Equal(t, excludedValues, excluded.Values(), "the bounded-out owner must not publish result values")
}

func requirePublishedOwners(t *testing.T, s *store.Store, value string, included []*store.Owner, expected ranges.Range) {
	t.Helper()
	key, ok := store.StringKey(value)
	require.True(t, ok)
	requirePublishedOwnerSnapshot(t, s, key, included, expected)
}

func requirePublishedByteOwners(t *testing.T, s *store.Store, value []byte, included []*store.Owner, expected ranges.Range) {
	t.Helper()
	key, ok := store.BytesKey(value)
	require.True(t, ok)
	requirePublishedOwnerSnapshot(t, s, key, included, expected)
}

func requirePublishedOwnerSnapshot(t *testing.T, s *store.Store, key store.Key, included []*store.Owner, expected ranges.Range) {
	t.Helper()
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, len(included), snapshot.Len())
	got := make(map[uint64]struct{}, snapshot.Len())
	for index := 0; index < snapshot.Len(); index++ {
		entry, ok := snapshot.At(index)
		require.True(t, ok)
		got[entry.OwnerID] = struct{}{}
		require.Equal(t, 1, entry.Ranges.Len())
		actual, ok := entry.Ranges.At(0)
		require.True(t, ok)
		require.Equal(t, expected, actual)
	}
	for _, owner := range included {
		require.Contains(t, got, owner.ID())
	}
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestStaleOwnerPrivateHelperLinkage(t *testing.T) {
	s := store.New()
	owner := s.Acquire()
	managed, _, ok := owner.TaintString("stale-owner", 1)
	require.True(t, ok)

	key, ok := store.StringKey(managed)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())

	owner.Finish()
	deriveStringWindow(managed[:5], &snapshot, s)

	require.Zero(t, s.ProcessCharged())
	require.Zero(t, s.ProcessValues())
}

func TestPublishHelpersDropStaleAndPreserveLiveOwner(t *testing.T) {
	s := store.New()
	stale := s.Acquire()
	live := s.Acquire()
	t.Cleanup(stale.Finish)
	t.Cleanup(live.Finish)

	sharedString := strings.Clone("shared-string")
	sharedBytes := bytes.Clone([]byte("shared-bytes"))
	var staleStringSet, liveStringSet, staleByteSet, liveByteSet ranges.Set
	require.True(t, ranges.AdoptCanonical(&staleStringSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(sharedString)), SourceID: 1, Marks: 0xe}}, uint32(len(sharedString))).Valid)
	require.True(t, ranges.AdoptCanonical(&liveStringSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(sharedString)), SourceID: 2, Marks: 0x6}}, uint32(len(sharedString))).Valid)
	require.True(t, ranges.AdoptCanonical(&staleByteSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(sharedBytes)), SourceID: 3, Marks: 0xa}}, uint32(cap(sharedBytes))).Valid)
	require.True(t, ranges.AdoptCanonical(&liveByteSet, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(sharedBytes)), SourceID: 4, Marks: 0x2}}, uint32(cap(sharedBytes))).Valid)

	_, ok := stale.AdoptString(sharedString, &staleStringSet)
	require.True(t, ok)
	_, ok = live.AdoptString(sharedString, &liveStringSet)
	require.True(t, ok)
	_, ok = stale.AdoptBytes(sharedBytes, &staleByteSet)
	require.True(t, ok)
	_, ok = live.AdoptBytes(sharedBytes, &liveByteSet)
	require.True(t, ok)

	stringSnapshot := lookupStringSnapshot(t, s, sharedString)
	byteSnapshot := lookupBytesSnapshot(t, s, sharedBytes)
	require.Equal(t, 2, stringSnapshot.Len())
	require.Equal(t, 2, byteSnapshot.Len())
	var coarseOwners [store.MaxSnapshotOwners]coarseOwner
	for index := 0; index < stringSnapshot.Len(); index++ {
		entry, found := stringSnapshot.At(index)
		require.True(t, found)
		coarseOwners[index].entry = *entry
		coarseAccumulate(&coarseOwners[index], &entry.Ranges)
	}

	staleIndex, ok := stale.Index()
	require.True(t, ok)
	staleGeneration := stale.Generation()
	staleID := stale.ID()
	stale.Finish()
	reused := s.Acquire()
	t.Cleanup(reused.Finish)
	reusedIndex, ok := reused.Index()
	require.True(t, ok)
	require.Equal(t, staleIndex, reusedIndex)
	require.NotEqual(t, staleGeneration, reused.Generation())
	require.NotEqual(t, staleID, reused.ID())

	stringWindow := sharedString[1:5]
	deriveStringWindow(stringWindow, &stringSnapshot, s)
	requireSingleStringOwner(t, s, stringWindow, live.ID(), ranges.Range{Length: uint32(len(stringWindow)), SourceID: 2, Marks: 0x6})

	stringCopy := strings.Clone(sharedString)
	publishStringCopy(stringCopy, uint32(len(sharedString)), &stringSnapshot, s)
	requireSingleStringOwner(t, s, stringCopy, live.ID(), ranges.Range{Length: uint32(len(stringCopy)), SourceID: 2, Marks: 0x6})

	stringRepeat := strings.Repeat(sharedString, 2)
	publishStringRepeat(stringRepeat, uint32(len(sharedString)), 2, &stringSnapshot, s)
	requireSingleStringOwner(t, s, stringRepeat, live.ID(), ranges.Range{Length: uint32(len(stringRepeat)), SourceID: 2, Marks: 0x6})

	byteWindow := sharedBytes[1:5]
	deriveBytesWindow(byteWindow, &byteSnapshot, s)
	requireSingleByteOwner(t, s, byteWindow, live.ID(), ranges.Range{Length: uint32(len(byteWindow)), SourceID: 4, Marks: 0x2})

	byteCopy := bytes.Clone(sharedBytes)
	publishBytesCopy(byteCopy, uint32(len(sharedBytes)), &byteSnapshot, s)
	requireSingleByteOwner(t, s, byteCopy, live.ID(), ranges.Range{Length: uint32(len(byteCopy)), SourceID: 4, Marks: 0x2})

	byteRepeat := bytes.Repeat(sharedBytes, 2)
	publishBytesRepeat(byteRepeat, uint32(len(sharedBytes)), 2, &byteSnapshot, s)
	requireSingleByteOwner(t, s, byteRepeat, live.ID(), ranges.Range{Length: uint32(len(byteRepeat)), SourceID: 4, Marks: 0x2})

	coarse := publishCoarseOwners(s, "coarse-result", &coarseOwners, stringSnapshot.Len())
	require.Equal(t, "coarse-result", coarse)
	requireSingleStringOwner(t, s, coarse, live.ID(), ranges.Range{Length: uint32(len(coarse)), SourceID: 2, Marks: 0x6})

	require.Zero(t, reused.Charged(), "a stale snapshot must not publish into the reused owner slot")
	require.Zero(t, reused.Values())
	require.Equal(t, live.Charged(), s.ProcessCharged(), "only live-owner anchors may remain charged")
	require.Equal(t, live.Values(), s.ProcessValues(), "only live-owner values may remain published")

	live.Finish()
	require.Zero(t, s.ProcessCharged())
	require.Zero(t, s.ProcessValues())
}

func lookupStringSnapshot(t *testing.T, s *store.Store, value string) store.Snapshot {
	t.Helper()
	key, ok := store.StringKey(value)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	return snapshot
}

func lookupBytesSnapshot(t *testing.T, s *store.Store, value []byte) store.Snapshot {
	t.Helper()
	key, ok := store.BytesKey(value)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	return snapshot
}

func requireSingleStringOwner(t *testing.T, s *store.Store, value string, ownerID uint64, expected ranges.Range) {
	t.Helper()
	snapshot := lookupStringSnapshot(t, s, value)
	requireSingleOwner(t, &snapshot, ownerID, expected)
}

func requireSingleByteOwner(t *testing.T, s *store.Store, value []byte, ownerID uint64, expected ranges.Range) {
	t.Helper()
	snapshot := lookupBytesSnapshot(t, s, value)
	requireSingleOwner(t, &snapshot, ownerID, expected)
}

func requireSingleOwner(t *testing.T, snapshot *store.Snapshot, ownerID uint64, expected ranges.Range) {
	t.Helper()
	require.Equal(t, 1, snapshot.Len())
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	require.Equal(t, ownerID, entry.OwnerID)
	require.Equal(t, 1, entry.Ranges.Len())
	value, ok := entry.Ranges.At(0)
	require.True(t, ok)
	require.Equal(t, expected, value)
}

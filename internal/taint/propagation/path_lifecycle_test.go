// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestPathFinishedOwnerStaleSlotsAreDropped(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)

	staleString, _ := taintString(t, owner, "stale-value", []ranges.Range{{Length: 11, SourceID: 1, Marks: 0xe}})
	staleBytes, _ := taintBytes(t, owner, []byte("stale-bytes"), []ranges.Range{{Length: 11, SourceID: 2, Marks: 0x6}})
	invalidUTF8, _ := taintBytes(t, owner, []byte{'a', 0xff, 'b'}, []ranges.Range{{Length: 3, SourceID: 3, Marks: 0x2}})
	document, _ := taintBytes(t, owner, []byte(`{"value":"attack"}`), []ranges.Range{{Start: 10, Length: 6, SourceID: 4, Marks: 0xa}})
	literal := document[9:17]

	adoptNative := strings.Clone(staleString)
	repeatNative := strings.Repeat(staleString, 2)
	caseNative := strings.ToUpper(staleString)
	copyNative := bytes.Clone(staleBytes)
	byteWindow := staleBytes[:5]
	repeatBytesNative := bytes.Repeat(staleBytes, 2)
	validUTF8Native := bytes.ToValidUTF8(invalidUTF8, []byte("?"))
	jsonNative := strings.Clone("attack")

	staleKeys := []store.Key{
		mustStringKey(t, staleString),
		mustBytesKey(t, staleBytes),
		mustBytesKey(t, invalidUTF8),
		mustBytesKey(t, document),
	}
	owner.Finish()

	require.Zero(t, owner.Charged())
	require.Zero(t, s.ProcessCharged())
	require.Zero(t, s.ProcessValues())
	for _, key := range staleKeys {
		requireStaleSlot(t, s, key)
	}

	adopted := propagation.AdoptStringCopy(staleString, adoptNative)
	require.True(t, unsafe.StringData(adopted) == unsafe.StringData(adoptNative))
	require.Nil(t, lookupRanges(s, adopted))

	repeated := propagation.RepeatString(staleString, repeatNative, 2)
	require.True(t, unsafe.StringData(repeated) == unsafe.StringData(repeatNative))
	require.Nil(t, lookupRanges(s, repeated))

	cased := propagation.CaseString(staleString, caseNative)
	require.True(t, unsafe.StringData(cased) == unsafe.StringData(caseNative))
	require.Nil(t, lookupRanges(s, cased))

	copied := propagation.CopyBytes(staleBytes, copyNative)
	require.True(t, unsafe.SliceData(copied) == unsafe.SliceData(copyNative))
	require.Nil(t, lookupByteRanges(s, copied))

	propagation.ByteWindows(staleBytes, [][]byte{byteWindow})
	require.Nil(t, lookupByteRanges(s, byteWindow))

	repeatedBytes := propagation.RepeatBytes(staleBytes, repeatBytesNative, 2)
	require.True(t, unsafe.SliceData(repeatedBytes) == unsafe.SliceData(repeatBytesNative))
	require.Nil(t, lookupByteRanges(s, repeatedBytes))

	validUTF8 := propagation.ValidUTF8Bytes(invalidUTF8, []byte("?"), validUTF8Native)
	require.True(t, unsafe.SliceData(validUTF8) == unsafe.SliceData(validUTF8Native))
	require.Nil(t, lookupByteRanges(s, validUTF8))

	decoded, propagated := propagation.JSONString(document, literal, jsonNative)
	require.False(t, propagated)
	require.True(t, unsafe.StringData(decoded) == unsafe.StringData(jsonNative))
	require.Nil(t, lookupRanges(s, decoded))

	require.Zero(t, s.ProcessCharged(), "stale slots must not restore released anchors")
	require.Zero(t, s.ProcessValues(), "stale slots must not publish new values")
}

func requireStaleSlot(t *testing.T, s *store.Store, key store.Key) {
	t.Helper()
	require.True(t, s.MayContain(key), "finished-owner slot must remain visible to the cheap gate")
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot), "an uncontended lookup must succeed")
	require.Zero(t, snapshot.Len(), "a finished owner must contribute zero live entries")
}

func mustStringKey(t *testing.T, value string) store.Key {
	t.Helper()
	key, ok := store.StringKey(value)
	require.True(t, ok)
	return key
}

func mustBytesKey(t *testing.T, value []byte) store.Key {
	t.Helper()
	key, ok := store.BytesKey(value)
	require.True(t, ok)
	return key
}

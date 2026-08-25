// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEqualLiteralDoesNotShareManagedTaint(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, _, ok := owner.TaintString("Header-Value", 0)
	require.True(t, ok)
	managedKey, _ := StringKey(managed)
	literalKey, _ := StringKey("Header-Value")
	require.NotEqual(t, managedKey.Pointer, literalKey.Pointer)
	var snapshot Snapshot
	require.True(t, store.Lookup(literalKey, &snapshot))
	require.Zero(t, snapshot.Len())
	owner.Finish()
}

func TestAddressReuseDoesNotReviveFinishedOwner(t *testing.T) {
	store := New()
	first := store.Acquire()
	managed, _, ok := first.TaintString(strings.Repeat("a", 64), 0)
	require.True(t, ok)
	oldKey, _ := StringKey(managed)
	first.Finish()
	managed = ""
	runtime.GC()

	second := store.Acquire()
	var reused string
	for i := 0; i < MaxRootsPerOwner; i++ {
		candidate, _, tainted := second.TaintString(strings.Repeat(string(rune('b'+i%20)), 64), 1)
		require.True(t, tainted)
		key, _ := StringKey(candidate)
		if key.Pointer == oldKey.Pointer {
			reused = candidate
			break
		}
	}
	if reused == "" {
		second.Finish()
		t.Skip("allocator did not reuse the address within the bounded attempt")
	}
	key, _ := StringKey(reused)
	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len(), "finished-owner slot must not reappear")
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	rangeValue, ok := entry.Ranges.At(0)
	require.True(t, ok)
	require.Equal(t, uint16(1), uint16(rangeValue.SourceID))
	second.Finish()
}

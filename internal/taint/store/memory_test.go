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

func TestManySubstringsChargeOneManagedRoot(t *testing.T) {
	store := New()
	owner := store.Acquire()
	original := strings.Repeat("x", MaxRootBytes)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	managed, _, ok := owner.TaintString(original, 0)
	require.True(t, ok)
	original = ""
	for i := 0; i < 255; i++ {
		start := i * 251 % (len(managed) - 2)
		key, valid := StringKey(managed[start : start+2])
		require.True(t, valid)
		require.NotNilf(t, lookupRanges(t, store, key), "substring %d", i)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	require.Equal(t, int64(MaxRootBytes), owner.Charged())
	require.Equal(t, int32(1), store.IndexedRoots().Load())
	if after.HeapAlloc > before.HeapAlloc {
		require.Less(t, after.HeapAlloc-before.HeapAlloc, uint64(256<<10), "substrings must not retain one parent per value")
	}
	owner.Finish()
	runtime.KeepAlive(managed)
	require.Zero(t, store.ProcessCharged())
}

func TestProbeBoundDropsCollisionOverflow(t *testing.T) {
	store := New()
	owner := store.Acquire()
	forceIndexCollision.Store(true)
	t.Cleanup(func() { forceIndexCollision.Store(false) })
	const window = IndexBucketProbe * IndexBucketSize
	values := make([]string, window+1)
	managed := make([]string, 0, window)
	for i := range values {
		// Values of 16 bytes use one tier S granule each.
		values[i] = strings.Repeat(string(rune('a'+i%20)), 15) + string(rune(i+40))
		value, _, ok := owner.TaintString(values[i], 0)
		if i < window {
			require.Truef(t, ok, "value %d", i)
			managed = append(managed, value)
		} else {
			require.False(t, ok)
		}
	}
	require.Equal(t, int32(window), store.IndexedRoots().Load())
	require.Equal(t, uint64(1), owner.Counters().IndexFull)
	for _, value := range managed {
		key, _ := StringKey(value)
		require.NotNil(t, lookupRanges(t, store, key))
	}
	owner.Finish()
	requireIndexEmpty(t, store)
}

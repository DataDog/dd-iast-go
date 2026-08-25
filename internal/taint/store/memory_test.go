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

	managed, root, ok := owner.TaintString(original, 0)
	require.True(t, ok)
	original = ""
	for i := 0; i < MaxValuesPerRoot-1; i++ {
		start := i % (len(managed) - 2)
		key, valid := StringKey(managed[start : start+2])
		require.True(t, valid)
		require.Truef(t, owner.Derive(key, root), "substring %d", i)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	require.Equal(t, int64(MaxRootBytes), owner.Charged())
	require.Equal(t, int32(MaxValuesPerRoot), owner.Values())
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
	forceCollision.Store(true)
	t.Cleanup(func() { forceCollision.Store(false) })
	values := make([]string, ProbeLimit+1)
	for i := range values {
		values[i] = strings.Clone(strings.Repeat(string(rune('a'+i%20)), 2) + string(rune(i+100)))
		_, _, ok := owner.TaintString(values[i], 0)
		if i < ProbeLimit {
			require.Truef(t, ok, "value %d", i)
		} else {
			require.False(t, ok)
		}
	}
	require.Equal(t, int32(ProbeLimit), owner.Values())
	owner.Finish()
	require.Zero(t, store.ProcessValues())
}

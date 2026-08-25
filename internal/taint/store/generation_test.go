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

func TestRootQuotaNeverRegressesGeneration(t *testing.T) {
	var root rootRecord
	root.valueQuota.Store(uint64(2)<<32 | 1)
	require.False(t, reserveRootValue(&root, 1))
	require.Equal(t, uint64(2)<<32|1, root.valueQuota.Load())
}

func TestDistinctMutationWindowsDoNotAccumulateCounters(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintBytes(make([]byte, 32<<10), 0)
	require.True(t, ok)

	for generation := 0; generation < 60; generation++ {
		for i := 0; i < 100; i++ {
			offset := (generation*211 + i*17) % (len(managed) - 2)
			key, valid := BytesKey(managed[offset : offset+2])
			require.True(t, valid)
			owner.Derive(key, root)
		}
		require.LessOrEqual(t, owner.Values(), int32(101))

		managed[generation%len(managed)]++
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: uint32(len(managed)), SourceID: 0}}, uint32(cap(managed))).Valid)
		root, ok = owner.PublishBytesMutation(root, managed, &set)
		require.Truef(t, ok, "generation %d", generation)
		require.Equal(t, int32(1), owner.Values(), "old generation counters must be reconciled at publication")
	}
	owner.Finish()
	require.Zero(t, store.ProcessValues())
}

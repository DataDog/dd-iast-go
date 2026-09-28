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

func TestDistinctMutationWindowsDoNotAccumulateIndexState(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintBytes(make([]byte, 32<<10), 0)
	require.True(t, ok)
	stats := store.Stats()

	for generation := 0; generation < 60; generation++ {
		for i := 0; i < 100; i++ {
			offset := (generation*211 + i*17) % (len(managed) - 2)
			key, valid := BytesKey(managed[offset : offset+2])
			require.True(t, valid)
			require.NotNilf(t, lookupRanges(t, store, key), "generation %d offset %d", generation, offset)
		}

		managed[generation%len(managed)]++
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: uint32(len(managed)), SourceID: 0}}, uint32(cap(managed))).Valid)
		root, ok = owner.PublishBytesMutation(root, managed, &set)
		require.Truef(t, ok, "generation %d", generation)
		require.Equal(t, stats, store.Stats(), "a mutation does not change the index")
	}
	owner.Finish()
	requireIndexEmpty(t, store)
}

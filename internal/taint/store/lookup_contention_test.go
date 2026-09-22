// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestLookupBusyLocksClearSnapshotAndRecover(t *testing.T) {
	store := New()
	owner := store.Acquire()
	t.Cleanup(owner.Finish)
	value, _, ok := owner.TaintString("lookup-value", 1)
	require.True(t, ok)
	key, ok := StringKey(value)
	require.True(t, ok)
	shard := &store.shards[shardIndex(keyHash(key))]
	for index, test := range []struct {
		name string
		lock sync.Locker
	}{
		{"shard", &shard.mu},
		{"owner lifecycle", &owner.owner.lifecycleMu},
		{"owner roots", &owner.owner.rootsMu},
	} {
		t.Run(test.name, func(t *testing.T) {
			var snapshot Snapshot
			require.True(t, store.Lookup(key, &snapshot))
			require.Equal(t, 1, snapshot.Len())

			acquired := func() bool {
				test.lock.Lock()
				defer test.lock.Unlock()
				return store.Lookup(key, &snapshot)
			}()
			// Only a busy shard returns false; a busy owner is a safe miss.
			require.Equal(t, index != 0, acquired)
			require.Zero(t, snapshot.Len(), "a refused contribution must not expose the preceding result")

			require.True(t, store.Lookup(key, &snapshot))
			require.Equal(t, 1, snapshot.Len())
			entry, ok := snapshot.At(0)
			require.True(t, ok)
			require.Equal(t, owner.ID(), entry.OwnerID)
			require.Equal(t, 1, entry.Ranges.Len())
			actual, ok := entry.Ranges.At(0)
			require.True(t, ok)
			require.Equal(t, ranges.Range{Length: uint32(len(value)), SourceID: 1}, actual)
		})
	}
}

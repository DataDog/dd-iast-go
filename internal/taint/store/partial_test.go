// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestLookupReportsPartialSnapshot(t *testing.T) {
	s := New()
	alpha, bravo := s.Acquire(), s.Acquire()
	t.Cleanup(func() { finishAll([]*Owner{alpha, bravo}) })
	buffer, backing := alignedBuffer(64, 64)
	shared := buffer[0:4:4]
	for index, owner := range []*Owner{alpha, bravo} {
		_, ok := owner.AdoptBytes(shared, mustSet(t, ranges.DefaultLimit, 4, r(0, 4, ranges.SourceID(index))))
		require.True(t, ok)
	}
	key, ok := BytesKey(shared)
	require.True(t, ok)
	var snapshot Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 2, snapshot.Len())
	require.False(t, snapshot.Partial())

	// A contended owner lock skips the entry of this owner: the snapshot is
	// partial, because an owner that it does not contain has bytes in value.
	bravo.owner.lifecycleMu.Lock()
	require.True(t, s.Lookup(key, &snapshot))
	bravo.owner.lifecycleMu.Unlock()
	require.Equal(t, 1, snapshot.Len())
	require.True(t, snapshot.Partial())

	// The next lookup resets the flag.
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 2, snapshot.Len())
	require.False(t, snapshot.Partial())
	var empty *Snapshot
	require.False(t, empty.Partial())
	runtime.KeepAlive(backing)
}

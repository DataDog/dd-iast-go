// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactionAbortLeavesShardUnchanged(t *testing.T) {
	store := New()
	owner := store.Acquire()
	shard := &store.shards[0]
	for i := 0; i <= ProbeLimit; i++ {
		shard.slots[i] = valueSlot{
			pointer: uintptr(i + 1), length: 2, kind: KindString,
			ownerIdx: owner.index, ownerGen: owner.gen,
		}
	}
	before := shard.slots
	forceCollision.Store(true)
	store.compact(shard)
	forceCollision.Store(false)
	require.Equal(t, before, shard.slots)
	require.Equal(t, uint64(1), store.compactAborts.Load())
	owner.Finish()
}

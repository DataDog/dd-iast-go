// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMillionOperationChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("million-operation bounded-store soak")
	}
	store := New()
	const valuesPerOwner = 64
	const cycles = 1_000_000 / valuesPerOwner
	values := make([]string, valuesPerOwner)
	for i := range values {
		values[i] = fmt.Sprintf("taint-churn-value-%04d", i)
	}
	for cycle := 0; cycle < cycles; cycle++ {
		owner := store.Acquire()
		require.False(t, owner.Disabled())
		for _, value := range values {
			_, _, ok := owner.TaintString(value, 0)
			require.Truef(t, ok, "cycle %d", cycle)
		}
		owner.Finish()
	}
	require.Zero(t, store.ProcessValues())
	require.Zero(t, store.ProcessCharged())
	stats := store.Stats()
	require.Equal(t, uint16(OverflowBlocks), stats.OverflowFree)
	require.LessOrEqual(t, stats.MaxTombstones, uint16(SlotsPerShard))
	require.LessOrEqual(t, stats.MaxProbe, uint8(ProbeLimit))
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOwnBusyDropsDelta: the heartbeat reports the change of the total of
// request.OwnBusyDrops since the last report.
func TestOwnBusyDropsDelta(t *testing.T) {
	previousTotal, previousReported := ownBusyDropsTotal, reportedOwnBusyDrops.Load()
	t.Cleanup(func() {
		ownBusyDropsTotal = previousTotal
		reportedOwnBusyDrops.Store(previousReported)
	})
	total := uint64(0)
	ownBusyDropsTotal = func() uint64 { return total }
	reportedOwnBusyDrops.Store(0)

	require.Zero(t, ownBusyDropsDelta())
	total = 5
	require.Equal(t, uint64(5), ownBusyDropsDelta())
	require.Zero(t, ownBusyDropsDelta(), "no new drop")
	total = 7
	require.Equal(t, uint64(2), ownBusyDropsDelta())
	// A total that goes back (not possible) gives no report.
	total = 3
	require.Zero(t, ownBusyDropsDelta())
	total = 4
	require.Equal(t, uint64(1), ownBusyDropsDelta())
}

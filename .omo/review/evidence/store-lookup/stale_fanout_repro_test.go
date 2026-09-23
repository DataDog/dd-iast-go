package store

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestReproLookupSkipsLiveOwnerAfterFourStaleMatches(t *testing.T) {
	store := New()
	value := strings.Clone("same-address-key-for-five-owners")
	key, ok := StringKey(value)
	require.True(t, ok)

	var owners [MaxSnapshotOwners + 1]*Owner
	for sourceID := range owners {
		owners[sourceID] = store.Acquire()
		require.False(t, owners[sourceID].Disabled())
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, 10, []ranges.Range{{
			Length: uint32(len(value)), SourceID: ranges.SourceID(sourceID),
		}}, uint32(len(value))).Valid)
		_, ok = owners[sourceID].AdoptString(value, &set)
		require.True(t, ok)
	}

	for _, owner := range owners[:MaxSnapshotOwners] {
		owner.Finish()
	}
	t.Cleanup(owners[MaxSnapshotOwners].Finish)

	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len(), "the fifth live owner must not be excluded by four stale slots")
}

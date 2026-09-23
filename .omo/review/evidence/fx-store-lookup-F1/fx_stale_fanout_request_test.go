package request

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// TestFxSharedBodyResultLosesLiveOwnerAfterFourStaleMatches reproduces
// store-lookup-F1 through the request-level body-adoption path that
// ReadAllBytes/CloneReaderBytes use: they adopt ONE shared result allocation
// into every active owner bound to the same input reader. Five concurrent
// sampled requests (DD_IAST_MAX_CONCURRENT_REQUESTS=5) bound to one reader
// therefore insert five same-key slots while all five owners are live. When
// four owners finish, their slots turn stale but stay in the fixed shard;
// Store.Lookup admits only the first four matching candidates before
// validation, drops all four as stale, and the fifth live owner's body taint
// is lost.
func TestFxSharedBodyResultLosesLiveOwnerAfterFourStaleMatches(t *testing.T) {
	manager := NewManager(nil)
	previous := processManager.Load()
	processManager.Store(manager)
	t.Cleanup(func() { processManager.Store(previous) })

	// One shared allocation adopted by five concurrent analyses, exactly as
	// ReadAllBytes(input, data) does for every active owner bound to input.
	shared := []byte("shared-readall-result-adopted-by-five-owners")

	const owners = store.MaxSnapshotOwners + 1
	analyses := make([]Analysis, 0, owners)
	for range owners {
		analysis, ok := manager.Acquire(owners)
		require.True(t, ok)
		require.True(t, analysis.adoptBodyBytes(shared))
		analyses = append(analyses, analysis)
	}
	for _, analysis := range analyses[:store.MaxSnapshotOwners] {
		analysis.Finish()
	}
	t.Cleanup(analyses[store.MaxSnapshotOwners].Finish)

	key, valid := store.BytesKey(shared)
	require.True(t, valid)
	var snapshot store.Snapshot
	require.True(t, manager.Store().Lookup(key, &snapshot))
	t.Logf("snapshot entries for the live owner's key: %d", snapshot.Len())
	require.Equal(t, 1, snapshot.Len(), "the fifth live owner's body taint must survive four stale same-key slots")
	require.True(t, IsTaintedBytes(shared), "the live owner's shared body result must stay tainted")
}

// Control: with only four concurrent adopters the surviving live owner is
// still found, because all four candidates fit in the snapshot budget.
func TestFxControlFourSharedOwnersKeepLiveOwner(t *testing.T) {
	manager := NewManager(nil)
	previous := processManager.Load()
	processManager.Store(manager)
	t.Cleanup(func() { processManager.Store(previous) })

	shared := []byte("shared-readall-result-adopted-by-four-owners")
	const owners = store.MaxSnapshotOwners
	analyses := make([]Analysis, 0, owners)
	for range owners {
		analysis, ok := manager.Acquire(owners)
		require.True(t, ok)
		require.True(t, analysis.adoptBodyBytes(shared))
		analyses = append(analyses, analysis)
	}
	for _, analysis := range analyses[:owners-1] {
		analysis.Finish()
	}
	t.Cleanup(analyses[owners-1].Finish)

	key, valid := store.BytesKey(shared)
	require.True(t, valid)
	var snapshot store.Snapshot
	require.True(t, manager.Store().Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	require.True(t, IsTaintedBytes(shared))
}

// Control: the default admission bound (two concurrent analyses) cannot
// create five same-key candidates, so a shared body result keeps its live
// owner's taint even after the other owner finished.
func TestFxControlDefaultConcurrencySharedOwnerKeepsTaint(t *testing.T) {
	manager := NewManager(nil)
	previous := processManager.Load()
	processManager.Store(manager)
	t.Cleanup(func() { processManager.Store(previous) })

	shared := []byte("shared-readall-result-under-default-admission")
	first, ok := manager.Acquire(2)
	require.True(t, ok)
	second, ok := manager.Acquire(2)
	require.True(t, ok)
	require.True(t, first.adoptBodyBytes(shared))
	require.True(t, second.adoptBodyBytes(shared))
	first.Finish()
	t.Cleanup(second.Finish)

	require.True(t, IsTaintedBytes(shared))
}

// Control: five analyses each adopting their own fresh per-request result
// (the ordinary io.ReadAll shape: distinct allocations) are unaffected.
func TestFxControlFreshPerRequestBuffersUnaffected(t *testing.T) {
	manager := NewManager(nil)
	previous := processManager.Load()
	processManager.Store(manager)
	t.Cleanup(func() { processManager.Store(previous) })

	const owners = store.MaxSnapshotOwners + 1
	type entry struct {
		analysis Analysis
		buffer   []byte
	}
	entries := make([]entry, 0, owners)
	for range owners {
		analysis, ok := manager.Acquire(owners)
		require.True(t, ok)
		buffer := []byte("fresh-per-request-readall-buffer")
		require.True(t, analysis.adoptBodyBytes(buffer))
		entries = append(entries, entry{analysis: analysis, buffer: buffer})
	}
	for _, e := range entries[:owners-1] {
		e.analysis.Finish()
	}
	t.Cleanup(entries[owners-1].analysis.Finish)
	require.True(t, IsTaintedBytes(entries[owners-1].buffer))
}

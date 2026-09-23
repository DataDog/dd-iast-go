package propagation_test

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// fxEnable activates the global IAST configuration for the duration of the test.
func fxEnable(t *testing.T) {
	t.Helper()
	prevEnabled := config.Enabled
	prevSampling := config.RequestSamplingPct
	prevMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = prevEnabled
		config.RequestSamplingPct = prevSampling
		config.MaxConcurrentRequests = prevMax
	})
}

// fxAdoptShared makes owner adopt the shared allocation with one range tagged
// with the given source ID, mirroring the audited shared-adoption state the
// store contract supports (see TestPublishHelpersDropStaleAndPreserveLiveOwner).
func fxAdoptShared(t *testing.T, owner *store.Owner, shared string, sourceID ranges.SourceID) {
	t.Helper()
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit,
		[]ranges.Range{{Length: uint32(len(shared)), SourceID: sourceID}},
		uint32(len(shared))).Valid)
	_, ok := owner.AdoptString(shared, &set)
	require.True(t, ok)
}

// TestFxReproCopyStringLosesLiveOwnerBehindFourStaleSlots is this node's
// independent reproducer, driven through the propagation surface that woven
// builds execute for stdlib string copies (MayContain gate -> Lookup ->
// publish). Five live owners adopt one shared allocation; the first four
// finish; the fifth stays live. A strings.Clone-style copy of the shared value
// must carry the live owner's taint. Expected: snapshot of the copy holds one
// entry (the live owner). Actual with the bug: the copy is published untainted.
func TestFxReproCopyStringLosesLiveOwnerBehindFourStaleSlots(t *testing.T) {
	fxEnable(t)
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(func() { scope.Finish() })
	s := request.ActiveStore()
	require.NotNil(t, s)

	shared := strings.Clone("shared-customer-string")
	var owners [store.MaxSnapshotOwners + 1]*store.Owner
	for i := range owners {
		owners[i] = s.Acquire()
		require.False(t, owners[i].Disabled())
		fxAdoptShared(t, owners[i], shared, ranges.SourceID(i+1))
	}
	for _, owner := range owners[:store.MaxSnapshotOwners] {
		owner.Finish()
	}
	t.Cleanup(owners[store.MaxSnapshotOwners].Finish)

	// Stale slots still satisfy the cheap gate...
	sharedKey, ok := store.StringKey(shared)
	require.True(t, ok)
	require.True(t, s.MayContain(sharedKey), "stale slots keep the cheap gate hot")

	// ...so customer code copying the tainted value goes through Lookup.
	result := strings.Clone(shared)
	managed := propagation.CopyString(shared, result)

	managedKey, ok := store.StringKey(managed)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(managedKey, &snapshot))
	require.Equal(t, 1, snapshot.Len(),
		"the copy must carry the fifth (live) owner's taint; four stale slots hid it")
}

// TestFxControlOneStaleOneLiveIsPreserved shows the contract below the cap:
// with one stale and one live owner on the same key, CopyString keeps the live
// owner's taint (mirrors the authors' TestPublishHelpersDropStaleAndPreserveLiveOwner
// at the propagation surface).
func TestFxControlOneStaleOneLiveIsPreserved(t *testing.T) {
	fxEnable(t)
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(func() { scope.Finish() })
	s := request.ActiveStore()
	require.NotNil(t, s)

	shared := strings.Clone("shared-customer-string")
	stale := s.Acquire()
	live := s.Acquire()
	fxAdoptShared(t, stale, shared, 1)
	fxAdoptShared(t, live, shared, 2)
	stale.Finish()
	t.Cleanup(live.Finish)

	managed := propagation.CopyString(shared, strings.Clone(shared))
	managedKey, ok := store.StringKey(managed)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(managedKey, &snapshot))
	require.Equal(t, 1, snapshot.Len(), "one stale slot must not hide the live owner")
}

// TestFxControlSequentialChurnReclaimsStaleSlots pins the reachability
// precondition: four owners adopt the same shared allocation and ALL finish
// (no live owner left); a fifth owner then adopts the same allocation. Its
// putWindow must reclaim the four dead slots, so the copy keeps the new live
// owner's taint. Sequential churn does not reproduce the false negative; it
// needs five owners with slots on one address at the same time.
func TestFxControlSequentialChurnReclaimsStaleSlots(t *testing.T) {
	fxEnable(t)
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(func() { scope.Finish() })
	s := request.ActiveStore()
	require.NotNil(t, s)

	shared := strings.Clone("shared-customer-string")
	var owners [store.MaxSnapshotOwners]*store.Owner
	for i := range owners {
		owners[i] = s.Acquire()
		fxAdoptShared(t, owners[i], shared, ranges.SourceID(i+1))
		owners[i].Finish()
	}

	live := s.Acquire()
	t.Cleanup(live.Finish)
	fxAdoptShared(t, live, shared, ranges.SourceID(99))

	sharedKey, ok := store.StringKey(shared)
	require.True(t, ok)
	var before store.Snapshot
	require.True(t, s.Lookup(sharedKey, &before))
	require.Equal(t, 1, before.Len(), "the new live owner must replace the dead slots")

	managed := propagation.CopyString(shared, strings.Clone(shared))
	managedKey, ok := store.StringKey(managed)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(managedKey, &snapshot))
	require.Equal(t, 1, snapshot.Len(), "sequential churn must keep the live owner's taint")
}

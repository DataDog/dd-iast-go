package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Deterministic mechanism check, separate from the unscheduled API/HTTP
// observation harness. The held lock simulates an Acquire in progress.
func TestReviewAdmissionBusyStoreWithSpareOwners(t *testing.T) {
	s := New()
	first := s.Acquire()
	require.False(t, first.Disabled())
	defer first.Finish()

	free := 0
	for i := range s.owners {
		if ownerState(s.owners[i].state.Load()) == stateUnused {
			free++
		}
	}
	require.Equal(t, MaxOwners-1, free)

	s.ownerMu.Lock()
	refused := s.Acquire()
	s.ownerMu.Unlock()
	require.True(t, refused.Disabled())
	require.Equal(t, uint64(1), s.AcquireDrops())

	recovered := s.Acquire()
	require.False(t, recovered.Disabled())
	defer recovered.Finish()
	t.Logf("active_before=1 free_before=%d rejected_while_busy=%v drops=%d admitted_after_unlock=%v",
		free, refused.Disabled(), s.AcquireDrops(), !recovered.Disabled())
}

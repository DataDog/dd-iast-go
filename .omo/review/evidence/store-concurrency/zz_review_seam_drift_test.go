package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// Forces claimMutation(R1) (the first step of PublishBytesMutation, run by a
// concurrent goroutine in practice) between putWindow's reserve on R2 and its
// release on R1 while the same key is rebound from R1 to R2.
func TestReviewSeamRebindMutationDrift(t *testing.T) {
	s := New()
	o := s.Acquire()
	buf := make([]byte, 64)
	var set ranges.Set
	ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: 64, SourceID: 1}}, 64)
	r1, ok := o.AdoptBytes(buf, &set)
	if !ok {
		t.Fatal("adopt r1")
	}
	reviewRebindHook = func() { _, claimed := o.claimMutation(r1); t.Logf("claimMutation(r1) inside rebind window: %v", claimed) }
	r2, ok := o.AdoptBytes(buf, &set)
	t.Logf("r1=%+v r2=%+v adopt2=%v", r1, r2, ok)
	t.Logf("after rebind: owner_values=%d process_values=%d r2_quota_count=%d (one live key)", o.Values(), s.ProcessValues(), uint32(o.owner.roots[r2.ID].valueQuota.Load()))
	next, ok := o.PublishBytesMutation(r2, buf, &set)
	t.Logf("after PublishBytesMutation(r2)->%+v ok=%v: owner_values=%d process_values=%d", next, ok, o.Values(), s.ProcessValues())
	if o.Values() != 1 || s.ProcessValues() != 1 {
		t.Errorf("value counters drifted: owner=%d process=%d, want 1 live key", o.Values(), s.ProcessValues())
	}
	o.Finish()
	t.Logf("after Finish: process_values=%d", s.ProcessValues())
}

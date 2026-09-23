package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// Reproduce the independent contention points in a failed root publication:
// the value shard rejects the window, then another root operation holds
// rootsMu when rollback tries to release the reservation.
func TestReviewFailedRootPublicationsConsumeOwnerSlots(t *testing.T) {
	s := New()
	o := s.Acquire()
	forceCollision.Store(true)
	t.Cleanup(func() { forceCollision.Store(false) })

	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.DefaultLimit,
		[]ranges.Range{{Length: 8, SourceID: 1}}, 8).Valid {
		t.Fatal("could not create test range")
	}
	for i := 0; i < MaxRootsPerOwner; i++ {
		value := make([]byte, 8)
		key, ok := BytesKey(value)
		if !ok {
			t.Fatal("could not create test key")
		}
		id, ok := o.reserveRootSlot(8)
		if !ok {
			t.Fatalf("reservation %d was rejected early", i)
		}
		generation, ok := o.publishRoot(id, key.Pointer, 8, 8, "", value, &set)
		if !ok {
			t.Fatalf("publication %d was rejected early", i)
		}
		s.shards[0].mu.Lock()
		published := o.putWindow(key, id, generation)
		s.shards[0].mu.Unlock()
		if published {
			t.Fatal("contended window unexpectedly published")
		}
		o.owner.rootsMu.Lock()
		o.rollbackRoot(id, 8)
		o.owner.rootsMu.Unlock()
	}

	_, _, admitted := o.TaintBytes([]byte("ok"), 1)
	t.Logf("after %d rejected windows: charged=%d rootCount=%d values=%d next root admitted=%t",
		MaxRootsPerOwner, o.Charged(), o.owner.rootCount.Load(), o.Values(), admitted)
	o.Finish()
	t.Logf("after Finish: processCharged=%d", s.ProcessCharged())
	if admitted {
		t.Fatal("expected the leaked reservations to exhaust the owner root table")
	}
	if s.ProcessCharged() != 0 {
		t.Fatal("Finish failed to release leaked reservations")
	}
}

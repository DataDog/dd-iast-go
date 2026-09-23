package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// These tests force ONE interleaving that unmodified code permits: Acquire
// (which never takes lifecycleMu) runs between alive()'s generation load and
// its state load. The seam only schedules that step; it changes no logic.

func TestReviewSeamStaleHandleBindsIntoReusedSlot(t *testing.T) {
	s := New()
	stale := s.Acquire() // request A, slot 0, gen 1
	stale.Finish()       // A done; an async goroutine still holds its handle
	var fresh *Owner
	reviewAliveHook = func() { fresh = s.Acquire() } // request C reuses slot 0
	obj := new(int64)                                // A's body reader, say
	bound := BindObject(stale, obj, BindingReader)
	t.Logf("stale_gen=%d fresh_gen=%d fresh_index=%d bind_returned=%v", stale.gen, fresh.gen, fresh.index, bound)
	var refs [MaxSnapshotOwners]OwnerRef
	n := LookupObject(s, obj, refs[:])
	for i := 0; i < n; i++ {
		t.Logf("LookupObject ref[%d]: index=%d generation=%d kind=%d", i, refs[i].index, refs[i].generation, refs[i].Kind)
	}
	if bound && n == 1 && refs[0].generation == fresh.gen {
		t.Errorf("finished request's handle bound its object into the next request (gen %d)", fresh.gen)
	}
	fresh.Finish()
}

func TestReviewSeamStaleHandleWriterStateIntoReusedSlot(t *testing.T) {
	s := New()
	stale := s.Acquire()
	stale.Finish()
	var fresh *Owner
	reviewAliveHook = func() { fresh = s.Acquire() }
	builder := new(int64) // stands in for A's *strings.Builder
	view := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	var in ranges.Set
	ranges.AdoptCanonical(&in, 10, []ranges.Range{{Length: 4, SourceID: 7}}, 4) // source 7 of request A's table
	updated := stale.UpdateWriter(builder, WriterStringBuilder, WriterView{}, view, &in, 4, 4)
	var wrefs [MaxSnapshotOwners]WriterRef
	n := LookupWriterValue(s, builder, WriterStringBuilder, view, wrefs[:])
	t.Logf("stale_gen=%d fresh_gen=%d update_returned=%v writer_refs=%d charged_fresh=%d", stale.gen, fresh.gen, updated, n, fresh.Charged())
	if n == 1 {
		h, ok := wrefs[0].Handle()
		var snap ranges.Set
		if ok && h.SnapshotWriter(builder, WriterStringBuilder, view, &snap) {
			var out [MaxRanges]ranges.Range
			c := snap.CopyTo(out[:])
			t.Logf("fresh request (gen %d) now reports writer provenance: %+v", h.gen, out[:c])
			t.Errorf("finished request's writer provenance (source %d of A) became request C's provenance", out[0].SourceID)
		}
	}
	fresh.Finish()
}

// Control: without the forced interleaving the stale handle is rejected.
func TestReviewSeamControlSequentialReuse(t *testing.T) {
	s := New()
	stale := s.Acquire()
	stale.Finish()
	fresh := s.Acquire()
	obj := new(int64)
	if BindObject(stale, obj, BindingReader) {
		t.Fatal("control: sequential stale bind unexpectedly succeeded")
	}
	var refs [MaxSnapshotOwners]OwnerRef
	t.Logf("control: stale bind rejected, LookupObject=%d", LookupObject(s, obj, refs[:]))
	fresh.Finish()
}

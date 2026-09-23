package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// Deterministic seam reproduction: the one-shot hook runs Store.Acquire
// between the generation load and the state load inside alive(), preserving
// the production load order. This is the exact interleaving the natural stress
// tests try to hit by scheduling alone.

// TestFxSeamStaleBindIntoSuccessor proves the claimed consequence of the
// beginWrite seam: a finished request's handle publishes an object into the
// successor generation's binding table.
func TestFxSeamStaleBindIntoSuccessor(t *testing.T) {
	s := New()
	objA := new(int64)
	ownerA := s.Acquire()
	if ownerA.Disabled() {
		t.Fatal("acquire A")
	}
	if !BindObjectValue(ownerA, objA, BindingReader) {
		t.Fatal("bind A")
	}
	stale := ownerA
	ownerA.Finish()

	var successor *Owner
	restore := fxInstallSeam(func() {
		fxReviewSeamOnce.Store(nil)
		successor = s.Acquire()
	})
	defer restore()

	objB := new(int64)
	if !BindObjectValue(stale, objB, BindingReader) {
		t.Fatal("seam did not fire: stale bind was rejected")
	}
	if successor == nil || successor.gen != stale.gen+1 {
		t.Fatalf("successor gen=%v, want %d", successor, stale.gen+1)
	}
	var refs [MaxSnapshotOwners]OwnerRef
	if n := LookupObject(s, objB, refs[:]); n != 1 {
		t.Fatalf("successor lookup found %d owners for the stale-published object, want 1", n)
	}
	ref := refs[0]
	if ref.generation != successor.gen || ref.index != successor.index {
		t.Fatalf("binding landed under generation=%d index=%d, want successor generation=%d index=%d",
			ref.generation, ref.index, successor.gen, successor.index)
	}
	t.Logf("stale handle gen=%d published fresh object; successor request (gen=%d, index=%d) now owns the binding",
		stale.gen, ref.generation, ref.index)
}

// TestFxSeamStaleWriterProvenanceIntoSuccessor proves the source-level
// consequence: request A's provenance (source ID 7) lands in request B's
// writer records and is read back by B as its own.
func TestFxSeamStaleWriterProvenanceIntoSuccessor(t *testing.T) {
	s := New()
	ownerA := s.Acquire()
	if ownerA.Disabled() {
		t.Fatal("acquire A")
	}
	stale := ownerA
	ownerA.Finish()

	var successor *Owner
	restore := fxInstallSeam(func() {
		fxReviewSeamOnce.Store(nil)
		successor = s.Acquire()
	})
	defer restore()

	obj := new(int64)
	var input ranges.Set
	if !ranges.AdoptCanonical(&input, 16,
		[]ranges.Range{{Start: 0, Length: 8, SourceID: 7}}, 8).Valid {
		t.Fatal("input set")
	}
	before := WriterView{Pointer: 0x1000, Length: 0, Capacity: 64}
	after := WriterView{Pointer: 0x1000, Length: 8, Capacity: 64}
	if !stale.UpdateWriter(obj, WriterStringBuilder, before, after, &input, 8, 8) {
		t.Fatal("seam did not fire: stale writer update was rejected")
	}
	if successor == nil || successor.gen != stale.gen+1 {
		t.Fatalf("successor gen=%v, want %d", successor, stale.gen+1)
	}
	var dst ranges.Set
	if !successor.SnapshotWriter(obj, WriterStringBuilder, after, &dst) {
		t.Fatal("successor could not read back the stale-published writer state")
	}
	if dst.Len() == 0 {
		t.Fatal("successor writer state is empty")
	}
	for i := 0; i < dst.Len(); i++ {
		r, ok := dst.At(i)
		if !ok {
			t.Fatal("range")
		}
		if r.SourceID != 7 {
			t.Fatalf("successor writer provenance source=%d, want stale source 7", r.SourceID)
		}
	}
	t.Logf("stale handle gen=%d wrote source 7 into successor gen=%d writer state; successor SnapshotWriter returns it as its own provenance",
		stale.gen, successor.gen)
}

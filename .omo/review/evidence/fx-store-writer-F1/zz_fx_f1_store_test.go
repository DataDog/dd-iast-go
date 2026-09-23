package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

// FX-F1 store-level deterministic reproducer.
//
// Request B owns a tracked strings.Builder. While B is inside one of its own
// writer critical sections (writersMu held, writerVersion odd — exactly the
// state during every wrapped Builder/Buffer write), request A performs a
// writer lookup for a completely UNRELATED receiver (different pointer, no
// backing overlap). The claim under test is that this unrelated lookup marks
// B's owner writerDirty, so B loses ALL of its writer state at its next
// writer operation.
func TestFxF1UnrelatedLookupDirtiesCriticalSectionOwner(t *testing.T) {
	s := New()
	ownerB := s.Acquire()
	ownerA := s.Acquire()
	defer ownerA.Finish()
	defer ownerB.Finish()

	objB := &writerObject{id: 1}
	objA := &writerObject{id: 2}

	// B tracks a tainted builder write, exactly like the public path does.
	input := writerInput(t, 4, ranges.Range{Start: 1, Length: 2, SourceID: 3})
	viewB := WriterView{Pointer: 0x1000, Length: 4, Capacity: 8}
	require.True(t, ownerB.UpdateWriter(objB, WriterStringBuilder, WriterView{}, viewB, &input, 4, 4))
	require.Equal(t, int64(8), ownerB.Charged())

	recB := ownerB.owner

	// B enters a writer critical section: writersMu held and writerVersion odd,
	// the exact invariants UpdateWriter/ResetWriter/TruncateWriter maintain.
	recB.writersMu.Lock()
	recB.writerVersion.Add(1)

	// A looks up its own, unrelated receiver. A's view shares nothing with B.
	viewA := WriterView{Pointer: 0x9000, Length: 4, Capacity: 8}
	var refs [MaxSnapshotOwners]WriterRef
	n := LookupWriterValue(s, objA, WriterStringBuilder, viewA, refs[:])
	require.Zero(t, n, "A tracks no writer; nothing should be returned")

	dirty := recB.writerDirty.Load()
	t.Logf("after unrelated lookup while B holds its writer critical section: B.writerDirty=%v", dirty)

	// B leaves the critical section (deferred version bump, then unlock).
	recB.writerVersion.Add(1)
	recB.writersMu.Unlock()

	// B reads its own writer back through its next writer operation.
	var snap ranges.Set
	ok := ownerB.SnapshotWriter(objB, WriterStringBuilder, viewB, &snap)
	t.Logf("B.SnapshotWriter after the unrelated lookup: ok=%v charged=%d writerCount=%d",
		ok, ownerB.Charged(), recB.writerCount)
	if dirty {
		t.Errorf("BUG: unrelated writer lookup for receiver %p dirtied B's owner (writerDirty=true) although no pointer or backing of B matched", objA)
	}
	if !ok {
		t.Errorf("BUG: B lost its entire tracked builder state (snapshot=%v charged=%d) because of request A's unrelated writer lookup", ok, ownerB.Charged())
	}
}

// FX-F1 store-level rate reproducer: no artificial lock holding. B performs
// real wrapped writer updates in a loop while A performs real unrelated
// lookups; count how often B's state was wiped.
func TestFxF1ConcurrentUnrelatedLookupWipeRate(t *testing.T) {
	s := New()
	ownerB := s.Acquire()
	ownerA := s.Acquire()
	defer ownerA.Finish()
	defer ownerB.Finish()

	objB := &writerObject{id: 1}
	objA := &writerObject{id: 2}
	input := writerInput(t, 4, ranges.Range{Start: 1, Length: 2, SourceID: 3})
	viewA := WriterView{Pointer: 0x9000, Length: 4, Capacity: 8}
	var refs [MaxSnapshotOwners]WriterRef

	const ops = 20000
	losses := 0
	for i := 0; i < ops; i++ {
		before := WriterView{Pointer: 0x1000, Length: uint32(i % 8), Capacity: 8}
		after := WriterView{Pointer: 0x1000, Length: uint32(i%8) + 4, Capacity: 8}
		if !ownerB.UpdateWriter(objB, WriterStringBuilder, before, after, &input, 4, 4) {
			losses++
		}
		LookupWriterValue(s, objA, WriterStringBuilder, viewA, refs[:])
	}
	t.Logf("FX-F1 store: ops=%d B-update-losses=%d", ops, losses)
	if losses > ops/10 {
		t.Errorf("BUG: B lost writer state on %d/%d updates because of A's unrelated lookups", losses, ops)
	}
}

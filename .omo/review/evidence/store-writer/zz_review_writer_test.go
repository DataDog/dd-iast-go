package store

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// Deterministic: an owner that is merely inside a writer critical section
// (writersMu held, writerVersion odd) is poisoned by an invalidation of an
// UNRELATED buffer, losing all of its writer provenance.
func TestReviewUnrelatedInvalidationPoisonsOwner(t *testing.T) {
	s := New()
	a := s.Acquire() // request A: unrelated
	b := s.Acquire() // request B: tracks a builder
	defer a.Finish()
	defer b.Finish()
	obj := &writerObject{id: 1}
	input := writerInput(t, 4, ranges.Range{Start: 0, Length: 4, SourceID: 1})
	view := WriterView{Pointer: 0x1000, Length: 4, Capacity: 64}
	if !b.UpdateWriter(obj, WriterStringBuilder, WriterView{}, view, &input, 4, 4) {
		t.Fatal("seed failed")
	}
	// B is mid-UpdateWriter on some other writer.
	b.owner.writersMu.Lock()
	b.owner.writerVersion.Add(1)
	unrelated := &writerObject{id: 99}
	var backing [64]byte
	s.InvalidateBuffer(uintptr(0xdead0000), uintptr(unsafePointer(&backing[0])), 64, false)
	var refs [MaxSnapshotOwners]WriterRef
	_ = LookupWriterValue(s, unrelated, WriterBytesBuffer, WriterView{}, refs[:])
	b.owner.writerVersion.Add(1)
	b.owner.writersMu.Unlock()

	t.Logf("B.writerDirty after unrelated invalidation = %v, B contention drops = %d", b.owner.writerDirty.Load(), b.Counters().Contention)
	var got ranges.Set
	ok := b.SnapshotWriter(obj, WriterStringBuilder, view, &got)
	t.Logf("B.SnapshotWriter(tracked builder) = %v (want true), writerCount after = %d", ok, b.owner.writerCount)
	if !ok {
		t.Errorf("BUG: unrelated buffer invalidation from another request wiped owner B's writer provenance")
	}
}

// Concurrent rate: B keeps one tainted builder and appends untainted bytes;
// another goroutine performs invalidations for an unrelated buffer (as the
// native bytes.Buffer hooks do for every Buffer write in the process while any
// writer state is live). Count how often B's provenance is wiped.
func TestReviewUnrelatedInvalidationRate(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs GOMAXPROCS>=2")
	}
	s := New()
	b := s.Acquire()
	defer b.Finish()
	obj := &writerObject{id: 1}
	var backing [4096]byte
	var stop atomic.Bool
	var wg sync.WaitGroup
	var invalidations atomic.Int64
	wg.Add(1)
	noInvalidator := os.Getenv("REVIEW_NO_INVALIDATOR") != ""
	go func() {
		defer wg.Done()
		if noInvalidator {
			return
		}
		for !stop.Load() {
			s.InvalidateBuffer(uintptr(0xdead0000), uintptr(unsafePointer(&backing[0])), 4096, false)
			invalidations.Add(1)
		}
	}()
	const ops = 200000
	losses := 0
	seedRetries := 0
	seed := func() WriterView {
		input := writerInput(t, 4, ranges.Range{Start: 0, Length: 4, SourceID: 1})
		v := WriterView{Pointer: 0x1000, Length: 4, Capacity: 60000}
		for try := 0; try < 100000; try++ {
			if b.UpdateWriter(obj, WriterStringBuilder, WriterView{}, v, &input, 4, 4) {
				return v
			}
			seedRetries++
		}
		t.Fatal("seed failed")
		return v
	}
	view := seed()
	for i := 0; i < ops; i++ {
		next := view
		next.Length++
		if next.Length >= 60000 {
			b.ResetWriter(obj, WriterStringBuilder)
			view = seed()
			continue
		}
		b.UpdateWriter(obj, WriterStringBuilder, view, next, nil, 1, 1)
		view = next
		var got ranges.Set
		if !b.SnapshotWriter(obj, WriterStringBuilder, view, &got) {
			losses++
			b.ResetWriter(obj, WriterStringBuilder)
			view = seed()
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("ops=%d unrelated invalidations=%d provenance losses=%d seedRetries=%d contention drops=%d", ops, invalidations.Load(), losses, seedRetries, b.Counters().Contention)
	if losses > 0 {
		t.Errorf("BUG: %d/%d writer states wiped by unrelated concurrent invalidation", losses, ops)
	}
}

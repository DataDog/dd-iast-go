package store

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func staleBudget() time.Duration {
	if v, err := time.ParseDuration(os.Getenv("STALE_BUDGET")); err == nil {
		return v
	}
	return 60 * time.Second
}

func staleSpinners() int {
	if v, err := strconv.Atoi(os.Getenv("STALE_SPINNERS")); err == nil {
		return v
	}
	return 8
}

type staleObj struct{ payload [16]byte }

// fillOtherSlots leaves only slot 0 free so every Acquire reuses it.
func fillOtherSlots(t *testing.T, s *Store) []*Owner {
	first := s.Acquire()
	var held []*Owner
	for i := 1; i < MaxOwners; i++ {
		held = append(held, s.Acquire())
	}
	if idx, _ := first.Index(); idx != 0 {
		t.Fatalf("unexpected first slot %d", idx)
	}
	first.Finish()
	return held
}

// TestReviewStaleHandleBindsIntoReusedSlot: a late goroutine keeps using the
// Owner handle of a finished request. beginWrite's alive() loads generation and
// state separately; Acquire (which never takes lifecycleMu) can bump the
// generation and publish stateActive between those loads. The stale handle then
// passes beginWrite and BindObject publishes its object into the NEXT request's
// binding table.
func TestReviewStaleHandleBindsIntoReusedSlot(t *testing.T) {
	s := New()
	held := fillOtherSlots(t, s)
	defer func() {
		for _, o := range held {
			o.Finish()
		}
	}()
	deadline := time.Now().Add(staleBudget())
	spinners := staleSpinners()
	for iter := 0; time.Now().Before(deadline); iter++ {
		a := s.Acquire()
		if idx, ok := a.Index(); !ok || idx != 0 {
			t.Fatalf("iteration %d: expected slot 0, got %d/%v", iter, idx, ok)
		}
		obj := &staleObj{}
		var stop atomic.Bool
		var attempts atomic.Int64
		var wg sync.WaitGroup
		for g := 0; g < spinners; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() {
					BindObject(a, obj, BindingURL)
					attempts.Add(1)
				}
			}()
		}
		for attempts.Load() < int64(spinners) {
		}
		a.Finish()
		b := s.Acquire()
		if idx, _ := b.Index(); idx != 0 || b.Generation() == a.Generation() {
			t.Fatalf("slot not reused")
		}
		mark := attempts.Load()
		for attempts.Load() < mark+int64(4*spinners) {
		}
		stop.Store(true)
		wg.Wait()
		var out [4]OwnerRef
		n := LookupObject(s, obj, out[:])
		for i := 0; i < n; i++ {
			if out[i].generation == b.Generation() {
				t.Fatalf("iteration %d: object bound only through the FINISHED request's handle (gen %d) is bound to the NEW request (idx=%d gen=%d, id=%d); bindings=%d",
					iter, a.Generation(), out[i].index, out[i].generation, b.ID(), b.owner.bindings.count)
			}
		}
		b.Finish()
	}
	t.Log("no stale bind observed within budget")
}

// TestReviewStaleFinishKillsReusedSlot: Owner.Finish checks the generation and
// then CASes state active->finishing as two steps. A stale second Finish racing
// slot reuse can finish the next request's owner.
func TestReviewStaleFinishKillsReusedSlot(t *testing.T) {
	s := New()
	held := fillOtherSlots(t, s)
	defer func() {
		for _, o := range held {
			o.Finish()
		}
	}()
	deadline := time.Now().Add(staleBudget())
	spinners := staleSpinners()
	for iter := 0; time.Now().Before(deadline); iter++ {
		a := s.Acquire()
		var stop atomic.Bool
		var attempts atomic.Int64
		var wg sync.WaitGroup
		for g := 0; g < spinners; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for !stop.Load() {
					a.Finish()
					attempts.Add(1)
				}
			}()
		}
		for ownerState(a.owner.state.Load()) != stateDead {
		}
		b := s.Acquire()
		if idx, _ := b.Index(); idx != 0 {
			t.Fatalf("slot not reused")
		}
		mark := attempts.Load()
		for attempts.Load() < mark+int64(4*spinners) {
		}
		stop.Store(true)
		wg.Wait()
		if !b.alive() {
			t.Fatalf("iteration %d: new owner (gen %d, id %d) was finished by the previous request's stale handle (gen %d); state=%d",
				iter, b.Generation(), b.ID(), a.Generation(), b.owner.state.Load())
		}
		b.Finish()
	}
	t.Log("no stale finish observed within budget")
}

type staleBuilder struct{ buf []byte }

// TestReviewStaleHandleWriterStateBleedsIntoNextRequest mirrors
// propagation/writer.go: a goroutine of a finished request still holds an
// Owner obtained through Handle() and records a tainted builder write. The
// write lands in the next request's owner, carrying the old request's
// owner-local source IDs, and later discovery/snapshot attributes it to the new
// request.
func TestReviewStaleHandleWriterStateBleedsIntoNextRequest(t *testing.T) {
	s := New()
	held := fillOtherSlots(t, s)
	defer func() {
		for _, o := range held {
			o.Finish()
		}
	}()
	deadline := time.Now().Add(staleBudget())
	spinners := staleSpinners()
	const sourceOfA = ranges.SourceID(7)
	for iter := 0; time.Now().Before(deadline); iter++ {
		a := s.Acquire()
		var stop atomic.Bool
		var attempts atomic.Int64
		var wg sync.WaitGroup
		objs := make([]*staleBuilder, spinners)
		for g := 0; g < spinners; g++ {
			objs[g] = &staleBuilder{buf: make([]byte, 0, 64)}
			wg.Add(1)
			go func(obj *staleBuilder) {
				defer wg.Done()
				var input ranges.Set
				ranges.AdoptCanonical(&input, ranges.DefaultLimit, []ranges.Range{{Length: 4, SourceID: sourceOfA}}, 4)
				p := uintptr(unsafe.Pointer(unsafe.SliceData(obj.buf)))
				before := WriterView{Pointer: p, Length: 0, Capacity: 64}
				after := WriterView{Pointer: p, Length: 4, Capacity: 64}
				for !stop.Load() {
					a.ResetWriter(obj, WriterStringBuilder)
					a.UpdateWriter(obj, WriterStringBuilder, before, after, &input, 4, 4)
					attempts.Add(1)
				}
			}(objs[g])
		}
		for attempts.Load() < int64(spinners) {
		}
		a.Finish()
		b := s.Acquire()
		mark := attempts.Load()
		for attempts.Load() < mark+int64(4*spinners) {
		}
		stop.Store(true)
		wg.Wait()
		for _, obj := range objs {
			p := uintptr(unsafe.Pointer(unsafe.SliceData(obj.buf)))
			view := WriterView{Pointer: p, Length: 4, Capacity: 64}
			var refs [4]WriterRef
			n := LookupWriterValue(s, obj, WriterStringBuilder, view, refs[:])
			for i := 0; i < n; i++ {
				if refs[i].generation != b.Generation() {
					continue
				}
				owner, _ := refs[i].Handle()
				var got ranges.Set
				snap := owner.SnapshotWriter(obj, WriterStringBuilder, view, &got)
				r, _ := got.At(0)
				t.Fatalf("iteration %d: builder written only through FINISHED request gen %d is tracked by NEW request gen %d (id %d); snapshot=%v ranges=%d first=%+v (source %d is request A's owner-local ID, now resolved in B's source table); B charged=%d writers=%d",
					iter, a.Generation(), b.Generation(), b.ID(), snap, got.Len(), r, sourceOfA, b.Charged(), b.owner.writerCount)
			}
		}
		b.Finish()
	}
	t.Log("no stale writer publication observed within budget")
}

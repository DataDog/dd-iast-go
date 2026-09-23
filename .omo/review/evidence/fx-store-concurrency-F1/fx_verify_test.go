package store

// Independent phase-3 verification reproducer for store-concurrency-F1 /
// crash-deadlock-F1 (stale raw *Owner handle publishing into a reused slot).
//
// Scenario mirrors the production escape at internal/taint/request/reader.go:23-25
// (BindReader): analysis.storeOwner() hands out a raw *store.Owner, and the
// caller later invokes store.BindObjectValue with it. If the request finishes
// and Store.Acquire recycles the slot while the call is inside beginWrite,
// the write lands in the successor generation.

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func fxDuration(t *testing.T, fallback time.Duration) time.Duration {
	if v := os.Getenv("FX_STRESS"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	return fallback
}

// TestFxStaleHandleBindCrossGeneration: a raw handle of a finished request must
// never successfully BindObjectValue, and a freshly allocated object must never
// be discoverable under a successor generation.
func TestFxStaleHandleBindCrossGeneration(t *testing.T) {
	s := New()
	keep := make([]*Owner, 0, MaxOwners-1)
	for range MaxOwners - 1 {
		keep = append(keep, s.Acquire())
	}
	defer func() {
		for _, o := range keep {
			o.Finish()
		}
	}()

	var stale atomic.Pointer[Owner]
	var stop atomic.Bool
	var cycles, crossGenBinds, staleButSucceeded atomic.Int64
	var wg sync.WaitGroup

	// Churner: acquire the single free slot and finish it as fast as possible,
	// publishing each handle after its Finish so every published handle is stale.
	wg.Go(func() {
		for !stop.Load() {
			o := s.Acquire()
			if o.Disabled() {
				continue
			}
			o.Finish()
			stale.Store(o)
			cycles.Add(1)
		}
	})

	workers := max(2, runtime.GOMAXPROCS(0)-2)
	for range workers {
		wg.Go(func() {
			for !stop.Load() {
				h := stale.Load()
				if h == nil {
					continue
				}
				obj := new(struct{ a, b uint64 })
				if !BindObjectValue(h, obj, BindingReader) {
					continue
				}
				if h.gen != h.owner.generation.Load() {
					staleButSucceeded.Add(1)
				}
				var refs [MaxSnapshotOwners]OwnerRef
				n := LookupObject(s, obj, refs[:])
				for i := 0; i < n; i++ {
					if refs[i].generation != h.gen {
						crossGenBinds.Add(1)
						t.Logf("stale handle gen=%d (slot now gen=%d) bound fresh object; successor gen=%d sees it as its own binding",
							h.gen, h.owner.generation.Load(), refs[i].generation)
					}
				}
			}
		})
	}

	deadline := time.Now().Add(fxDuration(t, 45*time.Second))
	for time.Now().Before(deadline) && crossGenBinds.Load() == 0 {
		runtime.Gosched()
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("slot_cycles=%d workers=%d stale_bind_succeeded=%d cross_generation_bindings=%d",
		cycles.Load(), workers, staleButSucceeded.Load(), crossGenBinds.Load())
	if crossGenBinds.Load() != 0 {
		t.Fatalf("stale owner handle published a fresh object into a successor generation's binding table")
	}
}

// TestFxStaleHandleUpdateWriterCrossGeneration: the same seam through the
// writer path (propagation/writer.go reaches Owner.UpdateWriter; a raw handle
// can also escape via request-side helpers). A stale handle that wins the seam
// appends provenance ranges (source ID 7 of the finished request) into the
// successor's writer records.
func TestFxStaleHandleUpdateWriterCrossGeneration(t *testing.T) {
	s := New()
	keep := make([]*Owner, 0, MaxOwners-1)
	for range MaxOwners - 1 {
		keep = append(keep, s.Acquire())
	}
	defer func() {
		for _, o := range keep {
			o.Finish()
		}
	}()

	var stale atomic.Pointer[Owner]
	var stop atomic.Bool
	var cycles, staleWriterWrites, crossGenWriterWrites atomic.Int64
	var wg sync.WaitGroup

	wg.Go(func() {
		for !stop.Load() {
			o := s.Acquire()
			if o.Disabled() {
				continue
			}
			o.Finish()
			stale.Store(o)
			cycles.Add(1)
		}
	})

	workers := max(2, runtime.GOMAXPROCS(0)-2)
	for range workers {
		wg.Go(func() {
			for !stop.Load() {
				h := stale.Load()
				if h == nil {
					continue
				}
				obj := new(stringsBuilder)
				var input ranges.Set
				if !ranges.AdoptCanonical(&input, 16,
					[]ranges.Range{{Start: 0, Length: 8, SourceID: 7}}, 8).Valid {
					t.Fatal("input set")
				}
				before := WriterView{Pointer: uintptr(0x1000), Length: 0, Capacity: 64}
				after := WriterView{Pointer: uintptr(0x1000), Length: 8, Capacity: 64}
				if !h.UpdateWriter(obj, WriterStringBuilder, before, after, &input, 8, 8) {
					continue
				}
				if h.gen != h.owner.generation.Load() {
					staleWriterWrites.Add(1)
				}
				var refs [MaxSnapshotOwners]WriterRef
				n := LookupWriterValue(s, obj, WriterStringBuilder, after, refs[:])
				for i := 0; i < n; i++ {
					if refs[i].generation != h.gen {
						crossGenWriterWrites.Add(1)
						t.Logf("stale handle gen=%d (slot now gen=%d) wrote provenance (source 7) into successor gen=%d writer state",
							h.gen, h.owner.generation.Load(), refs[i].generation)
					}
				}
			}
		})
	}

	deadline := time.Now().Add(fxDuration(t, 45*time.Second))
	for time.Now().Before(deadline) && crossGenWriterWrites.Load() == 0 {
		runtime.Gosched()
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("slot_cycles=%d workers=%d stale_writer_write_succeeded=%d cross_generation_writer_writes=%d",
		cycles.Load(), workers, staleWriterWrites.Load(), crossGenWriterWrites.Load())
	if crossGenWriterWrites.Load() != 0 {
		t.Fatalf("stale owner handle published writer provenance into a successor generation")
	}
}

// TestFxControlSequentialReuseRejected: without the race (finish, then recycle,
// then use the stale handle), the store correctly rejects the stale handle.
// This shows the bug is the Dead->Active seam in Acquire, not unconditional
// brokenness.
func TestFxControlSequentialReuseRejected(t *testing.T) {
	s := New()
	o := s.Acquire()
	if o.Disabled() {
		t.Fatal("acquire")
	}
	gen := o.gen
	o.Finish()
	next := s.Acquire()
	if next.Disabled() {
		t.Fatal("recycle acquire")
	}
	obj := new(int64)
	if BindObjectValue(o, obj, BindingReader) {
		t.Fatalf("sequential stale handle (gen %d, slot now gen %d) must be rejected", gen, next.gen)
	}
	var refs [MaxSnapshotOwners]OwnerRef
	if n := LookupObject(s, obj, refs[:]); n != 0 {
		t.Fatalf("control: object lookup found %d owners, want 0", n)
	}
}

type stringsBuilder struct{ _ [8]byte }

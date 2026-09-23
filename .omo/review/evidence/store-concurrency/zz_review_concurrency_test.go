package store

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func reviewDuration(t *testing.T, def time.Duration) time.Duration {
	if v := os.Getenv("REVIEW_STRESS"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	return def
}

// TestReviewStaleHandleBindAfterSlotReuse: a handle whose owner already
// finished must never bind an object into the NEXT generation of the reused
// slot. Unmodified production code; natural scheduling only.
func TestReviewStaleHandleBindAfterSlotReuse(t *testing.T) {
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
	var current atomic.Pointer[Owner]
	var stop atomic.Bool
	var hits, staleSuccess, cycles atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		for !stop.Load() {
			o := s.Acquire()
			if o.Disabled() {
				continue
			}
			current.Store(o)
			o.Finish()
			cycles.Add(1)
		}
	})
	workers := max(2, runtime.GOMAXPROCS(0)-2)
	for range workers {
		wg.Go(func() {
			for !stop.Load() {
				h := current.Load()
				if h == nil {
					continue
				}
				obj := new(int64)
				if !BindObject(h, obj, BindingURL) {
					continue
				}
				var refs [MaxSnapshotOwners]OwnerRef
				n := LookupObject(s, obj, refs[:])
				for i := 0; i < n; i++ {
					if refs[i].generation != h.gen {
						hits.Add(1)
						t.Logf("stale handle gen=%d bound object into reused owner slot gen=%d", h.gen, refs[i].generation)
					}
				}
				if h.gen != h.owner.generation.Load() {
					staleSuccess.Add(1)
				}
			}
		})
	}
	deadline := time.Now().Add(reviewDuration(t, 2*time.Second))
	for time.Now().Before(deadline) && hits.Load() == 0 {
		runtime.Gosched()
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("cycles=%d workers=%d bind_success_with_stale_gen_after_return=%d cross_generation_bindings=%d", cycles.Load(), workers, staleSuccess.Load(), hits.Load())
	if hits.Load() != 0 {
		t.Errorf("stale owner handle published a binding into a reused owner generation")
	}
}

// TestReviewRebindConcurrentMutationDrift: a same-key rebind from root R1 to
// root R2 racing a PublishBytesMutation(claimMutation) of R1 must keep
// owner.values equal to the number of live value slots.
func TestReviewRebindConcurrentMutationDrift(t *testing.T) {
	s := New()
	deadline := time.Now().Add(reviewDuration(t, 2*time.Second))
	iterations := 0
	for time.Now().Before(deadline) {
		o := s.Acquire()
		for j := 0; j < 200 && time.Now().Before(deadline); j++ {
			iterations++
			buf := make([]byte, 64)
			var set ranges.Set
			if !ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: 64, SourceID: 1}}, 64).Valid {
				t.Fatal("set")
			}
			r1, ok := o.AdoptBytes(buf, &set)
			if !ok {
				break
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Go(func() { <-start; o.AdoptBytes(buf, &set) })
			wg.Go(func() { <-start; o.claimMutationForReview(r1) })
			close(start)
			wg.Wait()
			live := reviewLiveSlots(s, o)
			if int32(live) != o.Values() || int32(live) != s.ProcessValues() {
				t.Logf("iteration=%d live_slots=%d owner_values=%d process_values=%d", iterations, live, o.Values(), s.ProcessValues())
				t.Errorf("value counters drifted from live slots")
				o.Finish()
				return
			}
		}
		o.Finish()
	}
	t.Logf("iterations=%d no drift observed", iterations)
}

// claimMutationForReview mirrors PublishBytesMutation up to and including its
// claim (beginWrite + claimMutation), which is where counters are reconciled.
func (o *Owner) claimMutationForReview(ref RootRef) bool {
	if !o.beginWrite() {
		return false
	}
	defer o.endWrite()
	_, ok := o.claimMutation(ref)
	return ok
}

func reviewLiveSlots(s *Store, o *Owner) int {
	live := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for j := range sh.slots {
			slot := &sh.slots[j]
			if slot.pointer == 0 || slot.pointer == tombstone || slot.ownerIdx != o.index || slot.ownerGen != o.gen {
				continue
			}
			if !s.stale(slot) {
				live++
			}
		}
		sh.mu.RUnlock()
	}
	return live
}

// TestReviewFullSurfaceRace hammers every public entry point from several
// owners at once, including Finish/Acquire churn, so the race detector sees
// every shared field. Application data is immutable; only store state races.
func TestReviewFullSurfaceRace(t *testing.T) {
	s := New()
	var writerActive, operatorActive atomic.Int32
	s.BindWriterActive(&writerActive)
	s.BindOperatorActive(&operatorActive)
	shared := new(int64)
	var builderObj [4]int64
	var stop atomic.Bool
	var wg sync.WaitGroup
	var liveOwner atomic.Pointer[Owner]
	var liveKey atomic.Pointer[Key]
	for g := range 6 {
		wg.Go(func() {
			for iter := 0; !stop.Load() && iter < 400; iter++ {
				o := s.Acquire()
				if o.Disabled() {
					continue
				}
				liveOwner.Store(o)
				src := "request-value-" + string(rune('a'+g)) + "-0123456789abcdef"
				managed, ref, ok := o.TaintString(src, ranges.SourceID(1))
				if ok {
					key, _ := StringKey(managed)
					liveKey.Store(&key)
					sub := managed[3:9]
					sk, _ := StringKey(sub)
					o.Derive(sk, ref)
				}
				b, bref, ok := o.TaintBytes([]byte("bytes-payload-xyz"), ranges.SourceID(2))
				if ok {
					var set ranges.Set
					ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: uint32(len(b)), SourceID: 2}}, uint32(cap(b)))
					o.PublishBytesMutation(bref, b, &set)
				}
				BindObject(o, shared, BindingReader)
				obj := &builderObj[g%len(builderObj)]
				view := WriterView{Pointer: uintptr(0x1000 + g), Length: 4, Capacity: 8}
				var in ranges.Set
				ranges.AdoptCanonical(&in, 10, []ranges.Range{{Length: 4, SourceID: 1}}, 4)
				o.UpdateWriter(obj, WriterStringBuilder, WriterView{}, view, &in, 4, 4)
				var snap ranges.Set
				o.SnapshotWriter(obj, WriterStringBuilder, view, &snap)
				o.TruncateWriter(obj, WriterStringBuilder, view, WriterView{Pointer: view.Pointer, Length: 2, Capacity: 8})
				if iter%3 == 0 {
					o.ResetWriter(obj, WriterStringBuilder)
				}
				o.Finish()
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for !stop.Load() {
				if kp := liveKey.Load(); kp != nil {
					var out Snapshot
					s.MayContain(*kp)
					if s.Lookup(*kp, &out) {
						for i := 0; i < out.Len(); i++ {
							e, _ := out.At(i)
							if h, ok := e.Handle(s); ok {
								h.Derive(*kp, e.Root)
							}
						}
					}
				}
				var refs [MaxSnapshotOwners]OwnerRef
				n := LookupObject(s, shared, refs[:])
				for i := 0; i < n; i++ {
					if h, ok := refs[i].Handle(); ok {
						BindObjectValue(&h, shared, BindingReader)
					}
				}
				var wrefs [MaxSnapshotOwners]WriterRef
				obj := &builderObj[0]
				LookupWriterValue(s, obj, WriterStringBuilder, WriterView{}, wrefs[:])
				s.InvalidateWriterPointer(uintptr(0x1000))
				s.InvalidateBuffer(uintptr(0x2000), uintptr(0x1000), 64, false)
				if o := liveOwner.Load(); o != nil {
					o.Values()
					o.Charged()
					o.Counters()
					o.ID()
				}
				s.Stats()
				s.ProcessCharged()
				s.HasWriterStates()
			}
		})
	}
	time.Sleep(reviewDuration(t, 300*time.Millisecond)) // bounded stress duration; not a synchronization wait
	stop.Store(true)
	wg.Wait()
	if c := s.ProcessCharged(); c != 0 {
		t.Errorf("process charge leaked after all owners finished: %d", c)
	}
	if v := s.ProcessValues(); v != 0 {
		t.Errorf("process values leaked after all owners finished: %d", v)
	}
	if s.HasWriterStates() || writerActive.Load() != 0 {
		t.Errorf("writer states leaked: %d", writerActive.Load())
	}
	if operatorActive.Load() != 0 {
		t.Errorf("operator mirror drifted: %d", operatorActive.Load())
	}
	if st := s.Stats(); st.OverflowFree != OverflowBlocks {
		t.Errorf("overflow blocks leaked: free=%d", st.OverflowFree)
	}
}

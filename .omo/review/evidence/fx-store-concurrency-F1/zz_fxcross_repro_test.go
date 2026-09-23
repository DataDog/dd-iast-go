package store

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A handle captured strictly after Finish returns can only pass beginWrite's
// alive() check if Acquire recycled the slot between alive()'s generation load
// and its state load: post-Finish state is Dead, and the only transition back
// to Active (in Acquire) increments the generation first. So a true return
// from BindObject on such a handle is by itself proof that the binding was
// published into the successor generation. LookupObject is used only as
// secondary confirmation (the successor may already have finished and reset
// its table before the lookup runs).

func TestFXXStaleOwnerBindCrossover(t *testing.T) {
	s := New()

	var stop atomic.Bool
	var wg sync.WaitGroup

	held := make([]*Owner, 0, MaxOwners/2)
	for range MaxOwners / 2 {
		held = append(held, s.Acquire())
	}
	defer func() {
		stop.Store(true)
		wg.Wait()
		for _, o := range held {
			o.Finish()
		}
	}()

	free := MaxOwners - len(held)
	type stream struct {
		cur atomic.Pointer[Owner]
	}
	streams := make([]*stream, free)
	for i := range streams {
		streams[i] = &stream{}
	}
	for i := range streams {
		st := streams[i]
		wg.Go(func() {
			for !stop.Load() {
				o := s.Acquire()
				if o.Disabled() {
					continue
				}
				o.Finish()
				st.cur.Store(o)
			}
		})
	}

	var hits, lookups atomic.Int64
	var firstLog atomic.Pointer[string]
	workers := max(4, runtime.GOMAXPROCS(0))
	for range workers {
		wg.Go(func() {
			for !stop.Load() {
				for _, st := range streams {
					h := st.cur.Load()
					if h == nil || h.Disabled() {
						continue
					}
					obj := new(int64)
					if !BindObject(h, obj, BindingURL) {
						continue
					}
					hits.Add(1)
					var refs [MaxSnapshotOwners]OwnerRef
					n := LookupObject(s, obj, refs[:])
					detail := "successor already finished; binding table reset before lookup"
					for i := 0; i < n; i++ {
						if refs[i].generation != h.gen {
							if owner, ok := refs[i].Handle(); ok {
								detail = "lookup resolves fresh object to live gen " +
									itoa(refs[i].generation) + " owner id " + itoa(owner.ID()) +
									" (stale handle gen " + itoa(h.gen) + " id " + itoa(h.ID()) + ")"
								lookups.Add(1)
							}
						}
					}
					if firstLog.CompareAndSwap(nil, &detail) {
						t.Logf("CROSSOVER: post-Finish handle (slot %d, gen %d, owner id %d) bound a fresh object; %s",
							h.index, h.gen, h.ID(), detail)
					}
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
	t.Logf("post_finish_bind_success=%d lookup_confirmed=%d", hits.Load(), lookups.Load())
	if hits.Load() != 0 {
		t.Errorf("stale post-Finish owner handle published a binding into a successor generation")
	}
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

package store

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// F1: rollbackRoot's TryLock failure leaves the reserved root slot and its
// byte charge held until Finish. Readers on rootsMu (Derive/putWindow, Lookup
// from any owner) make that TryLock fail. Accumulated leaks exhaust the
// request byte budget, so every later source in the request is dropped.
func TestReviewRollbackContentionLeaksChargeUntilFinish(t *testing.T) {
	s := New()
	owner := s.Acquire()
	// A live root that reader goroutines keep deriving from. Each Derive takes
	// rootsMu.RLock in putWindow.
	anchor, anchorRoot, ok := owner.TaintString("anchor-value-for-readers", 0)
	if !ok {
		t.Fatal("anchor")
	}
	baseCharge := owner.Charged()
	baseRoots := owner.owner.rootCount.Load()

	// Make every new putWindow fail deterministically at the shard lock so
	// that each TaintString attempt goes through rollbackRoot.
	forceCollision.Store(true)
	defer forceCollision.Store(false)
	s.shards[0].mu.Lock()

	var stop atomic.Bool
	var wg sync.WaitGroup
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(off int) {
			defer wg.Done()
			for !stop.Load() {
				k, _ := StringKey(anchor[off : off+2])
				owner.Derive(k, anchorRoot)
			}
		}(r)
	}
	big := strings.Repeat("x", MaxRootBytes)
	attempts, succeeded := 0, 0
	for i := 0; i < 20000 && owner.Charged() < RequestRootBytes-MaxRootBytes; i++ {
		attempts++
		if _, _, ok := owner.TaintString(big, 0); ok {
			succeeded++
		}
	}
	stop.Store(true)
	wg.Wait()
	s.shards[0].mu.Unlock()
	forceCollision.Store(false)

	leakedRoots := owner.owner.rootCount.Load() - baseRoots
	leakedCharge := owner.Charged() - baseCharge
	t.Logf("attempts=%d succeeded=%d leakedRoots=%d leakedCharge=%d requestBudget=%d contentionDrops=%d",
		attempts, succeeded, leakedRoots, leakedCharge, RequestRootBytes, owner.Counters().Contention)

	// Now, with no contention at all, a brand new source in the same request.
	_, _, okAfter := owner.TaintString(strings.Repeat("y", MaxRootBytes), 0)
	_, _, okSmallAfter := owner.TaintString(strings.Repeat("z", 1<<15), 0)
	t.Logf("uncontended TaintString(64KiB) after leaks ok=%v; TaintString(32KiB) ok=%v; charged=%d", okAfter, okSmallAfter, owner.Charged())
	owner.Finish()
	t.Logf("after Finish processCharged=%d", s.ProcessCharged())
	if succeeded == 0 && leakedCharge > 0 {
		t.Errorf("REPRO: %d bytes / %d root slots charged with zero successful roots", leakedCharge, leakedRoots)
	}
}

// F2: sizeClasses in limits.go diverges from the Go runtime table. append
// onto a nil slice rounds capacity up to the runtime allocation size class
// (growslice -> roundupsize), which is the retained allocation size.
func TestReviewSizeClassMatchesRuntime(t *testing.T) {
	under, over := 0, 0
	var firstUnder, lastUnder, worst int
	var worstDelta int64
	for n := 1; n <= MaxRootBytes; n++ {
		real := int64(cap(append([]byte(nil), make([]byte, n)...)))
		charged := sizeClass(n)
		switch {
		case charged < real:
			if under == 0 {
				firstUnder = n
			}
			lastUnder = n
			under++
			if real-charged > worstDelta {
				worstDelta, worst = real-charged, n
			}
		case charged > real:
			over++
		}
	}
	for _, n := range []int{1025, 1088, 1089, 5376, 5377, 5392, 5393} {
		t.Logf("n=%d charged=%d runtimeClass=%d", n, sizeClass(n), cap(append([]byte(nil), make([]byte, n)...)))
	}
	t.Logf("sizes 1..%d: undercharged=%d (first=%d last=%d worst n=%d by %d bytes) overcharged=%d", MaxRootBytes, under, firstUnder, lastUnder, worst, worstDelta, over)
	if under > 0 {
		t.Errorf("REPRO: %d sizes undercharged", under)
	}
}

// F1b: the same leak without artificial locks: concurrent same-owner writers
// and derivers.
func TestReviewRollbackLeakNaturalContention(t *testing.T) {
	leakedTotal := int32(0)
	var chargeGap int64
	for round := 0; round < 20; round++ {
		s := New()
		owner := s.Acquire()
		anchor, anchorRoot, _ := owner.TaintString("anchor-value-for-readers", 0)
		var succ atomic.Int32
		var succCharge atomic.Int64
		var stop atomic.Bool
		var wg, writers sync.WaitGroup
		for r := 0; r < 4; r++ {
			wg.Add(1)
			go func(off int) {
				defer wg.Done()
				for !stop.Load() {
					k, _ := StringKey(anchor[off : off+2])
					owner.Derive(k, anchorRoot)
				}
			}(r)
		}
		// Production shape: request sources are serialized by the analysis
		// sourceMu, so only ONE goroutine calls TaintString (w == 0). Other
		// request goroutines run propagation, which adopts fresh results
		// (AdoptString) and derives windows concurrently.
		for w := 0; w < 4; w++ {
			writers.Add(1)
			go func(w int) {
				defer writers.Done()
				for i := 0; i < 60; i++ {
					v := strings.Repeat(string(rune('a'+w)), 100+i)
					if w == 0 {
						if _, _, ok := owner.TaintString(v, 0); ok {
							succ.Add(1)
							succCharge.Add(sizeClass(len(v)))
						}
						continue
					}
					var set ranges.Set
					ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(v)), SourceID: 0}}, uint32(len(v)))
					if _, ok := owner.AdoptString(strings.Clone(v), &set); ok {
						succ.Add(1)
						succCharge.Add(sizeClass(len(v)))
					}
				}
			}(w)
		}
		writers.Wait()
		stop.Store(true)
		wg.Wait()
		leaked := owner.owner.rootCount.Load() - 1 - succ.Load()
		leakedTotal += leaked
		chargeGap += owner.Charged() - sizeClass(len(anchor)) - succCharge.Load()
		owner.Finish()
	}
	t.Logf("20 rounds x (60 TaintString + 180 AdoptString on 3 goroutines) with 4 concurrent derivers: leaked root slots=%d, charged bytes without a live root=%d", leakedTotal, chargeGap)
	if leakedTotal > 0 {
		t.Errorf("REPRO: rollback contention leaked %d root reservations", leakedTotal)
	}
}

// F3: TaintBytes returns a clone with the same cap whose [len:cap] tail is
// zeroed instead of the caller's bytes, and appends no longer alias the caller's
// backing array.
func TestReviewTaintBytesTailAndAliasDiverge(t *testing.T) {
	s := New()
	owner := s.Acquire()
	defer owner.Finish()
	backing := []byte("HEADER-PAYLOAD-TAIL-DATA")
	view := backing[:6]
	managed, _, ok := owner.TaintBytes(view, 0)
	if !ok {
		t.Fatal("taint")
	}
	t.Logf("original[:cap]=%q managed[:cap]=%q", view[:cap(view)], managed[:cap(managed)])
	managed = append(managed, '!')
	t.Logf("after append on managed: backing=%q (uninstrumented append would write backing[6]='!')", backing)
}

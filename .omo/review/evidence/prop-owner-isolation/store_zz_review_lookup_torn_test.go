package store

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Lookup checks owner generation and state as two loads (lookup.go:152) while
// Acquire (owner.go:53-59) bumps generation then stores stateActive without
// lifecycleMu. For a stale window of finished owner A, a lookup can observe A's
// generation and the successor's stateActive, then read the successor's root at
// the same rootID/rootGen. The returned Entry mixes A's generation with the
// successor's owner ID and ranges.
func TestReviewLookupTornHybridEntry(t *testing.T) {
	budget := 20 * time.Second
	if v := os.Getenv("REVIEW_BUDGET"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatal(err)
		}
		budget = d
	}
	s := New()
	const maxGen = 1 << 24
	ids := make([]atomic.Uint64, maxGen)
	type staleValue struct {
		key Key
		gen uint64
	}
	var stale atomic.Pointer[staleValue]
	var stop atomic.Bool
	var lookups, entries, hybrids, handleAccepted atomic.Uint64
	var mu sync.Mutex
	var samples []string
	var wg sync.WaitGroup
	workers := max(4, runtime.GOMAXPROCS(0)-2)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var snapshot Snapshot
			for !stop.Load() {
				sv := stale.Load()
				if sv == nil {
					continue
				}
				s.Lookup(sv.key, &snapshot)
				lookups.Add(1)
				for i := 0; i < snapshot.Len(); i++ {
					e, _ := snapshot.At(i)
					entries.Add(1)
					if e.OwnerGen >= maxGen {
						continue
					}
					want := ids[e.OwnerGen].Load()
					if want != 0 && want != e.OwnerID {
						hybrids.Add(1)
						if _, ok := e.Handle(s); ok {
							handleAccepted.Add(1)
						}
						mu.Lock()
						if len(samples) < 5 {
							samples = append(samples, fmt.Sprintf("entry OwnerGen=%d (id %d) but OwnerID=%d root=%+v ranges=%d", e.OwnerGen, want, e.OwnerID, e.Root, e.Ranges.Len()))
						}
						mu.Unlock()
					}
				}
			}
		}()
	}
	var keep []string // pin stale values so their stale slots are not address-reused
	deadline := time.Now().Add(budget)
	cycles := 0
	for time.Now().Before(deadline) && cycles < maxGen-2 {
		owner := s.Acquire()
		if owner.Disabled() {
			continue
		}
		ids[owner.Generation()].Store(owner.ID())
		value, _, ok := owner.TaintString(strings.Repeat("v", 16), 0)
		if ok && (stale.Load() == nil || cycles%4096 == 0) {
			key, _ := StringKey(value)
			keep = append(keep, value)
			stale.Store(&staleValue{key: key, gen: owner.Generation()})
		}
		owner.Finish()
		cycles++
	}
	stop.Store(true)
	wg.Wait()
	runtime.KeepAlive(keep)
	t.Logf("cycles=%d lookups=%d entries=%d hybrids=%d handleAccepted=%d", cycles, lookups.Load(), entries.Load(), hybrids.Load(), handleAccepted.Load())
	for _, sample := range samples {
		t.Log(sample)
	}
	if hybrids.Load() != 0 {
		t.Errorf("Lookup returned %d hybrid entries (stale owner generation with successor owner ID/ranges)", hybrids.Load())
	}
}

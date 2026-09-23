package store

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func crashDeadlockReviewDuration(t *testing.T, fallback time.Duration) time.Duration {
	if value := os.Getenv("REVIEW_STRESS"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil {
			t.Fatal(err)
		}
		return duration
	}
	return fallback
}

// TestCrashDeadlockStaleHandleBindAfterSlotReuse proves that a stale owner
// handle cannot publish a binding into a successor generation's table.
func TestCrashDeadlockStaleHandleBindAfterSlotReuse(t *testing.T) {
	store := New()
	keep := make([]*Owner, 0, MaxOwners-1)
	for range MaxOwners - 1 {
		keep = append(keep, store.Acquire())
	}
	defer func() {
		for _, owner := range keep {
			owner.Finish()
		}
	}()

	var current atomic.Pointer[Owner]
	var stop atomic.Bool
	var hits atomic.Int64
	var cycles atomic.Int64
	var wait sync.WaitGroup
	wait.Go(func() {
		for !stop.Load() {
			owner := store.Acquire()
			if owner.Disabled() {
				continue
			}
			current.Store(owner)
			owner.Finish()
			cycles.Add(1)
		}
	})

	workers := max(2, runtime.GOMAXPROCS(0)-2)
	for range workers {
		wait.Go(func() {
			for !stop.Load() {
				handle := current.Load()
				if handle == nil {
					continue
				}
				object := new(int64)
				if !BindObject(handle, object, BindingURL) {
					continue
				}
				var refs [MaxSnapshotOwners]OwnerRef
				for index := 0; index < LookupObject(store, object, refs[:]); index++ {
					if refs[index].generation != handle.gen {
						hits.Add(1)
						t.Logf("stale handle generation %d bound object into reused generation %d", handle.gen, refs[index].generation)
					}
				}
			}
		})
	}

	deadline := time.Now().Add(crashDeadlockReviewDuration(t, 90*time.Second))
	for time.Now().Before(deadline) && hits.Load() == 0 {
		runtime.Gosched()
	}
	stop.Store(true)
	wait.Wait()
	t.Logf("cycles=%d workers=%d cross_generation_bindings=%d", cycles.Load(), workers, hits.Load())
	if hits.Load() != 0 {
		t.Fatal("stale owner handle published a binding into a reused owner generation")
	}
}

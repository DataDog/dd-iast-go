package request

// crash-race-hunt: measures capacity drops caused purely by store.Acquire
// TryLock contention while permits and owner slots are free.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
)

func TestRaceHuntBeginContentionDrops(t *testing.T) {
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
	defaultManager()
	const workers = 16 // well under the 64-permit cap
	const perWorker = 2000
	var active, dropped atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < perWorker; i++ {
				ctx, scope, _ := Begin(context.Background())
				switch scope.Decision() {
				case DecisionActive:
					active.Add(1)
				case DecisionCapacityDropped:
					dropped.Add(1)
				}
				FinishContext(ctx, true)
			}
		}()
	}
	close(start)
	wg.Wait()
	storeDrops := defaultManager().Store().AcquireDrops()
	t.Logf("workers=%d (cap 64) begins=%d active=%d capacityDropped=%d (%.1f%%) storeAcquireDrops=%d",
		workers, workers*perWorker, active.Load(), dropped.Load(), 100*float64(dropped.Load())/float64(workers*perWorker), storeDrops)
}

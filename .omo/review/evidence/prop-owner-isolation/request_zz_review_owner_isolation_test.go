package request

import (
	"context"
	"net/url"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
)

func reviewConfig(t *testing.T, maxRequests int) {
	t.Helper()
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, maxRequests
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
}

// A goroutine spawned by request A calls url.URL.Query() (ManageURLQuery with an
// empty result map) while A finishes and request B reuses the same analysis
// permit. analysisForOwner reads the plain field analysisSlot.index; Manager.Acquire
// writes it with no synchronization. Run with -race.
func TestReviewAnalysisSlotIndexRace(t *testing.T) {
	reviewConfig(t, 1)
	var current atomic.Pointer[url.URL]
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for !stop.Load() {
			if u := current.Load(); u != nil {
				ManageURLQuery(u, nil)
			}
		}
	}()
	acquired := 0
	for cycle := 0; cycle < 3000; cycle++ {
		ctx, scope, created := Begin(context.Background())
		if !created {
			t.Fatal("scope not created")
		}
		if scope.Active() {
			acquired++
		}
		u := &url.URL{Path: "/review"}
		EagerHTTP(ctx, nil, nil, nil, nil, u, nil)
		current.Store(u)
		for i := 0; i < 8; i++ {
			runtime.Gosched()
		}
		scope.Finish()
	}
	stop.Store(true)
	<-done
	t.Logf("cycles=3000 acquired=%d", acquired)
}

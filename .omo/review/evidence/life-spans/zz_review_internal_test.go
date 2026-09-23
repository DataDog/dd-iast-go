package spans

import (
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// trimStore() is checked outside LoadOrCompute, so N concurrent first-time
// callers can all observe spare capacity and all insert.
func TestReviewStoreCapacityTOCTOU(t *testing.T) {
	configureOwnerSpanTest(t)
	config.MaxConcurrentRequests = 2
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	maxSize := 0
	for range 200 {
		const n = 32
		roots := make([]*tracer.Span, n)
		for i := range roots {
			roots[i] = tracer.StartSpan("concurrent-root")
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range roots {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				AnnotationFor(roots[i])
			}()
		}
		close(start)
		wg.Wait()
		maxSize = max(maxSize, store.Size())
		for _, r := range roots {
			Finished(r)
			r.Finish()
		}
	}
	t.Logf("configured cap=%d, max observed annotation store size=%d", config.MaxConcurrentRequests, maxSize)
	if maxSize > config.MaxConcurrentRequests {
		t.Errorf("BUG: store exceeded MaxConcurrentRequests: %d > %d", maxSize, config.MaxConcurrentRequests)
	}
}

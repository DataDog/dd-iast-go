package spans

import (
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

func TestBoundsAnnotationAdmission(t *testing.T) {
	require.Equal(t, 64, config.MaxConcurrentRequests)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	for _, count := range []int{128, 512, 2048} {
		t.Run(fmt.Sprintf("inflight=%d", count), func(t *testing.T) {
			require.Zero(t, store.Size())
			roots := make([]*tracer.Span, count)
			for i := range roots {
				roots[i] = tracer.StartSpan("annotation-admission-review")
			}
			entered := make(chan struct{}, count)
			release := make(chan struct{})
			reviewAfterCapacityCheck = func() {
				entered <- struct{}{}
				<-release
			}
			var completed sync.WaitGroup
			completed.Add(count)
			for _, span := range roots {
				go func() {
					defer completed.Done()
					AnnotationFor(span)
				}()
			}
			for range count {
				<-entered
			}
			// Every caller observed an empty map. No insertion has happened.
			require.Zero(t, store.Size())
			before := eventBoundsHeap()
			close(release)
			completed.Wait()
			reviewAfterCapacityCheck = nil
			after := eventBoundsHeap()
			require.Equal(t, count, store.Size())
			t.Logf("configured=%d inflight=%d retainedAnnotations=%d ratio=%.0f heapBefore=%d heapAfter=%d delta=%d sourceCharge=%d",
				config.MaxConcurrentRequests, count, store.Size(),
				float64(store.Size())/float64(config.MaxConcurrentRequests),
				before, after, int64(after)-int64(before), processEventSourceBytes.Load())
			for _, span := range roots {
				Finished(span)
				span.Finish()
			}
			require.Zero(t, store.Size())
			runtime.KeepAlive(roots)
			mock.Reset()
		})
	}
}

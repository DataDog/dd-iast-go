package spans

// Review-only reproducer for store-memory-bounds-F2. NO production code is
// patched: goroutines are released together by a start channel BEFORE they call
// the public entry points; nothing pauses inside the check/insert window.

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func fxHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func TestFxF2AdmissionNoPatch(t *testing.T) {
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	const trials = 40
	for _, path := range []string{"BindScopeFromContext", "AnnotationFor"} {
		for _, inflight := range []int{256, 4096} {
			t.Run(fmt.Sprintf("%s/inflight=%d", path, inflight), func(t *testing.T) {
				maxRetained, sum, sampled := 0, 0, 0
				var worstDelta int64
				for trial := 0; trial < trials; trial++ {
					if store.Size() != 0 {
						t.Fatalf("store not empty: %d", store.Size())
					}
					roots := make([]*tracer.Span, inflight)
					ctxs := make([]context.Context, inflight)
					created := make([]bool, inflight)
					for i := range roots {
						roots[i] = tracer.StartSpan("http.request")
						ctx := tracer.ContextWithSpan(context.Background(), roots[i])
						if path == "BindScopeFromContext" {
							// Same sequence the woven application.http.Handler advice runs.
							ctx, created[i] = request.BeginContext(ctx)
						}
						ctxs[i] = ctx
					}
					before := fxHeap()
					start := make(chan struct{})
					var wg sync.WaitGroup
					wg.Add(inflight)
					for i := range roots {
						go func() {
							defer wg.Done()
							<-start
							if path == "BindScopeFromContext" {
								BindScopeContext(ctxs[i])
							} else {
								AnnotationFor(roots[i])
							}
						}()
					}
					close(start)
					wg.Wait()
					retained := store.Size()
					after := fxHeap()
					n := 0
					store.Range(func(_ weak.Pointer[tracer.Span], a *Annotation) bool {
						if a.Sampled {
							n++
						}
						return true
					})
					sampled += n
					if retained > maxRetained {
						maxRetained = retained
						worstDelta = int64(after) - int64(before)
					}
					sum += retained
					for i, span := range roots {
						request.FinishContext(ctxs[i], created[i])
						Finished(span)
						span.Finish()
					}
					if store.Size() != 0 {
						t.Fatalf("finish did not drain store: %d", store.Size())
					}
					runtime.KeepAlive(roots)
					mock.Reset()
				}
				t.Logf("GOMAXPROCS=%d configured=%d inflight=%d trials=%d maxRetained=%d ratio=%.1fx meanRetained=%.1f meanSampled=%.1f worstHeapDelta=%d",
					runtime.GOMAXPROCS(0), config.MaxConcurrentRequests, inflight, trials, maxRetained,
					float64(maxRetained)/float64(max(config.MaxConcurrentRequests, 1)),
					float64(sum)/trials, float64(sampled)/trials, worstDelta)
			})
		}
	}
}

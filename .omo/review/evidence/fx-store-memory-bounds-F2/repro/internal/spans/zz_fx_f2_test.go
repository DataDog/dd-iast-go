package spans

// Review-only reproducer for store-memory-bounds-F2 (no production patch).
// It relies on natural scheduling only and reports observed occupancy of the
// annotation map versus config.MaxConcurrentRequests.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func fxCount() (total, sampled int) {
	store.Range(func(_ weak.Pointer[tracer.Span], a *Annotation) bool {
		total++
		if a != nil && a.Sampled {
			sampled++
		}
		return true
	})
	return
}

// TestFxF2HTTPServer drives a real net/http server whose handler performs the
// exact calls the woven application.http.Handler advice emits
// (iast/net/http/orchestrion.yml:100-121), after the tracer span has been
// created as dd-trace-go's server wrapper does. All handlers park while their
// spans are live so occupancy can be read, then are released.
func TestFxF2HTTPServer(t *testing.T) {
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	for _, n := range []int{64, 256, 1024} {
		for trial := range 5 {
			t.Run(fmt.Sprintf("n=%d/trial=%d", n, trial), func(t *testing.T) {
				if s := store.Size(); s != 0 {
					t.Fatalf("store not empty at start: %d", s)
				}
				entered := make(chan struct{}, n)
				release := make(chan struct{})
				var spansMu sync.Mutex
				var live []*tracer.Span
				srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					span, sctx := tracer.StartSpanFromContext(r.Context(), "http.request")
					// woven advice:
					ctx, created := request.BeginContext(sctx)
					defer request.FinishContext(ctx, created)
					BindScopeContext(ctx)
					spansMu.Lock()
					live = append(live, span)
					spansMu.Unlock()
					entered <- struct{}{}
					<-release
					// woven tracer.Span.Finish hook calls Finished first.
					Finished(span)
					span.Finish()
				}))
				srv.Config.SetKeepAlivesEnabled(false)
				srv.Start()
				defer srv.Close()
				tr := &http.Transport{MaxIdleConnsPerHost: n, MaxConnsPerHost: 0}
				client := &http.Client{Transport: tr}
				defer tr.CloseIdleConnections()
				before := fxHeap()
				var wg sync.WaitGroup
				start := make(chan struct{})
				for range n {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						resp, err := client.Get(srv.URL)
						if err == nil {
							resp.Body.Close()
						}
					}()
				}
				close(start)
				for range n {
					<-entered
				}
				total, sampled := fxCount()
				after := fxHeap()
				t.Logf("HTTP configured=%d trigger=%d requests=%d storedAnnotations=%d sampled=%d ratio=%.2f heapDelta=%d",
					config.MaxConcurrentRequests, triggerTrimThreshold, n, total, sampled,
					float64(total)/float64(max(config.MaxConcurrentRequests, 1)), int64(after)-int64(before))
				close(release)
				wg.Wait()
				if s := store.Size(); s != 0 {
					t.Errorf("store not drained after finish: %d", s)
				}
				mock.Reset()
			})
		}
	}
}

// TestFxF2NearCapacity pre-fills the map to capacity-1 so every burst caller
// takes the DeleteMatching trim path before its final Size() read.
func TestFxF2NearCapacity(t *testing.T) {
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	for _, n := range []int{1024, 8192} {
		maxTotal, maxSampled := 0, 0
		for range 20 {
			prefill := make([]*tracer.Span, config.MaxConcurrentRequests-1)
			for i := range prefill {
				prefill[i] = tracer.StartSpan("prefill")
				AnnotationFor(prefill[i])
			}
			spansList := make([]*tracer.Span, n)
			for i := range spansList {
				spansList[i] = tracer.StartSpan("burst")
			}
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(n)
			for i := range n {
				go func() {
					defer wg.Done()
					<-start
					AnnotationFor(spansList[i])
				}()
			}
			close(start)
			wg.Wait()
			total, sampled := fxCount()
			if total > maxTotal {
				maxTotal, maxSampled = total, sampled
			}
			for _, s := range append(prefill, spansList...) {
				Finished(s)
				s.Finish()
			}
			if s := store.Size(); s != 0 {
				t.Fatalf("store not drained: %d", s)
			}
			mock.Reset()
		}
		t.Logf("NEARCAP configured=%d prefill=%d goroutines=%d GOMAXPROCS=%d maxStoredAnnotations=%d sampledAtMax=%d ratio=%.2f (20 trials)",
			config.MaxConcurrentRequests, config.MaxConcurrentRequests-1, n, runtime.GOMAXPROCS(0), maxTotal, maxSampled,
			float64(maxTotal)/float64(max(config.MaxConcurrentRequests, 1)))
	}
}

// TestFxF2Burst releases many goroutines at once through the real production
// entry points (BindScopeFromContext for request code, AnnotationFor for the
// scope-less Report path) with spans held live.
func TestFxF2Burst(t *testing.T) {
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	for _, path := range []string{"BindScopeFromContext", "AnnotationFor"} {
		for _, n := range []int{64, 1024, 8192} {
			maxTotal, maxSampled := 0, 0
			var maxDelta int64
			for range 10 {
				if s := store.Size(); s != 0 {
					t.Fatalf("store not empty at start: %d", s)
				}
				spansList := make([]*tracer.Span, n)
				ctxs := make([]context.Context, n)
				var finishers []func()
				for i := range spansList {
					span, sctx := tracer.StartSpanFromContext(context.Background(), "burst")
					spansList[i] = span
					if path == "BindScopeFromContext" {
						ctx, created := request.BeginContext(sctx)
						finishers = append(finishers, func() { request.FinishContext(ctx, created) })
						ctxs[i] = ctx
					}
				}
				before := fxHeap()
				start := make(chan struct{})
				var wg sync.WaitGroup
				wg.Add(n)
				for i := range n {
					go func() {
						defer wg.Done()
						<-start
						if path == "BindScopeFromContext" {
							BindScopeFromContext(ctxs[i])
						} else {
							AnnotationFor(spansList[i])
						}
					}()
				}
				close(start)
				wg.Wait()
				total, sampled := fxCount()
				delta := int64(fxHeap()) - int64(before)
				if total > maxTotal {
					maxTotal, maxSampled, maxDelta = total, sampled, delta
				}
				for _, f := range finishers {
					f()
				}
				for _, s := range spansList {
					Finished(s)
					s.Finish()
				}
				if s := store.Size(); s != 0 {
					t.Fatalf("store not drained: %d", s)
				}
				runtime.KeepAlive(spansList)
				mock.Reset()
			}
			t.Logf("BURST path=%s configured=%d goroutines=%d maxStoredAnnotations=%d sampledAtMax=%d ratio=%.2f heapDeltaAtMax=%d (10 trials)",
				path, config.MaxConcurrentRequests, n, maxTotal, maxSampled,
				float64(maxTotal)/float64(max(config.MaxConcurrentRequests, 1)), maxDelta)
		}
	}
}

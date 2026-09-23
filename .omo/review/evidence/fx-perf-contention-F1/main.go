// Review-only observation harness. It does not modify the admission algorithm.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/orchestrion/runtime/built"
)

type observer struct {
	decisions      [4]int
	missingScope   int
	activeTainted  int
	droppedTainted int
	store          *store.Store
}

func (o *observer) observe(scope *request.Scope) {
	if scope == nil {
		o.missingScope++
		return
	}
	o.decisions[scope.Decision()]++
	if scope.Active() {
		o.store = request.ActiveStore()
	}
}

// Orchestrion injects the application http.Handler fallback here. The harness
// does not call Begin or EagerHTTP on this path.
func (o *observer) ServeHTTP(_ http.ResponseWriter, r *http.Request) {
	scope := request.FromContext(r.Context())
	o.observe(scope)
	if scope == nil {
		return
	}
	if request.IsTaintedString(r.URL.RawQuery) {
		switch scope.Decision() {
		case request.DecisionActive:
			o.activeTainted++
		case request.DecisionCapacityDropped:
			o.droppedTainted++
		}
	}
}

func main() {
	surface := flag.String("surface", "api", "api (Begin/Finish) or http (woven handler)")
	iterations := flag.Int("iterations", 50000, "requests per worker in each batch")
	flag.Parse()
	if (*surface != "api" && *surface != "http") || *iterations <= 0 {
		fmt.Fprintln(os.Stderr, "invalid surface or iteration count")
		os.Exit(2)
	}
	if !config.Enabled || config.RequestSamplingPct != 30 || config.MaxConcurrentRequests != 2 {
		fmt.Fprintln(os.Stderr, "requires unmodified defaults: enabled=true sampling=30 max=2")
		os.Exit(2)
	}
	if *surface == "http" && !built.WithOrchestrion {
		fmt.Fprintln(os.Stderr, "http surface requires go tool orchestrion")
		os.Exit(2)
	}
	fmt.Printf("go=%s procs=%d woven=%v surface=%s enabled=%v sampling=%d max=%d\n",
		runtime.Version(), runtime.GOMAXPROCS(0), built.WithOrchestrion, *surface,
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests)

	var previousDrops uint64
	var taintStore *store.Store
	for _, workers := range []int{1, 2} {
		start := make(chan struct{})
		done := make(chan observer, workers)
		for range workers {
			go func() {
				<-start
				o := observer{}
				for range *iterations {
					switch *surface {
					case "api":
						_, scope, _ := request.Begin(context.Background())
						o.observe(scope)
						scope.Finish()
					case "http":
						r := &http.Request{
							Method:     http.MethodGet,
							URL:        &url.URL{Path: "/review", RawQuery: "review=payload"},
							RequestURI: "/review?review=payload",
							Header:     make(http.Header),
						}
						o.ServeHTTP(httptest.NewRecorder(), r)
					}
				}
				done <- o
			}()
		}
		close(start)
		total := observer{}
		for range workers {
			o := <-done
			for i, n := range o.decisions {
				total.decisions[i] += n
			}
			total.missingScope += o.missingScope
			total.activeTainted += o.activeTainted
			total.droppedTainted += o.droppedTainted
			if o.store != nil {
				taintStore = o.store
			}
		}
		if taintStore == nil || total.missingScope != 0 {
			fmt.Fprintf(os.Stderr, "invalid run: store=%v missing_scope=%d\n",
				taintStore != nil, total.missingScope)
			os.Exit(1)
		}
		drops := taintStore.AcquireDrops()
		active := total.decisions[request.DecisionActive]
		dropped := total.decisions[request.DecisionCapacityDropped]
		fmt.Printf("workers=%d requests=%d sampled_out=%d active=%d capacity_dropped=%d store_acquire_drops=%d lost_of_sampled=%.4f active_query_tainted=%d dropped_query_tainted=%d remaining_active=%v\n",
			workers, workers**iterations, total.decisions[request.DecisionSampledOut],
			active, dropped, drops-previousDrops, float64(dropped)/float64(max(1, active+dropped)),
			total.activeTainted, total.droppedTainted, request.ActiveStore() != nil)
		// With no more than two outstanding requests, both permits are never
		// occupied by OTHER requests. This distinguishes store rejection from
		// legitimate admission saturation without manipulating private locks.
		if uint64(dropped) != drops-previousDrops || request.ActiveStore() != nil {
			fmt.Fprintln(os.Stderr, "unexpected permit exhaustion or unfinished scope")
			os.Exit(1)
		}
		previousDrops = drops
	}
}

// Review reproducers for node life-weak-gc. Not for commit.

package spans

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func reviewReset(t *testing.T, maxConcurrent int) mocktracer.Tracer {
	t.Helper()
	enabled, rate, capacity := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	vulns, dedup := config.VulnerabilitiesPerRequest, config.DeduplicationEnabled
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, maxConcurrent
	config.VulnerabilitiesPerRequest = MaxEventVulnerabilities
	store.Clear()
	for index := range ownerSpans {
		ownerSpans[index].Store(nil)
	}
	processEventSourceBytes.Store(0)
	mock := mocktracer.Start()
	t.Cleanup(func() {
		mock.Stop()
		store.Clear()
		for index := range ownerSpans {
			ownerSpans[index].Store(nil)
		}
		processEventSourceBytes.Store(0)
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = enabled, rate, capacity
		config.VulnerabilitiesPerRequest, config.DeduplicationEnabled = vulns, dedup
	})
	return mock
}

func gc() { runtime.GC(); runtime.GC() }

// Full lifecycle with GC forced between every step, concurrently, with GC
// percent at 1 and an allocation churner. Nothing may be lost while the span is
// alive, and nothing may be retained after finish.
func TestReviewGCLifecycleNoLossNoRetention(t *testing.T) {
	mock := reviewReset(t, 64)
	old := debug.SetGCPercent(1)
	t.Cleanup(func() { debug.SetGCPercent(old) })
	stop := make(chan struct{})
	var churn sync.WaitGroup
	churn.Add(1)
	go func() {
		defer churn.Done()
		var sink [][]byte
		for {
			select {
			case <-stop:
				return
			default:
			}
			sink = append(sink, make([]byte, 4096))
			if len(sink) > 256 {
				sink = nil
			}
		}
	}()

	const workers, iterations = 8, 150
	var (
		mu             sync.Mutex
		weakSpans      []weak.Pointer[tracer.Span]
		weakAnns       []weak.Pointer[Annotation]
		failures       atomic.Int64
		firstErr       atomic.Pointer[string]
		hash           atomic.Int32
		wg             sync.WaitGroup
		emittedJSON    atomic.Int64
		admissionDrops atomic.Int64
	)
	fail := func(format string, args ...any) {
		failures.Add(1)
		msg := fmt.Sprintf(format, args...)
		firstErr.CompareAndSwap(nil, &msg)
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				_, scope, created := request.Begin(context.Background())
				if !created || !scope.Active() {
					admissionDrops.Add(1) // request/owner.go store.Acquire TryLock contention; out of scope
					scope.Finish()
					continue
				}
				analysis, _ := scope.Analysis()
				index, id, generation, _ := analysis.Identity()
				ctx := tracer.ContextWithSpan(context.Background(), tracer.StartSpan("gc-root"))
				gc()
				span, _ := tracer.SpanFromContext(ctx)
				ann := BindScope(span, scope)
				if ann == nil {
					fail("BindScope returned nil with capacity 64")
					scope.Finish()
					continue
				}
				gc()
				gotSpan, gotAnn, ok := ExistingForOwner(index, id, generation)
				if !ok || gotSpan != span || gotAnn != ann {
					fail("ExistingForOwner lost live binding after GC: ok=%t", ok)
				}
				gotSpan = nil
				gc()
				if _, a, ok := ExistingForSpan(span); !ok || a != ann {
					fail("ExistingForSpan lost live annotation after GC")
				}
				commit := taintedCommit(hash.Add(1), []string{"src"}, []int{0})
				gc()
				if !ann.TryCommitTainted(&commit, nil) {
					fail("commit failed")
				}
				gc()
				Finished(span)
				if mocktracer.MockSpan(span).Tag(SpanTagJson) != nil || mocktracer.MockSpan(span).Tag(SpanTagMetaStruct) != nil {
					emittedJSON.Add(1)
				}
				span.Finish()
				gc()
				if _, _, ok := ExistingForOwner(index, id, generation); ok {
					fail("owner binding visible after span finish")
				}
				scope.Finish()
				if ownerSpans[index].Load() != nil && ownerSpans[index].Load().id == id && ownerSpans[index].Load().generation == generation {
					fail("owner binding retained after scope finish")
				}
				if _, ok := store.Load(weak.Make(span)); ok {
					fail("store entry retained after finish")
				}
				mu.Lock()
				weakSpans = append(weakSpans, weak.Make(span))
				weakAnns = append(weakAnns, weak.Make(ann))
				mu.Unlock()
				runtime.KeepAlive(ctx)
			}
		}()
	}
	wg.Wait()
	close(stop)
	churn.Wait()
	mock.Reset()
	gc()
	gc()
	aliveSpans, aliveAnns := 0, 0
	for _, w := range weakSpans {
		if w.Value() != nil {
			aliveSpans++
		}
	}
	for _, w := range weakAnns {
		if w.Value() != nil {
			aliveAnns++
		}
	}
	t.Logf("admissionDrops=%d iterations=%d emitted=%d failures=%d aliveSpans=%d aliveAnnotations=%d storeSize=%d processSourceBytes=%d",
		admissionDrops.Load(), len(weakSpans), emittedJSON.Load(), failures.Load(), aliveSpans, aliveAnns, store.Size(), processEventSourceBytes.Load())
	if failures.Load() != 0 {
		t.Fatalf("%d failures, first: %s", failures.Load(), *firstErr.Load())
	}
	if emittedJSON.Load() != int64(len(weakSpans)) {
		t.Fatalf("emitted %d of %d events", emittedJSON.Load(), len(weakSpans))
	}
	if aliveSpans != 0 || aliveAnns != 0 || store.Size() != 0 || processEventSourceBytes.Load() != 0 {
		t.Fatal("IAST retained span/annotation/charge after finish")
	}
}

// A span reachable only through a context must keep resolving.
func TestReviewContextOnlyReachability(t *testing.T) {
	reviewReset(t, 64)
	_, scope, _ := request.Begin(context.Background())
	defer scope.Finish()
	analysis, _ := scope.Analysis()
	index, id, generation, _ := analysis.Identity()
	ctx := func() context.Context {
		span, ctx := tracer.StartSpanFromContext(context.Background(), "ctx-only")
		if BindScope(span, scope) == nil {
			t.Fatal("bind failed")
		}
		return ctx
	}()
	for range 5 {
		gc()
		if _, _, ok := ExistingForOwner(index, id, generation); !ok {
			t.Fatal("span reachable through ctx resolved as dead")
		}
	}
	span, _ := tracer.SpanFromContext(ctx)
	Finished(span)
	span.Finish()
}

// An abandoned (never finished, unreachable) root is reclaimed and its event
// source charge is released by trimStore.
func TestReviewAbandonedSpanReclaimed(t *testing.T) {
	mock := reviewReset(t, 2)
	_, scope, _ := request.Begin(context.Background())
	analysis, _ := scope.Analysis()
	index, id, generation, _ := analysis.Identity()
	w := func() weak.Pointer[tracer.Span] {
		span := tracer.StartSpan("abandoned")
		ann := BindScope(span, scope)
		commit := taintedCommit(99, []string{"abandoned-source"}, []int{0})
		if !ann.TryCommitTainted(&commit, nil) {
			t.Fatal("commit failed")
		}
		return weak.Make(span)
	}()
	if processEventSourceBytes.Load() == 0 {
		t.Fatal("expected a charge")
	}
	mock.Reset()
	gc()
	if w.Value() != nil {
		t.Fatal("abandoned span retained (by IAST or mocktracer)")
	}
	if _, _, ok := ExistingForOwner(index, id, generation); ok {
		t.Fatal("dead root resolved")
	}
	if ownerSpans[index].Load() != nil {
		t.Fatal("dead binding not cleared by ExistingForOwner")
	}
	before := processEventSourceBytes.Load()
	if !trimStore() {
		t.Fatal("trim did not free the dead key")
	}
	t.Logf("charge before trim=%d after=%d storeSize=%d", before, processEventSourceBytes.Load(), store.Size())
	if processEventSourceBytes.Load() != 0 || store.Size() != 0 {
		t.Fatal("dead annotation not released")
	}
	scope.Finish()
}

// F1: sampled-out request spans consume the annotation store (capacity
// MaxConcurrentRequests, default 2). An admitted active request then has no
// annotation, no owner binding and no orphan capacity: its findings are lost.
func TestReviewSampledOutRequestsStarveActiveRequest(t *testing.T) {
	reviewReset(t, 2) // shipped default DD_IAST_MAX_CONCURRENT_REQUESTS
	var live []*tracer.Span
	var scopes []*request.Scope
	config.RequestSamplingPct = 0
	for range 2 {
		_, scope, _ := request.Begin(context.Background())
		span := tracer.StartSpan("sampled-out-request")
		if BindScope(span, scope) != nil {
			t.Fatal("sampled-out scope returned annotation")
		}
		live, scopes = append(live, span), append(scopes, scope)
	}
	config.RequestSamplingPct = 100
	_, active, _ := request.Begin(context.Background())
	if !active.Active() {
		t.Fatal("third request was not admitted (analysis permit unavailable)")
	}
	analysis, _ := active.Analysis()
	index, id, generation, _ := analysis.Identity()
	root := tracer.StartSpan("sampled-active-request")
	gc()
	ann := BindScope(root, active)
	_, _, ownerOK := ExistingForOwner(index, id, generation)
	_, spanAnn, spanOK := ExistingForSpan(root)
	orphan, orphanAnn := NewOrphanTaintedSpan()
	t.Logf("store.Size=%d activeAdmitted=%t BindScope=%p ExistingForOwner=%t ExistingForSpan=%t(%p) orphanAnnotation=%p",
		store.Size(), active.Active(), ann, ownerOK, spanOK, spanAnn, orphanAnn)
	if orphan != nil {
		orphan.Finish()
	}
	if ann == nil || !ownerOK {
		t.Errorf("BUG: admitted active request has no annotation; every tainted finding for it is dropped (ReportTainted returns false at vulnerability/tainted.go:62-67)")
	}
	for i, span := range live {
		Finished(span)
		span.Finish()
		scopes[i].Finish()
	}
	Finished(root)
	root.Finish()
	active.Finish()
}

// F1 quantified: realistic default config (30% sampling, capacity 2) with N
// concurrent in-flight requests arriving in random order.
func TestReviewSampledOutStarvationRate(t *testing.T) {
	reviewReset(t, 2)
	config.RequestSamplingPct = 30
	for _, inflight := range []int{2, 3, 4, 8, 16} {
		admitted, starved := 0, 0
		for range 2000 {
			type req struct {
				scope *request.Scope
				span  *tracer.Span
			}
			var reqs []req
			for range inflight {
				_, scope, _ := request.Begin(context.Background())
				span := tracer.StartSpan("req")
				ann := BindScope(span, scope)
				if scope.Active() {
					admitted++
					if ann == nil {
						starved++
					}
				}
				reqs = append(reqs, req{scope, span})
			}
			for _, r := range reqs {
				Finished(r.span)
				r.span.Finish()
				r.scope.Finish()
			}
		}
		t.Logf("inflight=%2d admitted-active=%5d without-annotation=%5d (%.1f%%)", inflight, admitted, starved, 100*float64(starved)/float64(max(admitted, 1)))
	}
}

// F2: a span created from a request context after the root finished (goroutine
// outliving the handler, e.g. a traced DB call) re-creates a store entry keyed
// on the finished root. It is never finished, occupies a store slot for as long
// as the root stays reachable, and blocks later requests.
func TestReviewLateBindAfterRootFinishLeaksSlot(t *testing.T) {
	mock := reviewReset(t, 2)
	late := make([]*tracer.Span, 0, 2)
	for iteration := range 2 {
		ctx, scope, _ := request.Begin(context.Background())
		root, ctx := tracer.StartSpanFromContext(ctx, "http.request")
		if BindScopeFromContext(ctx) == nil {
			t.Fatal("bind failed")
		}
		Finished(root) // handler returned: woven Finish hook
		root.Finish()
		scope.Finish()
		if store.Size() != iteration {
			t.Fatalf("finish did not release: size=%d", store.Size())
		}
		// goroutine still running with request ctx: woven StartSpanFromContext -> BindStartSpan
		child, childCtx := tracer.StartSpanFromContext(ctx, "late.db.query")
		BindScopeFromContext(childCtx)
		late = append(late, child)
	}
	gc()
	t.Logf("store.Size after two finished requests with late child spans = %d", store.Size())
	_, active, _ := request.Begin(context.Background())
	root := tracer.StartSpan("next-request")
	ann := BindScope(root, active)
	t.Logf("next active admitted=%t annotation=%p", active.Active(), ann)
	if store.Size() != 0 && ann == nil {
		t.Errorf("BUG: stale entries keyed on finished roots block a new active request")
	}
	Finished(root)
	root.Finish()
	active.Finish()
	for _, c := range late {
		Finished(c)
		c.Finish()
	}
	// The stale entries survive child finish too; only GC + trim reclaim them.
	t.Logf("store.Size after late children finished (roots still reachable) = %d", store.Size())
	late = nil
	mock.Reset()
	gc()
	trimStore()
	t.Logf("store.Size after roots unreachable + GC + trim = %d", store.Size())
}

// F2 variant: late bind while the scope is still active (between root Finish
// and scope Finish) creates a Sampled annotation that accepts findings which
// are never emitted.
func TestReviewLateBindActiveScopeSilentlyDropsCommittedFinding(t *testing.T) {
	reviewReset(t, 64)
	ctx, scope, _ := request.Begin(context.Background())
	analysis, _ := scope.Analysis()
	index, id, generation, _ := analysis.Identity()
	root, ctx := tracer.StartSpanFromContext(ctx, "http.request")
	BindScopeFromContext(ctx)
	Finished(root)
	root.Finish()
	child, childCtx := tracer.StartSpanFromContext(ctx, "late.child")
	lateAnn := BindScopeFromContext(childCtx)
	_, ann, ok := ExistingForOwner(index, id, generation)
	committed := false
	if ok {
		commit := taintedCommit(7, []string{"late"}, []int{0})
		committed = ann.TryCommitTainted(&commit, nil)
	}
	t.Logf("lateAnnotation=%p ExistingForOwner=%t committed=%t rootFinished=true", lateAnn, ok, committed)
	scope.Finish()
	Finished(child)
	child.Finish()
	if committed {
		if _, still := store.Load(weak.Make(root)); still {
			t.Errorf("BUG: finding committed to an annotation of an already-finished root; it can never be emitted (store still holds it: %t)", still)
		}
	}
}

// F3: Finished runs weak.Make on every finished span in the process, even when
// IAST is disabled and the store is empty.
func TestReviewFinishedAllocatesPerSpan(t *testing.T) {
	reviewReset(t, 2)
	for _, enabled := range []bool{true, false} {
		config.Enabled = enabled
		spansList := make([]*tracer.Span, 202)
		for i := range spansList {
			spansList[i] = tracer.StartSpan("plain")
		}
		i := 0
		allocs := testing.AllocsPerRun(200, func() {
			Finished(spansList[i])
			i++
		})
		t.Logf("config.Enabled=%t store.Size=%d allocs per Finished(never-annotated span)=%.2f", enabled, store.Size(), allocs)
		for _, s := range spansList {
			s.Finish()
		}
	}
}

// Control for the lifecycle test: admission drops with and without forced GC.
func TestReviewAdmissionDropsUnderConcurrency(t *testing.T) {
	reviewReset(t, 64)
	for _, forceGC := range []bool{false, true} {
		var admitted, dropped atomic.Int64
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 150 {
					_, scope, _ := request.Begin(context.Background())
					if scope.Active() {
						admitted.Add(1)
					} else {
						dropped.Add(1)
					}
					if forceGC {
						runtime.GC()
					}
					scope.Finish()
				}
			}()
		}
		wg.Wait()
		t.Logf("forceGC=%t concurrency=8 capacity=64 admitted=%d dropped=%d", forceGC, admitted.Load(), dropped.Load())
	}
}

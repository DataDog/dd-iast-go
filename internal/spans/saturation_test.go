// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"math"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestStoreLimitDoesNotOverflowAtMaxCapacity(t *testing.T) {
	for _, capacity := range []int{math.MaxInt, math.MaxInt - 16383, math.MaxInt - 16384} {
		t.Run(strconv.Itoa(capacity), func(t *testing.T) {
			spans.ConfigureForTest(t, capacity, 100)
			spans.SetClosedEntryBudgetForTest(t, 16384)
			startMock(t)
			want := int64(math.MaxInt64)
			if int64(capacity) <= math.MaxInt64-16384 {
				want = int64(capacity) + 16384
			}
			if got := spans.StoreLimitForTest(); got != want {
				t.Fatalf("store limit=%d, want %d", got, want)
			}
			root := tracer.StartSpan("request")
			if !spans.AnnotationFor(root).Sampled {
				t.Fatal("request was not admitted")
			}
			spans.Finished(root)
			root.Finish()
			finished := tracer.StartSpan("finished without report")
			child := finished.StartChild("late")
			spans.Finished(finished)
			finished.Finish()
			if spans.RefusingForTest() {
				t.Fatal("refusal window started")
			}
			if spans.AnnotationFor(child).Sampled {
				t.Fatal("late report was admitted")
			}
			next := tracer.StartSpan("next")
			if !spans.AnnotationFor(next).Sampled {
				t.Fatal("next request was not admitted")
			}
			spans.Finished(next)
			next.Finish()
			child.Finish()
		})
	}
}

func startMock(t *testing.T) {
	t.Helper()
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
}

func waitForCollectedSpans(t *testing.T, pointers []weak.Pointer[tracer.Span]) {
	t.Helper()
	allCollected := func() bool {
		for _, pointer := range pointers {
			if pointer.Value() != nil {
				return false
			}
		}
		return true
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		runtime.GC()
		if allCollected() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("spans were not collected")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestLateReportsAfterMoreFinishedRootsThanTheBudget(t *testing.T) {
	const capacity, budget, total = 2, 16, 200
	spans.ConfigureForTest(t, capacity, 100)
	spans.SetClosedEntryBudgetForTest(t, budget)
	startMock(t)

	roots := make([]*tracer.Span, total)
	children := make([]*tracer.Span, total)
	for i := range roots {
		roots[i] = tracer.StartSpan("root")
		children[i] = roots[i].StartChild("child")
		spans.Finished(roots[i])
	}

	for i, child := range children {
		if spans.AnnotationFor(child).Sampled {
			t.Fatalf("root %d: a late report got an annotation", i)
		}
	}
	entryCount, openCount := spans.StoreStateForTest()
	if openCount != 0 {
		t.Errorf("late reports use %d units of capacity", openCount)
	}
	if limit := int64(capacity + budget); entryCount > limit {
		t.Errorf("%d entries, limit %d", entryCount, limit)
	}
	// The roots stay reachable until here.
	for _, root := range roots {
		_ = root.Context()
	}
}

func TestUnrecordedRootStaysRefusedWhenAPlaceIsFree(t *testing.T) {
	const capacity, budget = 2, 4
	spans.ConfigureForTest(t, capacity, 100)
	spans.SetClosedEntryBudgetForTest(t, budget)
	spans.SetRefuseWindowForTest(t, time.Hour)
	startMock(t)

	// Keep the entries alive until the root has finished with the store full.
	held := make([]*tracer.Span, capacity+budget)
	pointers := make([]weak.Pointer[tracer.Span], len(held))
	for i := range held {
		held[i] = spans.InsertEntryOfUnreferencedSpanForTest(uint64(i), false)
		pointers[i] = weak.Make(held[i])
	}
	root := tracer.StartSpan("unrecorded")
	child := root.StartChild("child")
	spans.Finished(root) // The store is full: not recorded.
	// Clear the slice because debug builds can keep it alive until the test ends.
	clear(held)
	runtime.KeepAlive(held)
	waitForCollectedSpans(t, pointers)
	spans.TrimForTest()
	if e, o := spans.StoreStateForTest(); e != 0 || o != 0 {
		t.Fatalf("entries=%d open=%d, want 0 and 0", e, o)
	}

	if spans.AnnotationFor(child).Sampled {
		t.Fatal("a late report of an unrecorded root got an annotation")
	}
	if _, o := spans.StoreStateForTest(); o != 0 {
		t.Fatalf("%d units of capacity in use", o)
	}
}

func TestStoreLimitBoundary(t *testing.T) {
	const capacity, budget = 2, 4
	spans.ConfigureForTest(t, capacity, 100)
	spans.SetClosedEntryBudgetForTest(t, budget)
	spans.SetRefuseWindowForTest(t, 0)
	startMock(t)

	var keep []*tracer.Span
	finishedRoot := func() *tracer.Span {
		root := tracer.StartSpan("root")
		keep = append(keep, root)
		spans.Finished(root)
		return root
	}
	for range budget + capacity {
		finishedRoot()
	}
	if e, _ := spans.StoreStateForTest(); e != capacity+budget {
		t.Fatalf("%d entries, want %d", e, capacity+budget)
	}

	full := tracer.StartSpan("full")
	keep = append(keep, full)
	if spans.AnnotationFor(full).Sampled {
		t.Fatal("an annotation was stored in a full store")
	}
	finishedRoot()
	if e, o := spans.StoreStateForTest(); e != capacity+budget || o != 0 {
		t.Fatalf("entries=%d open=%d, want %d and 0", e, o, capacity+budget)
	}
	if size := spans.StoreSizeForTest(); size > capacity+budget {
		t.Fatalf("the map holds %d entries", size)
	}
	_ = keep
}

func TestStoreLimitIsSharedByOpenAndClosedEntries(t *testing.T) {
	const capacity, budget = 2, 4
	spans.ConfigureForTest(t, capacity, 100)
	spans.SetClosedEntryBudgetForTest(t, budget)
	startMock(t)

	var keep []*tracer.Span
	for range budget {
		root := tracer.StartSpan("closed")
		keep = append(keep, root)
		spans.Finished(root)
	}
	for i := range capacity {
		root := tracer.StartSpan("open")
		keep = append(keep, root)
		if !spans.AnnotationFor(root).Sampled {
			t.Fatalf("open annotation %d was refused", i)
		}
	}
	extra := tracer.StartSpan("extra")
	keep = append(keep, extra)
	if spans.AnnotationFor(extra).Sampled {
		t.Fatal("capacity was exceeded")
	}
	if e, o := spans.StoreStateForTest(); e != capacity+budget || o != capacity {
		t.Fatalf("entries=%d open=%d, want %d and %d", e, o, capacity+budget, capacity)
	}
	for _, root := range keep {
		spans.Finished(root)
	}
	if e, o := spans.StoreStateForTest(); e > capacity+budget || o != 0 {
		t.Fatalf("after the finish: entries=%d open=%d", e, o)
	}
}

func TestConcurrentFinishesStayWithinTheLimit(t *testing.T) {
	const capacity, budget, workers, perWorker = 4, 32, 8, 200
	spans.ConfigureForTest(t, capacity, 100)
	spans.SetClosedEntryBudgetForTest(t, budget)
	startMock(t)

	var (
		sizeSeen atomic.Int64
		wg       sync.WaitGroup
		stop     = make(chan struct{})
		maxSeen  atomic.Int64
		observed sync.WaitGroup
	)
	observed.Add(1)
	go func() {
		defer observed.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e, _ := spans.StoreStateForTest()
				maxSeen.Store(max(maxSeen.Load(), e))
				sizeSeen.Store(max(sizeSeen.Load(), int64(spans.StoreSizeForTest())))
				spans.TrimForTest()
			}
		}
	}()

	roots := make([][]*tracer.Span, workers)
	start := make(chan struct{})
	for w := range workers {
		roots[w] = make([]*tracer.Span, perWorker)
		for i := range roots[w] {
			roots[w][i] = tracer.StartSpan("root")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for _, root := range roots[w] {
				spans.Finished(root)
				spans.AnnotationFor(root.StartChild("late"))
			}
		}()
	}
	close(start)
	wg.Wait()
	close(stop)
	observed.Wait()

	if limit := int64(capacity + budget); maxSeen.Load() > limit {
		t.Fatalf("the store held %d entries, limit %d", maxSeen.Load(), limit)
	}
	if limit := int64(capacity + budget); sizeSeen.Load() > limit {
		t.Fatalf("the map held %d entries, limit %d", sizeSeen.Load(), limit)
	}
	if _, o := spans.StoreStateForTest(); o != 0 {
		t.Fatalf("%d units of capacity in use", o)
	}
}

func TestTrimGivesBackPlaces(t *testing.T) {
	const capacity, budget = 2, 8
	spans.ConfigureForTest(t, capacity, 100)
	spans.SetClosedEntryBudgetForTest(t, budget)
	startMock(t)

	// Hold the spans until all entries are in the store.
	held := make([]*tracer.Span, budget+capacity)
	pointers := make([]weak.Pointer[tracer.Span], len(held))
	for i := range held {
		held[i] = spans.InsertEntryOfUnreferencedSpanForTest(uint64(i), i < capacity)
		pointers[i] = weak.Make(held[i])
	}
	clear(held)
	runtime.KeepAlive(held)
	waitForCollectedSpans(t, pointers)
	spans.TrimForTest()
	if e, o := spans.StoreStateForTest(); e != 0 || o != 0 {
		t.Fatalf("entries=%d open=%d, want 0 and 0", e, o)
	}

	root := tracer.StartSpan("new")
	t.Cleanup(func() { spans.Finished(root) })
	if !spans.AnnotationFor(root).Sampled {
		t.Fatal("the places of removed spans were not given back")
	}
}

// A tracer can reuse the memory of a finished span for a new span. The entry
// of the old span must not affect the new one.
func TestEntryOfReusedSpanMemoryIsReplaced(t *testing.T) {
	spans.ConfigureForTest(t, 2, 100)
	startMock(t)

	root := tracer.StartSpan("root")
	stale := spans.InsertStaleEntryForTest(root)

	ann := spans.AnnotationFor(root)
	if !ann.Sampled || ann == stale {
		t.Fatal("the entry of an earlier span with the same memory was used")
	}
	if e, _ := spans.StoreStateForTest(); e != 1 {
		t.Fatalf("%d entries, want 1", e)
	}
	spans.Finished(root)
}

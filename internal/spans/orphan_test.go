// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func orphanReport(executed *atomic.Uint64) {
	vulnerability.Report(context.Background(), constants.VulnerabilityTypeWeakHash, "MD5", executed)
}

func countFindings(t *testing.T, span *mocktracer.Span) int {
	t.Helper()
	value := span.Tag(spans.SpanTagJson)
	if value == nil {
		return 0
	}
	payload, ok := value.(string)
	if !ok {
		t.Fatalf("payload type %T", value)
	}
	var event model.Event
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatal(err)
	}
	return len(event.Vulnerabilities)
}

func requireOrphanState(t *testing.T, entries, open, registry, refused int64) {
	t.Helper()
	e, o := spans.StoreStateForTest()
	if e != entries || o != open || int64(spans.OrphanCountForTest()) != registry || spans.RefusedOrphansForTest() != refused {
		t.Fatalf("entries=%d open=%d registry=%d refused=%d, want %d %d %d %d", e, o, spans.OrphanCountForTest(), spans.RefusedOrphansForTest(), entries, open, registry, refused)
	}
}

func watchOrphans() func() (int64, int64) {
	var registry, refused atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			registry.Store(max(registry.Load(), int64(spans.OrphanCountForTest())))
			refused.Store(max(refused.Load(), spans.RefusedOrphansForTest()))
		}
	})
	return func() (int64, int64) {
		close(stop)
		wg.Wait()
		return registry.Load(), refused.Load()
	}
}

func startOrphan(t *testing.T) *spans.Orphan {
	t.Helper()
	o, started := spans.StartOrphan()
	if !started {
		t.Fatal("orphan did not start")
	}
	return o
}

func TestLateReportOnRetainedOrphanSpan(t *testing.T) {
	spans.ConfigureForTest(t, 2, 100)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	var executed atomic.Uint64
	orphanReport(&executed)
	finished := mt.FinishedSpans()
	if len(finished) != 1 || countFindings(t, finished[0]) != 1 {
		t.Fatal("initial finding missing")
	}
	child := tracer.StartSpan("late", tracer.ChildOf(finished[0].Context())) //nolint:staticcheck // mocktracer exposes the context, not the span.
	ctx := tracer.ContextWithSpan(context.Background(), child)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { vulnerability.Report(ctx, constants.VulnerabilityTypeWeakHash, "SHA1", &executed) })
	}
	wg.Wait()
	if countFindings(t, finished[0]) != 1 {
		t.Fatal("finished orphan payload changed")
	}
	if e, o := spans.StoreStateForTest(); e > 1 || o > 1 {
		t.Fatalf("entries=%d open=%d", e, o)
	}
	if spans.OrphanCountForTest() != 0 {
		t.Fatal("orphan registry not empty")
	}
	root := tracer.StartSpan("new")
	if !spans.AnnotationFor(root).Sampled {
		t.Fatal("new root not admitted")
	}
	spans.Finished(root)
	root.Finish()
	child.Finish()
	for _, span := range mt.FinishedSpans()[1:] {
		if countFindings(t, span) != 0 {
			t.Fatal("late finding was published")
		}
	}
}

func TestOrphanAndRequestBurstsStayWithinTheLimit(t *testing.T) {
	spans.ConfigureForTest(t, 2, 100)
	spans.SetClosedEntryBudgetForTest(t, 32)
	spans.SetRefuseWindowForTest(t, 0)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	for range 1000 {
		orphanReport(nil)
	}
	requireOrphanState(t, 0, 0, 0, 0)
	if spans.StoreSizeForTest() != 0 {
		t.Fatal("orphan stored an entry")
	}
	var maxEntries, maxOpen, maxRefused atomic.Int64
	stop := make(chan struct{})
	var observer sync.WaitGroup
	observer.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			e, o := spans.StoreStateForTest()
			maxEntries.Store(max(maxEntries.Load(), e))
			maxOpen.Store(max(maxOpen.Load(), o))
			maxRefused.Store(max(maxRefused.Load(), spans.RefusedOrphansForTest()))
			spans.TrimForTest()
		}
	})
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 150 {
				orphanReport(nil)
				root := tracer.StartSpan("request")
				spans.AnnotationFor(root)
				spans.Finished(root)
				root.Finish()
			}
		})
	}
	wg.Wait()
	close(stop)
	observer.Wait()
	if maxEntries.Load() > 34 || maxOpen.Load() > 2 || maxRefused.Load() > 16 || spans.StoreSizeForTest() > 34 {
		t.Fatalf("entries=%d open=%d refused=%d map=%d", maxEntries.Load(), maxOpen.Load(), maxRefused.Load(), spans.StoreSizeForTest())
	}
	if _, o := spans.StoreStateForTest(); o != 0 || spans.OrphanCountForTest() != 0 || spans.RefusedOrphansForTest() != 0 {
		t.Fatal("resources not released")
	}
}

func TestFinishedIgnoresOnlyTheOrphanSpan(t *testing.T) {
	spans.ConfigureForTest(t, 2, 100)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	o := startOrphan(t)
	spans.Finished(o.Span())
	if e, _ := spans.StoreStateForTest(); e != 0 {
		t.Fatalf("orphan made %d entries", e)
	}
	root := tracer.StartSpan("user")
	spans.Finished(root)
	other := tracer.StartSpan("same-id", tracer.WithSpanID(o.Span().Context().SpanID()))
	spans.Finished(other)
	if e, _ := spans.StoreStateForTest(); e != 2 {
		t.Fatalf("entries=%d, want 2", e)
	}
	o.Finish()
	if spans.OrphanCountForTest() != 0 {
		t.Fatal("registry not empty")
	}
}

func TestOrphanObeysTheRefusalWindow(t *testing.T) {
	spans.ConfigureForTest(t, 1, 100)
	spans.SetClosedEntryBudgetForTest(t, 1)
	spans.SetRefuseWindowForTest(t, time.Hour)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	roots := []*tracer.Span{tracer.StartSpan("one"), tracer.StartSpan("two")}
	for _, root := range roots {
		spans.Finished(root)
	}
	extra := tracer.StartSpan("overflow")
	spans.Finished(extra)
	until := spans.RefuseUntilForTest()
	if !spans.RefusingForTest() {
		t.Fatal("refusal not active")
	}
	o := startOrphan(t)
	if o.Annotation().Sampled || spans.RefusedOrphansForTest() != 1 {
		t.Fatal("orphan not refused")
	}
	spans.SetRefuseWindowForTest(t, 2*time.Hour)
	spans.Finished(o.Span())
	o.Finish()
	if spans.RefuseUntilForTest() != until || !spans.RefusingForTest() {
		t.Fatal("refusal window changed")
	}
	if e, _ := spans.StoreStateForTest(); e != 2 {
		t.Fatalf("entries=%d", e)
	}
}

func TestOrphanReportsWithoutTracerDoNotUseCapacity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		capacity int
		sampling int
		held     bool
	}{
		{"admitted", 2, 100, false},
		{"capacity full", 1, 100, true},
		{"capacity zero", 0, 100, false},
		{"sampled out", 2, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spans.ConfigureForTest(t, tc.capacity, tc.sampling)
			tracer.Stop()
			var held *tracer.Span
			var count int64
			if tc.held {
				held = spans.InsertEntryOfUnreferencedSpanForTest(1, true)
				count = 1
			}
			if orphan, started := spans.StartOrphan(); orphan != nil || started {
				t.Fatal("orphan started without a tracer")
			}
			var executed atomic.Uint64
			for range 100 {
				orphanReport(&executed)
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					for range 100 {
						orphanReport(&executed)
					}
				})
			}
			wg.Wait()
			requireOrphanState(t, count, count, 0, 0)
			if executed.Load() != 0 || spans.RefusingForTest() {
				t.Fatalf("executed=%d refusing=%v", executed.Load(), spans.RefusingForTest())
			}
			runtime.KeepAlive(held)
		})
	}
}

func TestOrphanReportsAtZeroCapacityUseNoMemory(t *testing.T) {
	spans.ConfigureForTest(t, 0, 100)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	orphan := startOrphan(t)
	requireOrphanState(t, 0, 0, 0, 0)
	orphan.Finish()
	mt.Reset()
	observe := watchOrphans()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 500 {
				orphanReport(nil)
			}
		})
	}
	wg.Wait()
	if registry, refused := observe(); registry != 0 || refused != 0 {
		t.Fatalf("registry=%d refused=%d", registry, refused)
	}
	requireOrphanState(t, 0, 0, 0, 0)
	if spans.RefusingForTest() {
		t.Fatal("refusal started")
	}
	finished := mt.FinishedSpans()
	if len(finished) != 4000 {
		t.Fatalf("spans=%d", len(finished))
	}
	for _, span := range finished {
		if span.Tag(spans.SpanTagEnabled) != nil || countFindings(t, span) != 0 {
			t.Fatal("unexpected orphan finding")
		}
	}
}

func TestSampledOutOrphanReportsUseNoMemory(t *testing.T) {
	spans.ConfigureForTest(t, 1000, 0)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	orphan := startOrphan(t)
	requireOrphanState(t, 0, 0, 0, 0)
	orphan.Finish()
	mt.Reset()
	observe := watchOrphans()
	for range 1000 {
		orphanReport(nil)
	}
	if registry, refused := observe(); registry != 0 || refused != 0 {
		t.Fatalf("registry=%d refused=%d", registry, refused)
	}
	for _, span := range mt.FinishedSpans() {
		if span.Tag(spans.SpanTagEnabled) != 0.0 {
			t.Fatal("sampled-out tag missing")
		}
	}
	requireOrphanState(t, 0, 0, 0, 0)
	config.RequestSamplingPct = 30
	for range 2000 {
		orphanReport(nil)
		if registry := spans.OrphanCountForTest(); registry != 0 {
			t.Fatalf("registry=%d after report", registry)
		}
	}
	requireOrphanState(t, 0, 0, 0, 0)
	if spans.StoreSizeForTest() != 0 || spans.RefusingForTest() {
		t.Fatal("sampled-out reports changed the store")
	}
	finished := mt.FinishedSpans()[1000:]
	for _, span := range finished {
		child := tracer.StartSpan("child", tracer.ChildOf(span.Context())) //nolint:staticcheck // mocktracer exposes the context, not the span.
		sampled := spans.SamplingDecision(child)
		tag := span.Tag(spans.SpanTagEnabled)
		if sampled && (tag != 1.0 || countFindings(t, span) != 1) || !sampled && (tag != 0.0 || countFindings(t, span) != 0) {
			t.Fatalf("sampled=%v tag=%v", sampled, tag)
		}
		child.Finish()
	}
	for range 100 {
		o := startOrphan(t)
		want := 0
		if o.Annotation().Sampled {
			want = 1
		} else {
			spans.Finished(o.Span())
		}
		if n := spans.OrphanCountForTest(); n != want {
			t.Fatalf("registry=%d, want %d", n, want)
		}
		if entries, _ := spans.StoreStateForTest(); entries != 0 {
			t.Fatalf("entries=%d", entries)
		}
		o.Finish()
	}
	if spans.OrphanCountForTest() != 0 {
		t.Fatal("registry not empty")
	}
}

func TestRefusedOrphanWithoutFreeSlotStartsNoSpan(t *testing.T) {
	for _, orphanHolder := range []bool{false, true} {
		name := "request root holds capacity"
		if orphanHolder {
			name = "admitted orphan holds capacity"
		}
		t.Run(name, func(t *testing.T) {
			spans.ConfigureForTest(t, 1, 100)
			spans.SetRefusedOrphanBudgetForTest(t, 1)
			mt := mocktracer.Start()
			t.Cleanup(mt.Stop)
			var holder *spans.Orphan
			var root *tracer.Span
			var entries, registry int64
			if orphanHolder {
				holder = startOrphan(t)
				registry = 1
			} else {
				root = tracer.StartSpan("holder")
				if !spans.AnnotationFor(root).Sampled {
					t.Fatal("holder not admitted")
				}
				entries = 1
			}
			requireOrphanState(t, entries, 1, registry, 0)
			refused := startOrphan(t)
			if refused.Annotation().Sampled {
				t.Fatal("not refused")
			}
			requireOrphanState(t, entries, 1, registry+1, 1)
			before := len(mt.OpenSpans())
			if _, started := spans.StartOrphan(); started {
				t.Fatal("started without slot")
			}
			var executed atomic.Uint64
			orphanReport(&executed)
			if executed.Load() != 0 || len(mt.OpenSpans()) != before || len(mt.FinishedSpans()) != 0 {
				t.Fatal("report started a span")
			}
			refused.Finish()
			requireOrphanState(t, entries, 1, registry, 0)
			again := startOrphan(t)
			again.Finish()
			requireOrphanState(t, entries, 1, registry, 0)
			if holder != nil {
				holder.Finish()
			} else {
				spans.Finished(root)
				root.Finish()
			}
			requireOrphanState(t, entries, 0, 0, 0)
			if spans.RefusingForTest() {
				t.Fatal("refusal window started")
			}
		})
	}
}

func TestOrphanRegistryGrowsAndShrinksWithinTheLimit(t *testing.T) {
	spans.ConfigureForTest(t, 300, 100)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	initial := spans.OrphanRegistryStatsForTest()
	results := make(chan bool, 400)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var wg sync.WaitGroup
	defer wg.Wait()
	defer releaseOnce.Do(func() { close(release) })
	for range 400 {
		wg.Go(func() {
			o, started := spans.StartOrphan()
			results <- started
			if !started {
				return
			}
			<-release
			spans.Finished(o.Span())
			o.Finish()
		})
	}
	started := 0
	for range 400 {
		if <-results {
			started++
		}
	}
	if started != 316 {
		t.Fatalf("started=%d, want 316", started)
	}
	requireOrphanState(t, 0, 300, 316, 16)
	grown := spans.OrphanRegistryStatsForTest()
	if grown.TotalGrowths <= initial.TotalGrowths {
		t.Fatal("registry did not grow")
	}
	releaseOnce.Do(func() { close(release) })
	wg.Wait()
	requireOrphanState(t, 0, 0, 0, 0)
	if spans.RefusingForTest() {
		t.Fatal("refusal window started")
	}
	for i := 0; i < 8 && spans.OrphanRegistryStatsForTest().RootBuckets != initial.RootBuckets; i++ {
		startOrphan(t).Finish()
	}
	shrunk := spans.OrphanRegistryStatsForTest()
	if shrunk.RootBuckets != initial.RootBuckets || shrunk.TotalShrinks <= initial.TotalShrinks {
		t.Fatalf("registry did not shrink: initial=%+v final=%+v", initial, shrunk)
	}
}

func TestFinishedSeesOrphansWhileTheRegistryResizes(t *testing.T) {
	spans.ConfigureForTest(t, 600, 100)
	spans.SetClosedEntryBudgetForTest(t, 0)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	initial := spans.OrphanRegistryStatsForTest()
	roots := make([]*tracer.Span, 600)
	for i := range roots {
		roots[i] = spans.InsertEntryOfUnreferencedSpanForTest(uint64(i+1), false)
	}
	probes := []*spans.Orphan{startOrphan(t), startOrphan(t)}
	var finishOnce sync.Once
	finishProbes := func() {
		finishOnce.Do(func() {
			for _, probe := range probes {
				probe.Finish()
			}
		})
	}
	defer finishProbes()
	stop := make(chan struct{})
	var stopOnce sync.Once
	var lookups atomic.Uint64
	var lookupWG sync.WaitGroup
	defer lookupWG.Wait()
	defer stopOnce.Do(func() { close(stop) })
	for i := range 8 {
		probe := probes[i%len(probes)]
		lookupWG.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				spans.Finished(probe.Span())
				lookups.Add(1)
			}
		})
	}
	deadline := time.Now().Add(15 * time.Second)
	for lookups.Load() < 1000 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if lookups.Load() < 1000 {
		t.Fatal("lookup workers did not start")
	}
	beforeGrowth := lookups.Load()
	results := make(chan bool, 630)
	release := make(chan struct{})
	var releaseOnce sync.Once
	var holderWG sync.WaitGroup
	defer holderWG.Wait()
	defer releaseOnce.Do(func() { close(release) })
	for range 630 {
		holderWG.Go(func() {
			o, started := spans.StartOrphan()
			if started {
				spans.Finished(o.Span())
			}
			results <- started
			if started {
				<-release
				o.Finish()
			}
		})
	}
	started := 0
	for range 630 {
		if <-results {
			started++
		}
	}
	if started != 614 {
		t.Fatalf("holders started=%d, want 614", started)
	}
	requireOrphanState(t, 600, 600, 616, 16)
	grown := spans.OrphanRegistryStatsForTest()
	if grown.TotalGrowths-initial.TotalGrowths < 2 || lookups.Load() <= beforeGrowth {
		t.Fatalf("growths=%d lookups=%d", grown.TotalGrowths-initial.TotalGrowths, lookups.Load()-beforeGrowth)
	}
	beforeShrink := lookups.Load()
	releaseOnce.Do(func() { close(release) })
	holderWG.Wait()
	for i := 0; i < 32 && spans.OrphanRegistryStatsForTest().RootBuckets != initial.RootBuckets; i++ {
		startOrphan(t).Finish()
	}
	shrunk := spans.OrphanRegistryStatsForTest()
	if shrunk.RootBuckets != initial.RootBuckets || shrunk.TotalShrinks <= initial.TotalShrinks || lookups.Load() <= beforeShrink {
		t.Fatalf("shrink: initial=%+v final=%+v lookups=%d", initial, shrunk, lookups.Load()-beforeShrink)
	}
	stopOnce.Do(func() { close(stop) })
	lookupWG.Wait()
	finishProbes()
	requireOrphanState(t, 600, 0, 0, 0)
	if spans.RefusingForTest() {
		t.Fatal("refusal window started")
	}
	runtime.KeepAlive(roots)
}

func TestDefaultRefusedOrphanLimit(t *testing.T) {
	spans.ConfigureForTest(t, 2, 100)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	holders := []*spans.Orphan{startOrphan(t), startOrphan(t)}
	refused := make([]*spans.Orphan, 16)
	for i := range refused {
		refused[i] = startOrphan(t)
		if refused[i].Annotation().Sampled {
			t.Fatal("refused orphan was admitted")
		}
	}
	requireOrphanState(t, 0, 2, 18, 16)
	before := len(mt.OpenSpans())
	if _, started := spans.StartOrphan(); started || len(mt.OpenSpans()) != before {
		t.Fatal("orphan started without a slot")
	}
	for _, o := range refused {
		o.Finish()
	}
	for _, o := range holders {
		o.Finish()
	}
	requireOrphanState(t, 0, 0, 0, 0)
}

func TestConcurrentOrphanReportsStayWithinTheRegistryLimit(t *testing.T) {
	spans.ConfigureForTest(t, 2, 100)
	spans.SetRefusedOrphanBudgetForTest(t, 4)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	var maxRefused, maxOpen atomic.Int64
	stop := make(chan struct{})
	var observer sync.WaitGroup
	observer.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, o := spans.StoreStateForTest()
			maxRefused.Store(max(maxRefused.Load(), spans.RefusedOrphansForTest()))
			maxOpen.Store(max(maxOpen.Load(), o))
		}
	})
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 200 {
				orphanReport(nil)
			}
		})
	}
	wg.Wait()
	close(stop)
	observer.Wait()
	if maxRefused.Load() > 4 || maxOpen.Load() > 2 {
		t.Fatalf("refused=%d open=%d", maxRefused.Load(), maxOpen.Load())
	}
	requireOrphanState(t, 0, 0, 0, 0)
	if spans.RefusingForTest() {
		t.Fatal("refusal started")
	}
	for _, span := range mt.FinishedSpans() {
		tag, n := span.Tag(spans.SpanTagEnabled), countFindings(t, span)
		if !(tag == 1.0 && n == 1 || tag == nil && n == 0) {
			t.Fatalf("tag=%v findings=%d", tag, n)
		}
	}
	root := tracer.StartSpan("request")
	if !spans.AnnotationFor(root).Sampled {
		t.Fatal("request not admitted")
	}
	spans.Finished(root)
}

func TestOrphansWithTheSameIDStayRegistered(t *testing.T) {
	for _, order := range []string{"first finishes first", "second finishes first", "recycled span object"} {
		t.Run(order, func(t *testing.T) {
			spans.ConfigureForTest(t, 2, 100)
			spans.SetClosedEntryBudgetForTest(t, 0)
			spans.SetRefuseWindowForTest(t, time.Hour)
			spans.SetOrphanIDSourceForTest(t, func() uint64 { return 42 })
			mt := mocktracer.Start()
			t.Cleanup(mt.Stop)
			roots := []*tracer.Span{
				spans.InsertEntryOfUnreferencedSpanForTest(1, false),
				spans.InsertEntryOfUnreferencedSpanForTest(2, false),
			}
			first := startOrphan(t)
			if order == "recycled span object" {
				spans.ReplaceOrphanEntryForTest(first)
				first.Finish()
				requireOrphanState(t, 2, 0, 1, 0)
				spans.Finished(first.Span())
				requireOrphanState(t, 2, 0, 1, 0)
			} else {
				second := startOrphan(t)
				requireOrphanState(t, 2, 2, 2, 0)
				if order == "second finishes first" {
					first, second = second, first
				}
				spans.Finished(first.Span())
				first.Finish()
				requireOrphanState(t, 2, 1, 1, 0)
				spans.Finished(second.Span())
				second.Finish()
				requireOrphanState(t, 2, 0, 0, 0)
			}
			if spans.RefusingForTest() {
				t.Fatal("refusal window started")
			}
			runtime.KeepAlive(roots)
		})
	}
}

func TestOrphanKeyDistinguishesReusedSpanIDs(t *testing.T) {
	t.Run("new root", func(t *testing.T) {
		spans.ConfigureForTest(t, 2, 100)
		mt := mocktracer.Start()
		t.Cleanup(mt.Stop)
		root := tracer.StartSpan("request")
		spans.AddOrphanKeyForTest(root, root.Context().SpanID()+1)
		spans.Finished(root)
		requireOrphanState(t, 1, 0, 1, 0)
		root.Finish()
	})
	t.Run("finish keeps another ID", func(t *testing.T) {
		spans.ConfigureForTest(t, 2, 100)
		mt := mocktracer.Start()
		t.Cleanup(mt.Stop)
		o := startOrphan(t)
		spans.AddOrphanKeyForTest(o.Span(), o.Span().Context().SpanID()+1)
		requireOrphanState(t, 0, 1, 2, 0)
		o.Finish()
		requireOrphanState(t, 0, 0, 1, 0)
	})
}

func mustPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("panic not recovered")
		}
	}()
	fn()
}

func TestOrphanPanicDuringStartOrFinishReleasesResources(t *testing.T) {
	for _, phase := range []string{"start", "finish"} {
		for _, admitted := range []bool{true, false} {
			name := phase + "/" + map[bool]string{true: "admitted", false: "refused"}[admitted]
			t.Run(name, func(t *testing.T) {
				spans.ConfigureForTest(t, 1, 100)
				mt := mocktracer.Start()
				t.Cleanup(mt.Stop)
				var holder *spans.Orphan
				if !admitted {
					holder = startOrphan(t)
				}
				if phase == "start" {
					spans.SetOrphanSpanStarterForTest(t, func(string, ...tracer.StartSpanOption) *tracer.Span {
						panic("test")
					})
					mustPanic(t, func() { spans.StartOrphan() })
				} else {
					o := startOrphan(t)
					spans.ReplaceOrphanSpanForTest(o, new(tracer.Span))
					mustPanic(t, o.Finish)
				}
				if holder != nil {
					holder.Finish()
				}
				requireOrphanState(t, 0, 0, 0, 0)
			})
		}
	}
}

func TestOrphanGivesBackItsPlacesAfterAPanic(t *testing.T) {
	for _, admitted := range []bool{true, false} {
		t.Run(map[bool]string{true: "admitted", false: "refused"}[admitted], func(t *testing.T) {
			spans.ConfigureForTest(t, 1, 100)
			mt := mocktracer.Start()
			t.Cleanup(mt.Stop)
			var holder *spans.Orphan
			if !admitted {
				holder = startOrphan(t)
			}
			o := startOrphan(t)
			if o.Annotation().Sampled != admitted {
				t.Fatal("wrong admission")
			}
			if admitted {
				a := o.Annotation()
				a.Lock()
				a.AddVulnerability(model.NewVulnerability(constants.VulnerabilityTypeWeakHash, model.NewEvidenceString("MD5"), nil))
				a.Unlock()
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("panic not recovered")
					}
				}()
				defer o.Finish()
				panic("test")
			}()
			finished := mt.FinishedSpans()
			if len(finished) != 1 || countFindings(t, finished[0]) != map[bool]int{true: 1, false: 0}[admitted] {
				t.Fatal("wrong payload after panic")
			}
			if holder != nil {
				holder.Finish()
			}
			requireOrphanState(t, 0, 0, 0, 0)
		})
	}
}

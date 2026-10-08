// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// TestStoreCapacityConcurrentDistinctRoots starts many insertions of
// different root spans at the same time. The spans stay strongly reachable,
// thus a trim cannot remove their entries. The store must not keep more
// entries than the configured capacity.
func TestStoreCapacityConcurrentDistinctRoots(t *testing.T) {
	configureOwnerSpanTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	// A finished scope is not active: BindScope stores a negative decision,
	// which also uses a permit.
	_, finishedScope, _ := request.Begin(context.Background())
	if finishedScope == nil {
		t.Fatal("request scope was not created")
	}
	finishedScope.Finish()

	const capacity = 4
	const workers = 96
	baseline := storeSlots.Load()
	config.MaxConcurrentRequests = int(baseline) + capacity

	roots := make([]*tracer.Span, workers)
	for i := range roots {
		roots[i] = tracer.StartSpan("capacity-root")
	}
	orphans := make([]*tracer.Span, workers)
	stored := make([]bool, workers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for i := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			switch i % 3 {
			case 0:
				stored[i] = AnnotationFor(roots[i]).Sampled
			case 1:
				BindScope(roots[i], finishedScope)
				_, stored[i] = store.Load(weak.Make(roots[i]))
			default:
				span, annotation := NewOrphanTaintedSpan()
				orphans[i] = span
				stored[i] = annotation != nil
			}
		}()
	}
	close(start)
	wait.Wait()

	successes := 0
	for _, ok := range stored {
		if ok {
			successes++
		}
	}
	if successes != capacity {
		t.Errorf("stored %d annotations, want %d (the capacity)", successes, capacity)
	}
	if got := storeSlots.Load() - baseline; got != capacity {
		t.Errorf("store permits in use = %d, want %d", got, capacity)
	}
	if got := store.Size(); int64(got) > baseline+capacity {
		t.Errorf("store size = %d, want at most %d", got, baseline+capacity)
	}

	for i := range workers {
		Finished(roots[i])
		roots[i].Finish()
		if orphans[i] != nil {
			Finished(orphans[i])
			orphans[i].Finish()
		}
	}
	if got := storeSlots.Load(); got != baseline {
		t.Errorf("store permits after finish = %d, want %d", got, baseline)
	}
}

// TestStoreCapacityReleasedByTrim checks that the trim of a dead key releases
// its permit.
func TestStoreCapacityReleasedByTrim(t *testing.T) {
	configureOwnerSpanTest(t)
	baseline := storeSlots.Load()
	config.MaxConcurrentRequests = int(baseline) + 1

	// A key whose span is not reachable. The test adds it directly with a
	// permit, as an insertion does.
	dead := weak.Make(new(tracer.Span))
	if !acquireStoreSlot() {
		t.Fatal("no permit for the first entry")
	}
	store.Store(dead, &Annotation{Sampled: true})
	if acquireStoreSlot() {
		t.Fatal("permit acquired above the capacity")
	}
	runtime.GC()
	trimStore()
	if _, ok := store.Load(dead); ok {
		t.Fatal("trim did not remove the dead key")
	}
	if got := storeSlots.Load(); got != baseline {
		t.Fatalf("store permits after trim = %d, want %d", got, baseline)
	}
}

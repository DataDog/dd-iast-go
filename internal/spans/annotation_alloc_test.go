// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// allocRuns is the number of runs of each allocation test. AllocsPerRun calls
// the function one more time first.
const allocRuns = 100

// freshSpans starts the spans of one allocation test before the measure: each
// run needs a span that has no weak pointer yet. The first span is the parent
// of the others when child is true.
func freshSpans(t *testing.T, child bool) []*tracer.Span {
	t.Helper()
	parent := tracer.StartSpan(t.Name())
	result := make([]*tracer.Span, allocRuns+1)
	for i := range result {
		if child {
			result[i] = tracer.StartSpan(t.Name(), tracer.ChildOf(parent.Context()))
		} else {
			result[i] = tracer.StartSpan(t.Name())
		}
	}
	t.Cleanup(func() {
		for _, span := range result {
			spans.Finished(span)
			span.Finish()
		}
		spans.Finished(parent)
		parent.Finish()
	})
	return result
}

// TestSampledOutSpanAllocations pins the span cost of a request without
// analysis to the Phase 6 cost: weak.Make of the root span (one allocation)
// and the store entry of the negative decision (one allocation). The
// negative decision is the shared non-sampled annotation, and Finished
// releases it without telemetry.
func TestSampledOutSpanAllocations(t *testing.T) {
	configureSamplingTest(t)
	config.RequestSamplingPct = 0
	ctx, created := request.BeginServerContext(context.Background())
	if !created {
		t.Fatal("HTTP owner scope was not created")
	}
	t.Cleanup(func() { request.FinishContext(ctx, created) })
	scope := request.FromContext(ctx)
	roots := freshSpans(t, false)
	next := 0
	allocations := testing.AllocsPerRun(allocRuns, func() {
		span := roots[next]
		next++
		if spans.BindScope(span, scope) != nil {
			t.Fatal("sampled-out scope returned a reporting annotation")
		}
		spans.Finished(span)
	})
	if allocations > 2 {
		t.Fatalf("sampled-out bind and finish: %v allocations, want at most 2", allocations)
	}

	// AnnotationFor stores the same shared negative decision.
	roots = freshSpans(t, false)
	next = 0
	allocations = testing.AllocsPerRun(allocRuns, func() {
		span := roots[next]
		next++
		if spans.AnnotationFor(span).Sampled {
			t.Fatal("zero rate accepted a span")
		}
		spans.Finished(span)
	})
	if allocations > 2 {
		t.Fatalf("sampled-out annotation and finish: %v allocations, want at most 2", allocations)
	}
}

// TestFinishedChildSpanAllocations checks that Finished does not allocate for
// a child span: a child span is never a store key, thus Finished does not
// call weak.Make for it.
func TestFinishedChildSpanAllocations(t *testing.T) {
	configureSamplingTest(t)
	children := freshSpans(t, true)
	next := 0
	allocations := testing.AllocsPerRun(allocRuns, func() {
		spans.Finished(children[next])
		next++
	})
	if allocations != 0 {
		t.Fatalf("finish of a child span: %v allocations, want 0", allocations)
	}
}

// TestFinishedChildSpanKeepsRootAnnotation checks that the finish of a child
// span does not remove the annotation of its root.
func TestFinishedChildSpanKeepsRootAnnotation(t *testing.T) {
	configureSamplingTest(t)
	root := samplingSpan(t)
	annotation := spans.AnnotationFor(root)
	if !annotation.Sampled {
		t.Fatal("expected a sampled annotation")
	}
	child := tracer.StartSpan("child", tracer.ChildOf(root.Context()))
	if child.Root() != root {
		t.Fatal("child span has a different root")
	}
	spans.Finished(child)
	child.Finish()
	if got, existing, found := spans.ExistingForSpan(root); !found || got != root || existing != annotation {
		t.Fatal("finish of a child span removed the root annotation")
	}
	if spans.AnnotationFor(child) != annotation {
		t.Fatal("child span did not resolve to the root annotation")
	}
	spans.Finished(root)
	if !annotation.Closed() {
		t.Fatal("finish of the root span did not close its annotation")
	}
}

// TestSampledOutChildSpans checks the child spans of a sampled-out request.
// The bind and the finish of a child span do not allocate: the root span has
// a weak pointer already, and a child span is never a store key. The root
// keeps its negative entry until the root span finishes.
func TestSampledOutChildSpans(t *testing.T) {
	configureSamplingTest(t)
	config.RequestSamplingPct = 0
	ctx, created := request.BeginServerContext(context.Background())
	if !created {
		t.Fatal("HTTP owner scope was not created")
	}
	t.Cleanup(func() { request.FinishContext(ctx, created) })
	scope := request.FromContext(ctx)
	root := samplingSpan(t)
	if spans.BindScope(root, scope) != nil {
		t.Fatal("sampled-out scope returned a reporting annotation")
	}
	assertNegativeRootEntry := func(when string) {
		t.Helper()
		got, annotation, found := spans.ExistingForSpan(root)
		if !found || got != root {
			t.Fatalf("%s: the root span has no entry", when)
		}
		if annotation.Sampled || annotation.Closed() {
			t.Fatalf("%s: the root entry is not the open negative decision", when)
		}
	}
	assertNegativeRootEntry("after the root bind")
	first := tracer.StartSpan(t.Name(), tracer.ChildOf(root.Context()))
	if spans.BindScope(first, scope) != nil {
		t.Fatal("child span of a sampled-out request returned a reporting annotation")
	}
	spans.Finished(first)
	first.Finish()
	assertNegativeRootEntry("after the first child finish")

	children := make([]*tracer.Span, allocRuns+1)
	for i := range children {
		children[i] = tracer.StartSpan(t.Name(), tracer.ChildOf(root.Context()))
		if children[i].Root() != root {
			t.Fatal("child span has a different root")
		}
	}
	t.Cleanup(func() {
		for _, child := range children {
			child.Finish()
		}
	})
	next := 0
	allocations := testing.AllocsPerRun(allocRuns, func() {
		child := children[next]
		next++
		if spans.BindScope(child, scope) != nil {
			t.Fatal("child span of a sampled-out request returned a reporting annotation")
		}
		spans.Finished(child)
	})
	if allocations != 0 {
		t.Fatalf("sampled-out child bind and finish: %v allocations, want 0", allocations)
	}
	assertNegativeRootEntry("after the child finish")
	if spans.AnnotationFor(children[0]).Sampled {
		t.Fatal("child span did not resolve to the negative root decision")
	}

	spans.Finished(root)
	if _, _, found := spans.ExistingForSpan(root); found {
		t.Fatal("finish of the root span did not remove its negative entry")
	}
}

// TestCapacityDroppedSpanAllocations pins the span cost of a request that the
// request capacity dropped. The scope is the shared capacity-dropped scope,
// thus the bind stores the shared negative decision: weak.Make of the root
// span and the store entry (two allocations). When the span store has no
// capacity (MaxConcurrentRequests is 0), the bind does not store an entry:
// only weak.Make allocates. Finished does not allocate more in each case.
func TestCapacityDroppedSpanAllocations(t *testing.T) {
	for _, tc := range []struct {
		name string
		// maxConcurrent is config.MaxConcurrentRequests. When it is
		// positive, one active request holds all the analysis permits.
		maxConcurrent int
		maxAllocs     float64
		stored        bool
	}{
		{name: "analysis-capacity", maxConcurrent: 1, maxAllocs: 2, stored: true},
		{name: "no-capacity", maxConcurrent: 0, maxAllocs: 1, stored: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configureSamplingTest(t)
			config.MaxConcurrentRequests = tc.maxConcurrent
			if tc.maxConcurrent > 0 {
				holder, created := request.BeginServerContext(context.Background())
				if !created || !request.FromContext(holder).Active() {
					t.Fatal("the holder request did not get the analysis permit")
				}
				t.Cleanup(func() { request.FinishContext(holder, created) })
			}
			ctx, created := request.BeginServerContext(context.Background())
			if !created {
				t.Fatal("HTTP owner scope was not created")
			}
			t.Cleanup(func() { request.FinishContext(ctx, created) })
			scope := request.FromContext(ctx)
			if scope.Decision() != request.DecisionCapacityDropped {
				t.Fatalf("decision %v, want capacity dropped", scope.Decision())
			}

			roots := freshSpans(t, false)
			next := 0
			allocations := testing.AllocsPerRun(allocRuns, func() {
				span := roots[next]
				next++
				if spans.BindScope(span, scope) != nil {
					t.Fatal("capacity-dropped scope returned a reporting annotation")
				}
				spans.Finished(span)
			})
			if allocations > tc.maxAllocs {
				t.Fatalf("capacity-dropped bind and finish: %v allocations, want at most %v", allocations, tc.maxAllocs)
			}

			// The bind stores the negative decision only when the span
			// store has capacity.
			span := samplingSpan(t)
			if spans.BindScope(span, scope) != nil {
				t.Fatal("capacity-dropped scope returned a reporting annotation")
			}
			_, annotation, found := spans.ExistingForSpan(span)
			if found != tc.stored {
				t.Fatalf("entry found: %v, want %v", found, tc.stored)
			}
			if found && annotation.Sampled {
				t.Fatal("capacity-dropped span has a sampled annotation")
			}
		})
	}
}

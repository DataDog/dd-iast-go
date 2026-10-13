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

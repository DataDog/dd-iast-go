// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package http_test

import (
	"context"
	"testing"

	iasthttp "github.com/DataDog/dd-iast-go/iast/net/http"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

// TestBindStartSpanSampledOutAllocations pins the span binding cost of a
// sampled-out request: weak.Make of the root span and the store entry of the
// negative decision. BindStartSpan binds the given span: it does not call
// tracer.SpanFromContext, which allocates a context wrapper in a woven build.
func TestBindStartSpanSampledOutAllocations(t *testing.T) {
	testConfig(t, 0, 1)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	ctx, created := request.BeginServerContext(context.Background())
	require.True(t, created)
	t.Cleanup(func() { request.FinishContext(ctx, created) })

	// Each run needs a span without a weak pointer. tracer.StartSpan and
	// tracer.ContextWithSpan are not the call sites that the aspect wraps.
	const runs = 100
	starts := make([]*tracer.Span, runs+1)
	contexts := make([]context.Context, runs+1)
	for i := range starts {
		starts[i] = tracer.StartSpan("sampled-out")
		contexts[i] = tracer.ContextWithSpan(ctx, starts[i])
	}
	t.Cleanup(func() {
		for _, span := range starts {
			span.Finish()
		}
	})
	next := 0
	allocations := testing.AllocsPerRun(runs, func() {
		span, spanCtx := iasthttp.BindStartSpan(contexts[next], starts[next])
		if span != starts[next] || spanCtx != contexts[next] {
			t.Fatal("BindStartSpan changed its results")
		}
		spans.Finished(span)
		next++
	})
	require.LessOrEqual(t, allocations, 2.0)
}

// TestBindStartSpanBindsTheGivenSpan checks that BindStartSpan binds the span
// that it gets, and ignores a context without a request scope.
func TestBindStartSpanBindsTheGivenSpan(t *testing.T) {
	testConfig(t, 100, 1)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	span := tracer.StartSpan("no-scope")
	got, gotCtx := iasthttp.BindStartSpan(context.Background(), span)
	require.Same(t, span, got)
	require.Equal(t, context.Background(), gotCtx)
	_, _, found := spans.ExistingForSpan(span)
	require.False(t, found)
	spans.Finished(span)
	span.Finish()

	ctx, created := request.BeginServerContext(context.Background())
	require.True(t, created)
	defer request.FinishContext(ctx, created)
	span = tracer.StartSpan("scope")
	spanCtx := tracer.ContextWithSpan(ctx, span)
	got, gotCtx = iasthttp.BindStartSpan(spanCtx, span)
	require.Same(t, span, got)
	require.Equal(t, spanCtx, gotCtx)
	_, annotation, found := spans.ExistingForSpan(span)
	require.True(t, found)
	require.True(t, annotation.Sampled)
	index, id, generation, ok := annotation.Owner()
	require.True(t, ok)
	analysis, active := request.FromContext(ctx).Analysis()
	require.True(t, active)
	wantIndex, wantID, wantGeneration, identified := analysis.Identity()
	require.True(t, identified)
	require.Equal(t, []any{wantIndex, wantID, wantGeneration}, []any{index, id, generation})
	spans.Finished(span)
	span.Finish()

	// A nil span is not bound and does not panic.
	got, _ = iasthttp.BindStartSpan(ctx, nil)
	require.Nil(t, got)
}

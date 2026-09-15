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
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestAnnotationGuardPaths(t *testing.T) {
	var nilAnnotation *spans.Annotation
	if !nilAnnotation.Closed() {
		t.Fatal("nil annotation reported open")
	}
	if nilAnnotation.TryUseOpen(func(*spans.Annotation) {}) {
		t.Fatal("nil annotation was used")
	}
	if (&spans.Annotation{}).TryUseOpen(func(*spans.Annotation) {}) {
		t.Fatal("non-sampled annotation was used")
	}
	open := &spans.Annotation{Sampled: true}
	if open.TryUseOpen(nil) {
		t.Fatal("nil callback was accepted")
	}
	called := false
	if !open.TryUseOpen(func(*spans.Annotation) { called = true }) || !called {
		t.Fatal("open sampled annotation was not used")
	}

	if root, annotation, ok := spans.ExistingForSpan(nil); ok || root != nil || annotation != nil {
		t.Fatal("nil span produced an existing annotation")
	}
	if spans.TryUseExisting(nil, func(*spans.Annotation) {}) {
		t.Fatal("nil span was used")
	}
	if annotation := spans.AnnotationFor(nil); annotation == nil || annotation.Sampled {
		t.Fatal("nil span did not return the non-sampled annotation")
	}
	if spans.BindScope(nil, nil) != nil {
		t.Fatal("nil span and scope were bound")
	}

	previousSampling := config.RequestSamplingPct
	config.RequestSamplingPct = 0
	t.Cleanup(func() { config.RequestSamplingPct = previousSampling })
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span := tracer.StartSpan("unsampled")
	t.Cleanup(func() { span.Finish() })
	if root, annotation, ok := spans.ExistingForSpan(span); ok || root != nil || annotation != nil {
		t.Fatal("span unexpectedly had an annotation")
	}
	annotation := spans.AnnotationFor(span)
	if annotation == nil || annotation.Sampled {
		t.Fatal("zero sampling did not return a non-sampled annotation")
	}
	if spans.TryUseExisting(span, func(*spans.Annotation) {}) {
		t.Fatal("sampled-out span was used")
	}
}

func TestFinishedClosesExistingAnnotation(t *testing.T) {
	previousSampling := config.RequestSamplingPct
	config.RequestSamplingPct = 100
	t.Cleanup(func() { config.RequestSamplingPct = previousSampling })

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span, _ := tracer.StartSpanFromContext(context.Background(), "test")
	ann := spans.AnnotationFor(span)
	ann.Lock()

	started := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		close(started)
		spans.Finished(span)
		close(finished)
	}()
	<-started
	ann.RequestTainted.Store(7)
	ann.Unlock()
	<-finished

	if ann.TryUseOpen(func(*spans.Annotation) {
		t.Fatal("used closed annotation pointer")
	}) {
		t.Fatal("closed annotation pointer remained open")
	}
	if spans.TryUseExisting(span, func(*spans.Annotation) {
		t.Fatal("used finished annotation")
	}) {
		t.Fatal("finished annotation remained open")
	}
	span.Finish()
}

func TestTryLockExistingDropsContention(t *testing.T) {
	previousSampling := config.RequestSamplingPct
	config.RequestSamplingPct = 100
	t.Cleanup(func() { config.RequestSamplingPct = previousSampling })

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span, _ := tracer.StartSpanFromContext(context.Background(), "test")
	ann := spans.AnnotationFor(span)
	ann.Lock()
	if spans.TryUseExisting(span, func(*spans.Annotation) {
		t.Fatal("used contended annotation")
	}) {
		t.Fatal("acquired contended annotation")
	}
	ann.Unlock()
	spans.Finished(span)
	span.Finish()
}

func TestAnnotationForDoesNotStoreWithoutCapacity(t *testing.T) {
	previousMaxConcurrentRequests := config.MaxConcurrentRequests
	previousSampling := config.RequestSamplingPct
	config.MaxConcurrentRequests = 0
	config.RequestSamplingPct = 100
	t.Cleanup(func() {
		config.MaxConcurrentRequests = previousMaxConcurrentRequests
		config.RequestSamplingPct = previousSampling
	})

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span := tracer.StartSpan("test")
	t.Cleanup(func() { span.Finish() })

	first := spans.AnnotationFor(span)
	second := spans.AnnotationFor(span)
	if first != second {
		t.Fatal("AnnotationFor() allocated distinct annotations with no request capacity")
	}
	if first.Sampled || second.Sampled {
		t.Error("AnnotationFor() sampled an annotation with no request capacity")
	}
	spans.Finished(span)
}

func TestAnnotationForContextUsesExistingRequestDecision(t *testing.T) {
	previousMaxConcurrentRequests := config.MaxConcurrentRequests
	previousSampling := config.RequestSamplingPct
	previousEnabled := config.Enabled
	config.Enabled = true
	config.MaxConcurrentRequests = 1
	config.RequestSamplingPct = 100
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.MaxConcurrentRequests = previousMaxConcurrentRequests
		config.RequestSamplingPct = previousSampling
	})

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	requestCtx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("request scope was not acquired")
	}
	span, spanCtx := tracer.StartSpanFromContext(requestCtx, "test")
	annotation := spans.AnnotationForContext(spanCtx, span)
	if annotation == nil || !annotation.Sampled {
		t.Fatal("context annotation did not reuse the active request decision")
	}
	if bound := spans.BindScopeFromContext(spanCtx); bound != annotation {
		t.Fatal("context binding did not reuse the annotation")
	}

	spans.Finished(span)
	if !scope.Active() {
		t.Fatal("span finish released the request-owned scope")
	}
	scope.Finish()
	span.Finish()
}

func TestBindScopePreservesExistingAnnotationAfterScopeFinish(t *testing.T) {
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	_, scope, _ := request.Begin(context.Background())
	span := tracer.StartSpan("finished-scope")
	annotation := spans.BindScope(span, scope)
	if annotation == nil {
		t.Fatal("active scope was not bound")
	}
	scope.Finish()
	if rebound := spans.BindScope(span, scope); rebound != annotation {
		t.Fatal("finished scope replaced an existing annotation")
	}
	spans.Finished(span)
	span.Finish()
}

func TestBindScopeFromContextRequiresScopeAndSpan(t *testing.T) {
	if spans.BindScopeFromContext(context.Background()) != nil {
		t.Fatal("bound a context without scope or span")
	}
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	config.Enabled = true
	config.RequestSamplingPct = 0
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
	})
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	ctx, scope, _ := request.Begin(context.Background())
	if spans.BindScopeFromContext(ctx) != nil {
		t.Fatal("bound a context without span")
	}
	span, spanCtx := tracer.StartSpanFromContext(ctx, "sampled-out")
	if spans.BindScopeFromContext(spanCtx) != nil {
		t.Fatal("stored an annotation for a sampled-out scope")
	}
	scope.Finish()
	span.Finish()
}

func TestAnnotationForReusesStoredAnnotation(t *testing.T) {
	previousMaxConcurrentRequests := config.MaxConcurrentRequests
	previousSampling := config.RequestSamplingPct
	config.MaxConcurrentRequests = 1
	config.RequestSamplingPct = 100
	t.Cleanup(func() {
		config.MaxConcurrentRequests = previousMaxConcurrentRequests
		config.RequestSamplingPct = previousSampling
	})

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span := tracer.StartSpan("test")
	t.Cleanup(func() { span.Finish() })

	first := spans.AnnotationFor(span)
	second := spans.AnnotationFor(span)
	if first != second {
		t.Fatal("AnnotationFor() did not reuse a stored annotation")
	}
	spans.Finished(span)
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"context"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestOwnerSpanBindingLifecycle(t *testing.T) {
	configureOwnerSpanTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	_, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("active scope was not created")
	}
	t.Cleanup(scope.Finish)
	span := tracer.StartSpan("owner-span")
	annotation := BindScope(span, scope)
	analysis, ok := scope.Analysis()
	if !ok {
		t.Fatal("analysis unavailable")
	}
	index, id, generation, ok := analysis.Identity()
	if !ok {
		t.Fatal("owner identity unavailable")
	}
	gotSpan, gotAnnotation, ok := ExistingForOwner(index, id, generation)
	if !ok || gotSpan != span || gotAnnotation != annotation {
		t.Fatalf("binding = (%p, %p, %t), want (%p, %p, true)", gotSpan, gotAnnotation, ok, span, annotation)
	}
	other := tracer.StartSpan("later-owner-span")
	BindScope(other, scope)
	gotSpan, gotAnnotation, ok = ExistingForOwner(index, id, generation)
	if !ok || gotSpan != span || gotAnnotation != annotation {
		t.Fatal("later span replaced the first live request-root binding")
	}
	finishOwnerSpan(index, id+1, generation)
	if _, _, ok := ExistingForOwner(index, id, generation); !ok {
		t.Fatal("mismatched identity invalidated live binding")
	}
	Finished(other)
	other.Finish()
	scope.Finish()
	if _, _, ok := ExistingForOwner(index, id, generation); ok {
		t.Fatal("finished owner binding remained visible")
	}
	Finished(span)
	span.Finish()
}

func TestOwnerSpanBindingRejectsClosedAnnotation(t *testing.T) {
	configureOwnerSpanTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	_, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("active scope was not created")
	}
	t.Cleanup(scope.Finish)
	span := tracer.StartSpan("closed-owner-span")
	BindScope(span, scope)
	analysis, _ := scope.Analysis()
	index, id, generation, _ := analysis.Identity()
	Finished(span)
	if _, _, ok := ExistingForOwner(index, id, generation); ok {
		t.Fatal("closed annotation remained visible")
	}
	scope.Finish()
	span.Finish()
}

func TestOwnerSpanConcurrentBindAndFinish(t *testing.T) {
	configureOwnerSpanTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	for range 1_000 {
		_, scope, created := request.Begin(context.Background())
		if !created || !scope.Active() {
			t.Fatal("active scope was not created")
		}
		analysis, _ := scope.Analysis()
		index, id, generation, _ := analysis.Identity()
		span := tracer.StartSpan("concurrent-owner-span")
		var wait sync.WaitGroup
		wait.Add(2)
		start := make(chan struct{})
		go func() {
			defer wait.Done()
			<-start
			BindScope(span, scope)
		}()
		go func() {
			defer wait.Done()
			<-start
			scope.Finish()
		}()
		close(start)
		wait.Wait()
		if _, _, ok := ExistingForOwner(index, id, generation); ok {
			t.Fatal("binding remained after concurrent scope finish")
		}
		Finished(span)
		span.Finish()
	}
}

func configureOwnerSpanTest(t *testing.T) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
}

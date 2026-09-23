// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestAnnotationForCachesNegativeDecision(t *testing.T) {
	configureSamplingTest(t)
	config.RequestSamplingPct = 0
	span := samplingSpan(t)
	first := spans.AnnotationFor(span)
	if first.Sampled {
		t.Fatal("zero rate accepted the initial decision")
	}

	config.RequestSamplingPct = 100
	second := spans.AnnotationFor(span)
	if second.Sampled || second != first {
		t.Fatal("sampled-out span made a fresh sampling decision")
	}
	if !spans.AnnotationFor(samplingSpan(t)).Sampled {
		t.Fatal("fresh span did not accept the changed sampling rate")
	}
}

func TestBindScopeCachesInactiveDecision(t *testing.T) {
	for _, reason := range []string{"sampled-out", "capacity-dropped", "finished"} {
		t.Run(reason, func(t *testing.T) {
			configureSamplingTest(t)
			switch reason {
			case "sampled-out":
				config.RequestSamplingPct = 0
			case "capacity-dropped":
				config.MaxConcurrentRequests = 0
			}
			ctx, created := request.BeginServerContext(context.Background())
			scope := request.FromContext(ctx)
			if !created || scope == nil {
				t.Fatal("HTTP owner scope was not created")
			}
			t.Cleanup(scope.Finish)
			if reason == "finished" {
				scope.Finish()
			}
			if scope.Active() {
				t.Fatal("expected an inactive HTTP owner scope")
			}
			config.MaxConcurrentRequests = 64
			span := samplingSpan(t)
			if spans.BindScope(span, scope) != nil {
				t.Fatal("inactive scope returned a reporting annotation")
			}

			// Weak sinks can have the tracing context without the HTTP scope.
			config.RequestSamplingPct = 100
			sinkCtx := tracer.ContextWithSpan(context.Background(), span)
			vulnerability.Report(sinkCtx, constants.VulnerabilityTypeWeakHash, "MD5", nil, vulnerability.SkipFrame{})
			annotation := spans.AnnotationFor(span)
			if annotation.Sampled {
				t.Fatal("context-free weak sink resampled an inactive HTTP owner")
			}
			if spans.TryUseExisting(span, func(*spans.Annotation) {}) {
				t.Fatal("inactive owner accepted a vulnerability callback")
			}
			if !spans.AnnotationFor(samplingSpan(t)).Sampled {
				t.Fatal("fresh span did not accept the changed sampling rate")
			}
		})
	}
}

func TestBindScopePreservesExistingDecisionForInactiveScope(t *testing.T) {
	for _, reason := range []string{"sampled-out", "capacity-dropped", "finished"} {
		t.Run(reason, func(t *testing.T) {
			configureSamplingTest(t)
			span := samplingSpan(t)
			existing := spans.AnnotationFor(span)
			if !existing.Sampled {
				t.Fatal("expected an existing sampled annotation")
			}
			switch reason {
			case "sampled-out":
				config.RequestSamplingPct = 0
			case "capacity-dropped":
				config.MaxConcurrentRequests = 0
			}
			ctx, created := request.BeginServerContext(context.Background())
			scope := request.FromContext(ctx)
			if !created || scope == nil {
				t.Fatal("HTTP owner scope was not created")
			}
			t.Cleanup(scope.Finish)
			if reason == "finished" {
				scope.Finish()
			}
			if scope.Active() {
				t.Fatal("expected an inactive scope")
			}
			config.MaxConcurrentRequests = 64
			if spans.BindScope(span, scope) != existing {
				t.Fatal("inactive scope replaced the stored span decision")
			}
			if spans.AnnotationForContext(ctx, span) != existing {
				t.Fatal("request context replaced the stored span decision")
			}
			if current := spans.AnnotationFor(span); current != existing || !current.Sampled {
				t.Fatal("inactive binding changed the earlier span decision")
			}
		})
	}
}

func configureSamplingTest(t *testing.T) mocktracer.Tracer {
	t.Helper()
	enabled, rate, capacity := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = enabled, rate, capacity
	})
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	return mock
}

func TestNegativeAnnotationsFinishIndependently(t *testing.T) {
	configureSamplingTest(t)
	config.RequestSamplingPct = 0
	first, second := samplingSpan(t), samplingSpan(t)
	firstAnnotation, secondAnnotation := spans.AnnotationFor(first), spans.AnnotationFor(second)
	spans.Finished(first)
	if !firstAnnotation.Closed() || secondAnnotation.Closed() || spans.AnnotationFor(nil).Closed() {
		t.Fatal("finishing one rejection changed another rejection or the shared fallback")
	}
	config.RequestSamplingPct = 100
	if got := spans.AnnotationFor(second); got != secondAnnotation || got.Sampled {
		t.Fatal("finishing another span invalidated the negative decision")
	}
}

func TestNegativeAnnotationsRespectCapacity(t *testing.T) {
	configureSamplingTest(t)
	config.RequestSamplingPct, config.MaxConcurrentRequests = 0, 1
	first := samplingSpan(t)
	if spans.AnnotationFor(first).Sampled {
		t.Fatal("zero rate accepted the first span")
	}
	config.RequestSamplingPct = 100
	if spans.AnnotationFor(samplingSpan(t)).Sampled {
		t.Fatal("annotation storage exceeded capacity")
	}
	spans.Finished(first)
	if !spans.AnnotationFor(samplingSpan(t)).Sampled {
		t.Fatal("negative annotation did not release storage on finish")
	}
}

func samplingSpan(t *testing.T) *tracer.Span {
	t.Helper()
	span := tracer.StartSpan(t.Name())
	t.Cleanup(func() {
		spans.Finished(span)
		span.Finish()
	})
	return span
}

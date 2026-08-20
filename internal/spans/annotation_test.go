// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestAnnotationForDoesNotStoreWithoutCapacity(t *testing.T) {
	previousMaxConcurrentRequests := config.MaxConcurrentRequests
	config.MaxConcurrentRequests = 0
	t.Cleanup(func() { config.MaxConcurrentRequests = previousMaxConcurrentRequests })

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span := tracer.StartSpan("test")
	t.Cleanup(func() { span.Finish() })

	first := spans.AnnotationFor(span)
	second := spans.AnnotationFor(span)
	if first == second {
		t.Fatal("AnnotationFor() reused an annotation with no request capacity")
	}
	if first.Sampled || second.Sampled {
		t.Error("AnnotationFor() sampled an annotation with no request capacity")
	}
	spans.Finished(span)
}

func TestAnnotationForReusesStoredAnnotation(t *testing.T) {
	previousMaxConcurrentRequests := config.MaxConcurrentRequests
	config.MaxConcurrentRequests = 1
	t.Cleanup(func() { config.MaxConcurrentRequests = previousMaxConcurrentRequests })

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

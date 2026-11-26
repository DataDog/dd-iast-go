// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package saturation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestLateReportsAfterManyFinishedRoots(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("this test needs the Finish hook: build with Orchestrion or otelc")
	}
	const total = 17000 // More than the places of the store.
	config.Enabled = true
	config.MaxConcurrentRequests, config.RequestSamplingPct = 2, 100
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	children := make([]*tracer.Span, total)
	for i := range children {
		root := tracer.StartSpan("root")
		children[i] = root.StartChild("child")
		root.Finish()
	}
	for i, child := range children {
		if spans.AnnotationFor(child).Sampled {
			t.Fatalf("root %d: a late report got an annotation", i)
		}
	}
	other := tracer.StartSpan("other")
	t.Cleanup(func() { other.Finish() })
	if spans.AnnotationFor(other).Sampled {
		t.Log("a new request got an annotation while the store was full")
	}
}

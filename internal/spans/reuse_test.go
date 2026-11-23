// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"testing"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// A tracer can reuse the memory of a finished span for a new span. The entry
// of the old span must not affect the new one.
func TestEntryOfReusedSpanMemoryIsReplaced(t *testing.T) {
	previousMax, previousPct, previousEnabled := config.MaxConcurrentRequests, config.RequestSamplingPct, config.Enabled
	config.MaxConcurrentRequests, config.RequestSamplingPct, config.Enabled = 2, 100, true
	t.Cleanup(func() {
		config.MaxConcurrentRequests, config.RequestSamplingPct, config.Enabled = previousMax, previousPct, previousEnabled
	})
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	root := tracer.StartSpan("root")
	stale := newTombstone(root.Context().SpanID() + 1)
	store.Store(weak.Make(root), stale)
	t.Cleanup(func() { store.Delete(weak.Make(root)) })

	ann := AnnotationFor(root)
	if !ann.Sampled || ann == stale {
		t.Fatal("the entry of an earlier span with the same memory was used")
	}
	t.Cleanup(func() { Finished(root) })
}

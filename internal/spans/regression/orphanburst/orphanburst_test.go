// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package orphanburst_test

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func configure(t *testing.T, capacity, sampling int) {
	t.Helper()
	oldCapacity, oldSampling := config.MaxConcurrentRequests, config.RequestSamplingPct
	oldEnabled, oldStack := config.Enabled, config.StackTraceEnabled
	oldDedup, oldLimit := config.DeduplicationEnabled, config.VulnerabilitiesPerRequest
	config.MaxConcurrentRequests, config.RequestSamplingPct = capacity, sampling
	config.Enabled, config.StackTraceEnabled, config.DeduplicationEnabled = true, false, false
	config.VulnerabilitiesPerRequest = 100000
	t.Cleanup(func() {
		config.MaxConcurrentRequests, config.RequestSamplingPct = oldCapacity, oldSampling
		config.Enabled, config.StackTraceEnabled, config.DeduplicationEnabled = oldEnabled, oldStack, oldDedup
		config.VulnerabilitiesPerRequest = oldLimit
	})
}

func findingCount(t *testing.T, span *mocktracer.Span) int {
	t.Helper()
	value := span.Tag(spans.SpanTagJson)
	if value == nil {
		return 0
	}
	data, ok := value.(string)
	if !ok {
		t.Fatalf("unexpected payload type %T", value)
	}
	var event model.Event
	if err := json.Unmarshal([]byte(data), &event); err != nil {
		t.Fatal(err)
	}
	return len(event.Vulnerabilities)
}

func report(executed *atomic.Uint64) {
	vulnerability.Report(context.Background(), constants.VulnerabilityTypeWeakHash, "MD5", executed)
}

func checkRequest(t *testing.T, mt mocktracer.Tracer) {
	t.Helper()
	root := tracer.StartSpan("request")
	ctx := tracer.ContextWithSpan(context.Background(), root)
	var executed atomic.Uint64
	vulnerability.Report(ctx, constants.VulnerabilityTypeWeakHash, "MD5", &executed)
	root.Finish()
	finished := mt.FinishedSpans()
	last := finished[len(finished)-1]
	if executed.Load() != 1 || last.Tag(spans.SpanTagEnabled) != 1.0 || findingCount(t, last) != 1 {
		t.Fatalf("request: executed=%d tag=%v findings=%d", executed.Load(), last.Tag(spans.SpanTagEnabled), findingCount(t, last))
	}
}

func TestOrphanReportBurstKeepsAnalyzingRequests(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires compile-time instrumentation")
	}
	configure(t, 2, 100)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	const total = 17000
	var executed atomic.Uint64
	for range total {
		report(&executed)
	}
	finished := mt.FinishedSpans()
	if executed.Load() != total || len(finished) != total {
		t.Fatalf("executed=%d spans=%d, want %d", executed.Load(), len(finished), total)
	}
	for i, span := range finished {
		if span.Tag(spans.SpanTagEnabled) != 1.0 || findingCount(t, span) != 1 {
			t.Fatalf("span %d: tag=%v findings=%d", i, span.Tag(spans.SpanTagEnabled), findingCount(t, span))
		}
	}
	checkRequest(t, mt)
}

func TestConcurrentOrphanReportBurst(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires compile-time instrumentation")
	}
	configure(t, 2, 100)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	const workers, each = 32, 550
	var executed atomic.Uint64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range each {
				report(&executed)
			}
		})
	}
	wg.Wait()
	finished := mt.FinishedSpans()
	if len(finished) > workers*each {
		t.Fatalf("%d spans, maximum %d", len(finished), workers*each)
	}
	var accepted uint64
	for i, span := range finished {
		tag, count := span.Tag(spans.SpanTagEnabled), findingCount(t, span)
		switch {
		case tag == 1.0 && count == 1:
			accepted++
		case tag == nil && count == 0:
		default:
			t.Fatalf("span %d: tag=%v findings=%d", i, tag, count)
		}
	}
	if accepted == 0 || accepted != executed.Load() {
		t.Fatalf("accepted=%d executed=%d", accepted, executed.Load())
	}
	checkRequest(t, mt)
}

func TestOrphanReportBurstWithoutAdmission(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("requires compile-time instrumentation")
	}
	for _, tc := range []struct {
		name               string
		capacity, sampling int
		hold               bool
		tag                any
	}{
		{"zero capacity", 0, 100, false, nil},
		{"sampled out", 2, 0, false, 0.0},
		{"capacity full", 1, 100, true, nil},
		{"partial sampling", 2, 30, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configure(t, tc.capacity, tc.sampling)
			mt := mocktracer.Start()
			t.Cleanup(mt.Stop)
			var holder *tracer.Span
			if tc.hold {
				holder = tracer.StartSpan("holder")
				if !spans.AnnotationFor(holder).Sampled {
					t.Fatal("holder not admitted")
				}
			}
			const total = 17000
			var executed atomic.Uint64
			for range total {
				report(&executed)
			}
			finished := mt.FinishedSpans()
			if len(finished) != total {
				t.Fatalf("spans=%d", len(finished))
			}
			var accepted, sampledOut uint64
			for i, span := range finished {
				tag, count := span.Tag(spans.SpanTagEnabled), findingCount(t, span)
				if tc.sampling == 30 {
					switch {
					case tag == 1.0 && count == 1:
						accepted++
					case tag == 0.0 && count == 0:
						sampledOut++
					default:
						t.Fatalf("span %d: tag=%v findings=%d", i, tag, count)
					}
				} else if tag != tc.tag || count != 0 {
					t.Fatalf("span %d: tag=%v findings=%d", i, tag, count)
				}
			}
			if executed.Load() != accepted || tc.sampling == 30 && (accepted == 0 || sampledOut == 0) {
				t.Fatalf("accepted=%d sampled out=%d executed=%d", accepted, sampledOut, executed.Load())
			}
			if holder != nil {
				holder.Finish()
			}
			config.MaxConcurrentRequests, config.RequestSamplingPct = 2, 100
			checkRequest(t, mt)
		})
	}
}

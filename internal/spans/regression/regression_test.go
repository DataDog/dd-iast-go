// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package regression_test

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

// The two tests of this file use only the API that the previous version of the
// package has, so they can run against it.

// configureRegression sets the capacity and the sampling rate for one test.
func configureRegression(t *testing.T, capacity, samplingPct int) {
	t.Helper()
	previousCapacity, previousPct := config.MaxConcurrentRequests, config.RequestSamplingPct
	previousVulns, previousDedup := config.VulnerabilitiesPerRequest, config.DeduplicationEnabled
	previousEnabled := config.Enabled
	config.MaxConcurrentRequests, config.RequestSamplingPct = capacity, samplingPct
	config.VulnerabilitiesPerRequest, config.DeduplicationEnabled = 100000, false
	config.Enabled = true
	t.Cleanup(func() {
		config.MaxConcurrentRequests, config.RequestSamplingPct = previousCapacity, previousPct
		config.VulnerabilitiesPerRequest, config.DeduplicationEnabled = previousVulns, previousDedup
		config.Enabled = previousEnabled
	})
}

func vulnerabilityCount(t *testing.T, tag any) int {
	t.Helper()
	text, ok := tag.(string)
	if !ok {
		return 0
	}
	var event model.Event
	if err := json.Unmarshal([]byte(text), &event); err != nil {
		t.Fatalf("invalid event: %v", err)
	}
	return len(event.Vulnerabilities)
}

// TestLateReportAfterRootFinish checks the reports that come after the root
// span finished, with the real Finish hook and the production report path.
func TestLateReportAfterRootFinish(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("this test needs the Finish hook: build with Orchestrion or otelc")
	}
	configureRegression(t, 1, 100)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	root := tracer.StartSpan("root")
	child := root.StartChild("child")
	ctx := tracer.ContextWithSpan(context.Background(), child)

	var executed atomic.Uint64
	vulnerability.Report(ctx, constants.VulnerabilityTypeWeakHash, "MD5", &executed)
	if executed.Load() != 1 {
		t.Fatal("the first report was not made")
	}
	child.Finish()
	root.Finish()

	finished := mockTracer.FinishedSpans()
	if len(finished) != 2 {
		t.Fatalf("%d spans finished, want 2", len(finished))
	}
	payload := finished[1].Tag("_dd.iast.json")
	if got := vulnerabilityCount(t, payload); got != 1 {
		t.Fatalf("the payload of the first Finish has %d findings, want 1", got)
	}

	// Reports after the finish, one after the other and at the same time.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulnerability.Report(ctx, constants.VulnerabilityTypeWeakHash, "SHA1", &executed)
		}()
	}
	wg.Wait()
	if late := spans.AnnotationFor(child); late.Sampled {
		t.Fatal("a report after the root finished got an annotation")
	}
	if executed.Load() != 1 {
		t.Fatalf("%d reports were made, want only the first", executed.Load())
	}

	// A second Finish of the same root, at the same time as another one, does
	// not change what the first one wrote.
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); root.Finish() }()
	}
	wg.Wait()
	if got := vulnerabilityCount(t, finished[1].Tag("_dd.iast.json")); got != 1 {
		t.Fatalf("the payload changed after the finish: %d findings", got)
	}

	// No capacity is used: another request is still sampled.
	other := tracer.StartSpan("other")
	t.Cleanup(func() { other.Finish() })
	if !spans.AnnotationFor(other).Sampled {
		t.Fatal("the late reports used capacity")
	}
}

func TestAnnotationCapacityIsAtomic(t *testing.T) {
	const capacity, goroutines = 3, 64
	configureRegression(t, capacity, 100)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	for round := range 20 {
		roots := make([]*tracer.Span, goroutines)
		for i := range roots {
			roots[i] = tracer.StartSpan("root")
		}
		var (
			wg      sync.WaitGroup
			start   = make(chan struct{})
			mu      sync.Mutex
			sampled int
		)
		for _, root := range roots {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if spans.AnnotationFor(root).Sampled {
					mu.Lock()
					sampled++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if sampled != capacity {
			t.Fatalf("round %d: %d annotations stored, want exactly %d", round, sampled, capacity)
		}
		for _, root := range roots {
			spans.Finished(root)
		}
	}
}

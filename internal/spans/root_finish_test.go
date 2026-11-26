// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"sync"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func configure(t *testing.T, capacity, samplingPct int) {
	t.Helper()
	spans.ConfigureForTest(t, capacity, samplingPct)
}

func newVulnerability() model.Vulnerability {
	return model.NewVulnerability(constants.VulnerabilityTypeWeakHash, model.NewEvidenceString("MD5"), &model.Location{})
}

// add mimics the end of a report: it adds a finding unless the annotation is closed.
func add(ann *spans.Annotation) {
	ann.Lock()
	defer ann.Unlock()
	if ann.Closed() {
		return
	}
	ann.AddVulnerability(newVulnerability())
}

func TestLateReportRacesFinish(t *testing.T) {
	configure(t, 2, 100)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	for range 50 {
		root := tracer.StartSpan("root")
		ann := spans.AnnotationFor(root)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 50 {
					add(spans.AnnotationFor(root))
				}
			}()
		}
		spans.Finished(root)
		ann.RLock()
		atFinish := len(ann.Vulnerabilities)
		ann.RUnlock()
		wg.Wait()
		ann.RLock()
		defer ann.RUnlock()
		if len(ann.Vulnerabilities) != atFinish {
			t.Fatalf("findings changed after finish: %d then %d", atFinish, len(ann.Vulnerabilities))
		}
	}
}

func TestNotSampledRequestsUseNoCapacity(t *testing.T) {
	configure(t, 1, 0)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	for range 100 {
		root := tracer.StartSpan("root")
		if spans.AnnotationFor(root).Sampled || spans.SamplingDecision(root) {
			t.Fatal("no request may be sampled at 0%")
		}
	}
	config.RequestSamplingPct = 100
	root := tracer.StartSpan("root")
	t.Cleanup(func() { spans.Finished(root) })
	if !spans.AnnotationFor(root).Sampled {
		t.Fatal("requests that are not sampled used the capacity")
	}
}

func TestSamplingDecisionIsStablePerRoot(t *testing.T) {
	configure(t, 1, 30)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	in := 0
	const total = 2000
	for range total {
		root := tracer.StartSpan("root")
		first := spans.SamplingDecision(root)
		for range 5 {
			if spans.SamplingDecision(root) != first {
				t.Fatal("the decision changed for one root")
			}
		}
		if first {
			in++
		}
	}
	if in < total*20/100 || in > total*40/100 {
		t.Fatalf("%d of %d sampled at 30%%", in, total)
	}
}

func TestFirstReportAfterRootFinish(t *testing.T) {
	configure(t, 2, 100)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	root := tracer.StartSpan("root")
	child := root.StartChild("child")
	spans.Finished(root)
	root.Finish()

	if late := spans.AnnotationFor(child); late.Sampled {
		t.Fatal("the first report after the root finished got an annotation")
	}
	for range 2 {
		other := tracer.StartSpan("other")
		if !spans.AnnotationFor(other).Sampled {
			t.Fatal("a finished root used capacity")
		}
		t.Cleanup(func() { spans.Finished(other) })
	}
}

func TestConcurrentFinishWaitsForPublication(t *testing.T) {
	configure(t, 2, 100)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	root := tracer.StartSpan("root")
	ann := spans.AnnotationFor(root)
	add(ann)

	ann.Lock() // Blocks the first call while it writes the findings.
	first, second := make(chan struct{}), make(chan struct{})
	go func() { spans.Finished(root); close(first) }()
	for !ann.Closed() {
		time.Sleep(time.Millisecond)
	}
	go func() { spans.Finished(root); close(second) }()
	select {
	case <-second:
		ann.Unlock()
		t.Fatal("a second Finished returned before the findings were written")
	case <-time.After(50 * time.Millisecond):
	}
	ann.Unlock()
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Finished did not return after the findings were written")
		}
	}
}

func TestSamplingDecisionMatchesAnnotation(t *testing.T) {
	configure(t, 1000, 30)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	for range 200 {
		root := tracer.StartSpan("root")
		child := root.StartChild("child")
		want := spans.SamplingDecision(root)
		if spans.SamplingDecision(child) != want {
			t.Fatal("a child decides differently from its root")
		}
		if got := spans.AnnotationFor(child).Sampled; got != want {
			t.Fatalf("AnnotationFor() sampled=%v, SamplingDecision() = %v", got, want)
		}
		spans.Finished(root)
	}
}

func TestReportsOfOneRootShareTheLastSlot(t *testing.T) {
	configure(t, 1, 100)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	for range 50 {
		root := tracer.StartSpan("root")
		results := make([]*spans.Annotation, 16)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[i] = spans.AnnotationFor(root)
			}()
		}
		close(start)
		wg.Wait()
		for _, ann := range results {
			if !ann.Sampled || ann != results[0] {
				t.Fatal("reports of one request did not share one annotation")
			}
		}
		spans.Finished(root)
	}
}

func TestAnnotationForNilSpan(t *testing.T) {
	configure(t, 1, 100)
	if spans.AnnotationFor(nil).Sampled {
		t.Fatal("a nil span was sampled")
	}
}

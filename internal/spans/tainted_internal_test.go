// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// +checklocksignore
func TestTryCommitTaintedMergesAndRemapsSources(t *testing.T) {
	configureTaintedCommitTest(t)
	ann := &Annotation{Sampled: true}
	first := taintedCommit(1, []string{"alpha", "beta"}, []int{0, 1, 0})
	first.Vulnerability.Location = &model.Location{}
	called := false
	if !ann.TryCommitTainted(&first, func(vulnerability *model.Vulnerability) {
		called = true
		vulnerability.Location.StackID = "stack"
	}) || !called {
		t.Fatal("first transaction failed")
	}
	if len(ann.Event.Sources) != 2 || len(ann.sourceIdentities) != 2 || len(ann.Event.Vulnerabilities) != 1 {
		t.Fatalf("first counts = sources:%d identities:%d vulnerabilities:%d", len(ann.Event.Sources), len(ann.sourceIdentities), len(ann.Event.Vulnerabilities))
	}
	assertPartSources(t, ann.Event.Vulnerabilities[0], []int{0, 1, 0})
	if first.Vulnerability.Location.StackID != "" || ann.Event.Vulnerabilities[0].Location.StackID != "stack" {
		t.Fatal("transaction mutated input location or lost committed stack ID")
	}

	second := taintedCommit(2, []string{"beta", "gamma", "beta"}, []int{0, 1, 2})
	if !ann.TryCommitTainted(&second, nil) {
		t.Fatal("second transaction failed")
	}
	assertPartSources(t, second.Vulnerability, []int{0, 1, 2})
	if len(ann.Event.Sources) != 3 || len(ann.sourceIdentities) != 3 || len(ann.Event.Vulnerabilities) != 2 {
		t.Fatalf("second counts = sources:%d identities:%d vulnerabilities:%d", len(ann.Event.Sources), len(ann.sourceIdentities), len(ann.Event.Vulnerabilities))
	}
	assertPartSources(t, ann.Event.Vulnerabilities[1], []int{1, 2, 1})

	ann.Lock()
	ann.releaseSourceIdentities()
	ann.Unlock()
}

// +checklocksignore
func TestTryCommitTaintedRejectsWithoutPartialState(t *testing.T) {
	configureTaintedCommitTest(t)
	tests := []struct {
		name   string
		mutate func(*Annotation, *TaintedCommit)
	}{
		{name: "invalid part index", mutate: func(_ *Annotation, commit *TaintedCommit) {
			*commit.Vulnerability.Evidence.ValueParts[0].SourceIndex = 2
		}},
		{name: "source mismatch", mutate: func(ann *Annotation, _ *TaintedCommit) {
			ann.Lock()
			ann.Event.Sources = append(ann.Event.Sources, model.Source{})
			ann.Unlock()
		}},
		{name: "closed", mutate: func(ann *Annotation, _ *TaintedCommit) { ann.closed.Store(true) }},
		{name: "unsampled", mutate: func(ann *Annotation, _ *TaintedCommit) { ann.Sampled = false }},
		{name: "local bytes", mutate: func(_ *Annotation, commit *TaintedCommit) {
			commit.Sources[0].Identity.Value = strings.Repeat("x", MaxEventSourceBytes+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ann := &Annotation{Sampled: true}
			commit := taintedCommit(1, []string{"alpha"}, []int{0})
			test.mutate(ann, &commit)
			before := processEventSourceBytes.Load()
			if ann.TryCommitTainted(&commit, nil) {
				t.Fatal("invalid transaction committed")
			}
			if len(ann.Event.Vulnerabilities) != 0 || len(ann.sourceIdentities) != 0 || processEventSourceBytes.Load() != before {
				t.Fatal("invalid transaction changed state or charge")
			}
		})
	}
}

// +checklocksignore
func TestTryCommitTaintedRejectsSharedNonSampledAnnotation(t *testing.T) {
	configureTaintedCommitTest(t)
	commit := taintedCommit(1, []string{"alpha"}, []int{0})
	if nonSampledAnnotation.TryCommitTainted(&commit, nil) {
		t.Fatal("shared non-sampled annotation accepted a transaction")
	}
	if len(nonSampledAnnotation.Event.Sources) != 0 || len(nonSampledAnnotation.Event.Vulnerabilities) != 0 {
		t.Fatal("shared non-sampled annotation was mutated")
	}
}

// +checklocksignore
func TestTryCommitTaintedAllowsNilEvidenceWithoutSources(t *testing.T) {
	configureTaintedCommitTest(t)
	ann := &Annotation{Sampled: true}
	commit := TaintedCommit{Vulnerability: model.Vulnerability{Hash: 1}}
	if !ann.TryCommitTainted(&commit, nil) {
		t.Fatal("nil-evidence transaction failed")
	}
	if len(ann.Event.Vulnerabilities) != 1 || ann.Event.Vulnerabilities[0].Evidence != nil {
		t.Fatal("nil evidence changed")
	}
}

// +checklocksignore
func TestTryCommitTaintedRejectsDuplicateAndCapacity(t *testing.T) {
	configureTaintedCommitTest(t)
	ann := &Annotation{Sampled: true}
	commit := taintedCommit(1, []string{"alpha"}, []int{0})
	if !ann.TryCommitTainted(&commit, nil) {
		t.Fatal("initial transaction failed")
	}
	beforeSources := len(ann.Event.Sources)
	duplicate := taintedCommit(1, []string{"new"}, []int{0})
	if ann.TryCommitTainted(&duplicate, nil) {
		t.Fatal("duplicate vulnerability committed")
	}
	if len(ann.Event.Sources) != beforeSources {
		t.Fatal("duplicate left an orphan source")
	}

	previous := config.VulnerabilitiesPerRequest
	config.VulnerabilitiesPerRequest = 1
	defer func() { config.VulnerabilitiesPerRequest = previous }()
	capacity := taintedCommit(2, []string{"new"}, []int{0})
	if ann.TryCommitTainted(&capacity, nil) {
		t.Fatal("over-capacity vulnerability committed")
	}

	ann.Lock()
	ann.releaseSourceIdentities()
	ann.Unlock()
}

// +checklocksignore
func TestTryCommitTaintedRecoversBeforeCommitPanic(t *testing.T) {
	configureTaintedCommitTest(t)
	ann := &Annotation{Sampled: true}
	commit := taintedCommit(1, []string{"alpha"}, []int{0})
	before := processEventSourceBytes.Load()
	if ann.TryCommitTainted(&commit, func(*model.Vulnerability) { panic("callback") }) {
		t.Fatal("panicking callback committed")
	}
	if len(ann.Event.Sources) != 0 || len(ann.Event.Vulnerabilities) != 0 || processEventSourceBytes.Load() != before {
		t.Fatal("panicking callback left state or charge")
	}
}

// +checklocksignore
func TestTryCommitTaintedSourceCountBoundary(t *testing.T) {
	configureTaintedCommitTest(t)
	identities := make([]string, MaxEventSources)
	for index := range identities {
		identities[index] = string(rune(index + 1))
	}
	ann := &Annotation{Sampled: true}
	commit := taintedCommit(1, identities, []int{MaxEventSources - 1})
	if !ann.TryCommitTainted(&commit, nil) {
		t.Fatal("maximum source-count transaction failed")
	}
	if len(ann.Event.Sources) != MaxEventSources {
		t.Fatalf("source count = %d, want %d", len(ann.Event.Sources), MaxEventSources)
	}
	tooMany := append(append([]string(nil), identities...), "overflow")
	extra := &Annotation{Sampled: true}
	rejected := taintedCommit(2, tooMany, []int{0})
	if extra.TryCommitTainted(&rejected, nil) {
		t.Fatal("over-source-count transaction committed")
	}
	ann.Lock()
	ann.releaseSourceIdentities()
	ann.Unlock()
}

// +checklocksignore
func TestTryCommitTaintedProcessByteLimit(t *testing.T) {
	configureTaintedCommitTest(t)
	value := strings.Repeat("x", MaxEventSourceBytes-len("parameter"))
	annotations := make([]*Annotation, 0, MaxProcessEventSourceBytes/MaxEventSourceBytes)
	for index := 0; index < cap(annotations); index++ {
		ann := &Annotation{Sampled: true}
		commit := taintedCommit(int32(index+1), []string{value}, []int{0})
		if !ann.TryCommitTainted(&commit, nil) {
			t.Fatalf("transaction %d failed before process capacity", index)
		}
		annotations = append(annotations, ann)
	}
	extra := &Annotation{Sampled: true}
	commit := taintedCommit(99, []string{value}, []int{0})
	if extra.TryCommitTainted(&commit, nil) {
		t.Fatal("transaction exceeded process byte capacity")
	}
	for _, ann := range annotations {
		ann.Lock()
		ann.releaseSourceIdentities()
		ann.Unlock()
	}
	if got := processEventSourceBytes.Load(); got != 0 {
		t.Fatalf("process source bytes = %d, want 0", got)
	}
}

// +checklocksignore
func TestFinishedReleasesExactSourceIdentities(t *testing.T) {
	configureTaintedCommitTest(t)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span, _ := tracer.StartSpanFromContext(context.Background(), "test")
	ann := AnnotationFor(span)
	commit := taintedCommit(1, []string{"alpha", "beta"}, []int{0, 1})
	if !ann.TryCommitTainted(&commit, nil) {
		t.Fatal("transaction failed")
	}
	if processEventSourceBytes.Load() == 0 {
		t.Fatal("transaction did not charge source identity bytes")
	}
	Finished(span)
	if processEventSourceBytes.Load() != 0 || len(ann.sourceIdentities) != 0 {
		t.Fatal("finish retained exact source identities")
	}
	if len(ann.Event.Sources) != 2 || len(ann.Event.Vulnerabilities) != 1 {
		t.Fatal("finish cleared wire event data")
	}
	assertPartSources(t, ann.Event.Vulnerabilities[0], []int{0, 1})
	span.Finish()
}

// +checklocksignore
func TestTryCommitTaintedSerializesWithFinish(t *testing.T) {
	configureTaintedCommitTest(t)
	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)
	span, _ := tracer.StartSpanFromContext(context.Background(), "test")
	ann := AnnotationFor(span)
	commit := taintedCommit(1, []string{"alpha"}, []int{0})
	entered := make(chan struct{})
	release := make(chan struct{})
	commitDone := make(chan bool)
	go func() {
		commitDone <- ann.TryCommitTainted(&commit, func(*model.Vulnerability) {
			close(entered)
			<-release
		})
	}()
	<-entered
	finishDone := make(chan struct{})
	go func() {
		Finished(span)
		close(finishDone)
	}()
	close(release)
	if !<-commitDone {
		t.Fatal("transaction did not commit before finish")
	}
	<-finishDone
	if processEventSourceBytes.Load() != 0 {
		t.Fatal("finish did not release committed source identities")
	}
	if ann.TryCommitTainted(&commit, nil) {
		t.Fatal("closed annotation accepted a transaction")
	}
	span.Finish()
}

// +checklocksignore
func TestTryCommitTaintedDropsContention(t *testing.T) {
	configureTaintedCommitTest(t)
	ann := &Annotation{Sampled: true}
	commit := taintedCommit(1, []string{"alpha"}, []int{0})
	ann.Lock()
	if ann.TryCommitTainted(&commit, nil) {
		t.Fatal("contended transaction committed")
	}
	ann.Unlock()
}

func taintedCommit(hash int32, identities []string, partSources []int) TaintedCommit {
	sources := make([]TaintedSource, len(identities))
	for index, value := range identities {
		sources[index] = TaintedSource{
			Identity: SourceIdentity{Origin: constants.OriginHttpRequestParameter, Name: "parameter", Value: value},
			Model:    model.NewSourceString(constants.OriginHttpRequestParameter, "parameter", value),
		}
	}
	parts := make([]model.ValuePart, len(partSources))
	for index, source := range partSources {
		parts[index] = model.NewValuePartTaintedString("x", source, nil)
	}
	return TaintedCommit{Vulnerability: model.Vulnerability{
		Type:     constants.VulnerabilityTypeSqlInjection,
		Hash:     hash,
		Evidence: model.NewEvidenceTaintedValue(parts),
	}, Sources: sources}
}

func assertPartSources(t *testing.T, vulnerability model.Vulnerability, want []int) {
	t.Helper()
	if vulnerability.Evidence == nil || len(vulnerability.Evidence.ValueParts) != len(want) {
		t.Fatal("unexpected evidence parts")
	}
	for index, expected := range want {
		if source := vulnerability.Evidence.ValueParts[index].SourceIndex; source == nil || *source != expected {
			t.Fatalf("part %d source = %v, want %d", index, source, expected)
		}
	}
}

func configureTaintedCommitTest(t *testing.T) {
	t.Helper()
	previousCapacity := config.VulnerabilitiesPerRequest
	previousDedup := config.DeduplicationEnabled
	previousSampling := config.RequestSamplingPct
	config.VulnerabilitiesPerRequest = MaxEventVulnerabilities
	config.RequestSamplingPct = 100
	config.DeduplicationEnabled = true
	processEventSourceBytes.Store(0)
	t.Cleanup(func() {
		config.VulnerabilitiesPerRequest = previousCapacity
		config.DeduplicationEnabled = previousDedup
		config.RequestSamplingPct = previousSampling
		processEventSourceBytes.Store(0)
	})
}

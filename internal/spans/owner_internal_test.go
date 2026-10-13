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
	"github.com/DataDog/dd-iast-go/internal/model"
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

func TestAnnotationOwnerIsFirstBoundScope(t *testing.T) {
	configureOwnerSpanTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	span := tracer.StartSpan("owner-span")
	var unbound *Annotation
	if _, _, _, ok := unbound.Owner(); ok {
		t.Fatal("nil annotation has an owner")
	}
	if _, _, _, ok := AnnotationFor(span).Owner(); ok {
		t.Fatal("annotation without a scope has an owner")
	}
	Finished(span)
	span.Finish()

	span = tracer.StartSpan("request-span")
	_, first, _ := request.Begin(context.Background())
	t.Cleanup(first.Finish)
	_, second, _ := request.Begin(context.Background())
	t.Cleanup(second.Finish)
	annotation := BindScope(span, first)
	if BindScope(span, second) != annotation {
		t.Fatal("second scope changed the root annotation")
	}
	analysis, _ := first.Analysis()
	wantIndex, wantID, wantGeneration, _ := analysis.Identity()
	index, id, generation, ok := annotation.Owner()
	if !ok || index != wantIndex || id != wantID || generation != wantGeneration {
		t.Fatalf("owner = (%d, %d, %d, %t), want first scope (%d, %d, %d)", index, id, generation, ok, wantIndex, wantID, wantGeneration)
	}
	secondAnalysis, _ := second.Analysis()
	secondIndex, secondID, secondGeneration, _ := secondAnalysis.Identity()
	if _, _, ok := ExistingForOwner(secondIndex, secondID, secondGeneration); ok {
		t.Fatal("second owner was bound to the root span of the first owner")
	}
	if annotation.OwnedBy(secondIndex, secondID, secondGeneration) || !annotation.OwnedBy(wantIndex, wantID, wantGeneration) {
		t.Fatal("OwnedBy does not match the first owner")
	}
	first.Finish()
	if _, gotID, _, ok := annotation.Owner(); !ok || gotID != wantID {
		t.Fatal("finished owner identity changed")
	}
	Finished(span)
	span.Finish()
}

// scopeOwner returns the store owner identity of scope as a commit owner.
func scopeOwner(t *testing.T, scope *request.Scope) CommitOwner {
	t.Helper()
	analysis, ok := scope.Analysis()
	if !ok {
		t.Fatal("analysis unavailable")
	}
	index, id, generation, ok := analysis.Identity()
	if !ok {
		t.Fatal("owner identity unavailable")
	}
	return CommitOwner{ID: id, Generation: generation, Index: index}
}

func beginOwnerScope(t *testing.T) *request.Scope {
	t.Helper()
	_, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("active scope was not created")
	}
	t.Cleanup(scope.Finish)
	return scope
}

func ownedCommit(hash int32, value string, owner CommitOwner) *TaintedCommit {
	commit := taintedCommit(hash, []string{value}, []int{0})
	commit.Owner = owner
	return &commit
}

// +checklocksignore
func eventSourceValues(annotation *Annotation) []string {
	annotation.RLock()
	defer annotation.RUnlock()
	values := make([]string, 0, len(annotation.Event.Sources))
	for _, source := range annotation.Event.Sources {
		values = append(values, source.Value)
	}
	return values
}

func TestTryCommitTaintedClaimsUnownedAnnotation(t *testing.T) {
	configureOwnerSpanTest(t)
	configureTaintedCommitTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	alphaScope, bravoScope := beginOwnerScope(t), beginOwnerScope(t)
	alpha, bravo := scopeOwner(t, alphaScope), scopeOwner(t, bravoScope)
	span := tracer.StartSpan("unowned-span")
	annotation := AnnotationFor(span)
	if !annotation.Sampled || !annotation.OwnedBy(alpha.Index, alpha.ID, alpha.Generation) {
		t.Fatal("unowned annotation must accept a first owner")
	}

	if !annotation.TryCommitTainted(ownedCommit(1, "alpha-value", alpha), nil) {
		t.Fatal("first owner commit failed")
	}
	if !annotation.HasOwner(alpha.Index, alpha.ID, alpha.Generation) {
		t.Fatal("commit did not claim the annotation")
	}
	if _, _, _, ok := annotation.Owner(); ok {
		t.Fatal("a claimed annotation must not be a bound request annotation")
	}
	// A report of a different owner cannot go to the claimed annotation.
	if annotation.TryCommitTainted(ownedCommit(2, "bravo-value", bravo), nil) {
		t.Fatal("commit of a different owner was accepted")
	}
	if annotation.OwnedBy(bravo.Index, bravo.ID, bravo.Generation) {
		t.Fatal("claimed annotation accepts a different owner")
	}
	// A different owner cannot be bound to the claimed annotation.
	if BindScope(span, bravoScope) != annotation {
		t.Fatal("bind changed the root annotation")
	}
	if _, _, ok := ExistingForOwner(bravo.Index, bravo.ID, bravo.Generation); ok {
		t.Fatal("a different owner was bound to the claimed annotation")
	}
	// The claiming owner can be bound: the claim becomes the bound owner.
	BindScope(span, alphaScope)
	if index, id, generation, ok := annotation.Owner(); !ok || index != alpha.Index || id != alpha.ID || generation != alpha.Generation {
		t.Fatal("the claiming owner was not bound")
	}
	if !annotation.TryCommitTainted(ownedCommit(3, "alpha-other", alpha), nil) {
		t.Fatal("second commit of the owner failed")
	}
	if got := eventSourceValues(annotation); len(got) != 2 || got[0] != "alpha-value" || got[1] != "alpha-other" {
		t.Fatalf("event sources = %q, want only alpha sources", got)
	}
	Finished(span)
	span.Finish()
}

func TestTryCommitTaintedRejectsDifferentBoundOwner(t *testing.T) {
	configureOwnerSpanTest(t)
	configureTaintedCommitTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	alphaScope, bravoScope := beginOwnerScope(t), beginOwnerScope(t)
	alpha := scopeOwner(t, alphaScope)
	span := tracer.StartSpan("bravo-root")
	annotation := BindScope(span, bravoScope)
	before := processEventSourceBytes.Load()
	if annotation.TryCommitTainted(ownedCommit(1, "alpha-value", alpha), nil) {
		t.Fatal("commit of a different owner was accepted by a bound annotation")
	}
	if got := eventSourceValues(annotation); len(got) != 0 {
		t.Fatalf("event sources = %q, want none", got)
	}
	if processEventSourceBytes.Load() != before {
		t.Fatal("rejected commit kept its source byte reservation")
	}
	// A commit with no owner keeps the previous behavior.
	if !annotation.TryCommitTainted(ownedCommit(2, "no-owner", CommitOwner{}), nil) {
		t.Fatal("commit without owner failed")
	}
	Finished(span)
	span.Finish()
}

func TestTryCommitTaintedRacesWithBind(t *testing.T) {
	configureOwnerSpanTest(t)
	configureTaintedCommitTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	alphaScope, bravoScope := beginOwnerScope(t), beginOwnerScope(t)
	alpha, bravo := scopeOwner(t, alphaScope), scopeOwner(t, bravoScope)
	for iteration := range 500 {
		span := tracer.StartSpan("race-span")
		annotation := AnnotationFor(span)
		var committed bool
		var wait sync.WaitGroup
		start := make(chan struct{})
		wait.Go(func() {
			<-start
			BindScope(span, bravoScope)
		})
		wait.Go(func() {
			<-start
			committed = annotation.TryCommitTainted(ownedCommit(int32(iteration+1), "alpha-value", alpha), nil)
		})
		close(start)
		wait.Wait()
		sources := eventSourceValues(annotation)
		boundSpan, boundAnnotation, bravoBound := ExistingForOwner(bravo.Index, bravo.ID, bravo.Generation)
		bravoBound = bravoBound && boundSpan == span && boundAnnotation == annotation
		switch {
		case committed && bravoBound:
			t.Fatal("the event has a report of alpha and the request of bravo")
		case committed && (len(sources) != 1 || !annotation.HasOwner(alpha.Index, alpha.ID, alpha.Generation)):
			t.Fatalf("committed event sources = %q", sources)
		case !committed && (len(sources) != 0 || !annotation.HasOwner(bravo.Index, bravo.ID, bravo.Generation)):
			t.Fatalf("rejected commit: sources = %q", sources)
		}
		Finished(span)
		span.Finish()
	}
}

func requireBoundOwner(t *testing.T, annotation *Annotation, owner CommitOwner) {
	t.Helper()
	index, id, generation, ok := annotation.Owner()
	if !ok || index != owner.Index || id != owner.ID || generation != owner.Generation {
		t.Fatalf("bound owner = (%d, %d, %d, %t), want (%d, %d, %d)", index, id, generation, ok, owner.Index, owner.ID, owner.Generation)
	}
}

func TestTryCommitTaintedPanicReleasesClaim(t *testing.T) {
	configureOwnerSpanTest(t)
	configureTaintedCommitTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	alphaScope, bravoScope := beginOwnerScope(t), beginOwnerScope(t)
	alpha, bravo := scopeOwner(t, alphaScope), scopeOwner(t, bravoScope)
	panics := func(*model.Vulnerability) { panic("rollback") }

	// The failed commit of alpha removes its claim: bravo can be bound.
	span := tracer.StartSpan("unowned-span")
	annotation := AnnotationFor(span)
	before := processEventSourceBytes.Load()
	if annotation.TryCommitTainted(ownedCommit(1, "alpha-value", alpha), panics) {
		t.Fatal("panicking commit succeeded")
	}
	if annotation.HasOwner(alpha.Index, alpha.ID, alpha.Generation) || !annotation.OwnedBy(bravo.Index, bravo.ID, bravo.Generation) {
		t.Fatal("the failed commit kept its claim")
	}
	if got := eventSourceValues(annotation); len(got) != 0 || processEventSourceBytes.Load() != before {
		t.Fatalf("failed commit kept state: sources = %q", got)
	}
	if BindScope(span, bravoScope) != annotation {
		t.Fatal("bind changed the root annotation")
	}
	requireBoundOwner(t, annotation, bravo)
	if _, bound, ok := ExistingForOwner(bravo.Index, bravo.ID, bravo.Generation); !ok || bound != annotation {
		t.Fatal("bravo was not bound after the failed commit")
	}
	Finished(span)
	span.Finish()

	// A bind of the same owner during the failed commit stays.
	span = tracer.StartSpan("bound-during-commit")
	annotation = AnnotationFor(span)
	if annotation.TryCommitTainted(ownedCommit(2, "alpha-value", alpha), func(*model.Vulnerability) {
		BindScope(span, alphaScope)
		panic("rollback")
	}) {
		t.Fatal("panicking commit succeeded")
	}
	requireBoundOwner(t, annotation, alpha)
	Finished(span)
	span.Finish()

	// The claim of an earlier commit of the same owner stays.
	span = tracer.StartSpan("claimed-before")
	annotation = AnnotationFor(span)
	if !annotation.TryCommitTainted(ownedCommit(3, "alpha-value", alpha), nil) {
		t.Fatal("first commit failed")
	}
	if annotation.TryCommitTainted(ownedCommit(4, "alpha-other", alpha), panics) {
		t.Fatal("panicking commit succeeded")
	}
	if !annotation.HasOwner(alpha.Index, alpha.ID, alpha.Generation) {
		t.Fatal("the failed commit removed the claim of an earlier commit")
	}
	if got := eventSourceValues(annotation); len(got) != 1 || got[0] != "alpha-value" {
		t.Fatalf("event sources = %q, want the first commit only", got)
	}
	Finished(span)
	span.Finish()
}

func TestAnnotationReportOwner(t *testing.T) {
	var none *Annotation
	if _, _, _, ok := none.ReportOwner(); ok {
		t.Fatal("a nil annotation has an owner")
	}
	annotation := new(Annotation)
	if _, _, _, ok := annotation.ReportOwner(); ok {
		t.Fatal("a new annotation has an owner")
	}
	claimed, ok := annotation.claimOwner(3, 11, 7)
	if !ok {
		t.Fatal("claim failed")
	}
	index, id, generation, ok := annotation.ReportOwner()
	if !ok || index != 3 || id != 11 || generation != 7 {
		t.Fatalf("claimed owner = %d %d %d %t", index, id, generation, ok)
	}
	if _, _, _, bound := annotation.Owner(); bound {
		t.Fatal("a claimed owner is not a bound owner")
	}
	annotation.releaseClaim(claimed)
	if _, _, _, ok := annotation.ReportOwner(); ok {
		t.Fatal("a released claim is still the owner")
	}
	if !annotation.bindOwner(4, 12, 8) {
		t.Fatal("bind failed")
	}
	index, id, generation, ok = annotation.ReportOwner()
	if !ok || index != 4 || id != 12 || generation != 8 {
		t.Fatalf("bound owner = %d %d %d %t", index, id, generation, ok)
	}
}

package request_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

func TestReviewServerScopeReacquiredWhenContextContainsFinishedScope(t *testing.T) {
	// Given a previous request context retained as the parent context of a
	// subsequent server request, with capacity and sampling enabled.
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 1
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	parent, created := request.BeginServerContext(context.Background())
	if !created {
		t.Fatal("first request did not create its scope")
	}
	request.FinishContext(parent, created)
	fresh, freshCreated := request.BeginServerContext(context.Background())
	if !freshCreated || !request.FromContext(fresh).Active() {
		t.Fatal("control request with a fresh context could not acquire the released permit")
	}
	request.FinishContext(fresh, freshCreated)

	// When a new request begins using that retained context as its parent.
	next, nextCreated := request.BeginServerContext(parent)
	defer request.FinishContext(next, nextCreated)

	// Then the new request must receive its own live analysis, not reuse the
	// finished first request's scope (which would silently drop all sources).
	if !nextCreated || !request.FromContext(next).Active() {
		t.Fatalf("new request: created=%t active=%t; expected a fresh live scope", nextCreated, request.FromContext(next).Active())
	}
}

package request_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

func TestReviewEagerHTTPReacquiresSourceForFinishedContext(t *testing.T) {
	// Given the documented defaults for enabled IAST, sampling, and admission.
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 30, 2
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	parent, parentCreated := request.BeginContext(context.Background())
	if !parentCreated {
		t.Fatal("first request did not create its scope")
	}
	previousDecision := request.FromContext(parent).Decision()
	request.FinishContext(parent, parentCreated)

	// When a fresh application-handler entry follows that completed request.
	config.RequestSamplingPct = 100
	control, controlCreated := request.BeginContext(context.Background())
	if !controlCreated || !request.FromContext(control).Active() {
		t.Fatal("fresh-context control could not acquire the released permit")
	}
	controlURI := "/fresh-control"
	request.EagerHTTP(control, &controlURI, nil, nil, nil, nil, nil)
	if !taint.IsTaintedString(controlURI) {
		t.Fatal("fresh-context control did not taint its request URI")
	}
	request.FinishContext(control, controlCreated)

	// Then a later application-handler entry on the retained parent taints anew.
	config.RequestSamplingPct = 30
	next, nextCreated := request.BeginContext(parent)
	defer request.FinishContext(next, nextCreated)
	nextURI := "/next-request"
	request.EagerHTTP(next, &nextURI, nil, nil, nil, nil, nil)

	if !taint.IsTaintedString(nextURI) {
		scope := request.FromContext(next)
		t.Fatalf(
			"later request source missing: created=%t active=%t uri_tainted=%t sampling=%d max_concurrent=%d previous_decision=%d",
			nextCreated, scope.Active(), taint.IsTaintedString(nextURI),
			config.RequestSamplingPct, config.MaxConcurrentRequests, previousDecision,
		)
	}
}

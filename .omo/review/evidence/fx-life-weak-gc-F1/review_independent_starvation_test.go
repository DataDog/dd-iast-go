package spans

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// The two live, rejected HTTP scopes have no analysis owners, yet consume both
// annotation slots; the third request acquires an analysis owner successfully.
func TestIndependentActiveRequestKeepsItsReportingSlot(t *testing.T) {
	if !config.Enabled || config.RequestSamplingPct != 30 || config.MaxConcurrentRequests != 2 {
		t.Fatalf("expected shipped defaults: enabled=%t sampling=%d capacity=%d",
			config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests)
	}
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	oldRate := config.RequestSamplingPct
	t.Cleanup(func() { config.RequestSamplingPct = oldRate })
	config.RequestSamplingPct = 0

	var negativeSpans []*tracer.Span
	for range 2 {
		ctx, created := request.BeginServerContext(context.Background())
		if !created {
			t.Fatal("no HTTP scope")
		}
		scope := request.FromContext(ctx)
		t.Cleanup(scope.Finish)
		span := tracer.StartSpan("sampled-out-http")
		t.Cleanup(func() { Finished(span); span.Finish() })
		negativeSpans = append(negativeSpans, span)
		if scope.Decision() != request.DecisionSampledOut || BindScope(span, scope) != nil {
			t.Fatal("expected a sampled-out request with no annotation")
		}
	}
	config.RequestSamplingPct = 100
	activeCtx, created := request.BeginServerContext(context.Background())
	active := request.FromContext(activeCtx)
	if !created || !active.Active() {
		t.Fatal("active HTTP request failed admission despite two free permits")
	}
	t.Cleanup(active.Finish)
	analysis, _ := active.Analysis()
	index, id, generation, _ := analysis.Identity()
	root := tracer.StartSpan("active-http")
	t.Cleanup(func() { Finished(root); root.Finish() })

	ann := BindScope(root, active)
	_, _, ownerBound := ExistingForOwner(index, id, generation)
	_, _, spanBound := ExistingForSpan(root)
	orphan, orphanAnn := NewOrphanTaintedSpan()
	if orphan != nil {
		t.Cleanup(func() { Finished(orphan); orphan.Finish() })
	}
	t.Logf("default capacity=2 negative roots=%d active=%t annotation=%t ownerBound=%t spanBound=%t orphanAnnotation=%t",
		len(negativeSpans), active.Active(), ann != nil, ownerBound, spanBound, orphanAnn != nil)
	if (ann == nil || !ownerBound || !spanBound) && orphanAnn == nil {
		t.Errorf("admitted active analysis has neither a bound reporting annotation nor orphan reporting capacity")
	}
}

// Review reproducer for F2. Do not commit.

package spans

import (
	"context"
	"testing"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestReviewFXLateChildDoesNotOccupyFinishedRootSlots(t *testing.T) {
	resetReviewFX(t, 2)

	var lateChildren []*tracer.Span
	for range 2 {
		ctx, scope, created := request.Begin(context.Background())
		if !created || !scope.Active() {
			t.Fatal("expected an active request scope")
		}

		root, requestCtx := tracer.StartSpanFromContext(ctx, "request")
		if BindScopeFromContext(requestCtx) == nil {
			t.Fatal("initial root bind failed")
		}
		Finished(root)
		root.Finish()
		scope.Finish()

		child, childCtx := tracer.StartSpanFromContext(requestCtx, "late-child")
		if child.Root() != root {
			t.Fatal("late child did not retain the finished request root")
		}
		if annotation := BindScopeFromContext(childCtx); annotation != nil {
			t.Fatal("finished scope unexpectedly created a sampled annotation")
		}
		lateChildren = append(lateChildren, child)
	}

	if store.Size() != 0 {
		t.Errorf("BUG: late child spans recreated %d annotation slot(s) for finished roots", store.Size())
	}

	_, activeScope, created := request.Begin(context.Background())
	if !created || !activeScope.Active() {
		t.Fatal("expected a later active scope")
	}
	activeRoot := tracer.StartSpan("next-request")
	if annotation := BindScope(activeRoot, activeScope); annotation != nil {
		Finished(activeRoot)
		activeRoot.Finish()
	} else {
		t.Error("BUG: stale late-child annotations denied a later active request")
	}

	for _, child := range lateChildren {
		Finished(child)
		child.Finish()
	}
	if store.Size() != 0 {
		t.Errorf("BUG: finishing late children left %d finished-root annotation slot(s)", store.Size())
	}

	Finished(activeRoot)
	activeRoot.Finish()
	activeScope.Finish()
}

func TestReviewFXLateBindCannotCommitToFinishedRoot(t *testing.T) {
	resetReviewFX(t, 64)

	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("expected an active request scope")
	}
	root, requestCtx := tracer.StartSpanFromContext(ctx, "request")
	if BindScopeFromContext(requestCtx) == nil {
		t.Fatal("initial root bind failed")
	}
	Finished(root)
	root.Finish()

	child, childCtx := tracer.StartSpanFromContext(requestCtx, "late-child")
	annotation := BindScopeFromContext(childCtx)
	if annotation == nil || annotation.Closed() {
		Finished(child)
		child.Finish()
		scope.Finish()
		return
	}
	if child.Root() != root {
		t.Fatal("late child did not retain finished request root")
	}

	commit := TaintedCommit{
		Vulnerability: model.NewVulnerability(
			constants.VulnerabilityTypeWeakHash,
			nil,
			nil,
		),
	}
	if !annotation.TryCommitTainted(&commit, nil) {
		t.Fatal("late annotation rejected a valid vulnerability commit")
	}
	if len(annotation.Event.Vulnerabilities) != 1 {
		t.Fatalf("late annotation vulnerability count=%d, want 1", len(annotation.Event.Vulnerabilities))
	}

	Finished(child)
	child.Finish()
	stored, ok := store.Load(weak.Make(root))
	if !ok || stored != annotation || annotation.Closed() {
		scope.Finish()
		return
	}
	t.Error("BUG: a late child committed a vulnerability into an open annotation whose root had already finished")
	scope.Finish()
}

func resetReviewFX(t *testing.T, maxConcurrent int) {
	t.Helper()
	enabled := config.Enabled
	sampling := config.RequestSamplingPct
	capacity := config.MaxConcurrentRequests
	vulnerabilities := config.VulnerabilitiesPerRequest
	mock := mocktracer.Start()
	store.Clear()
	if store.Size() != 0 {
		t.Fatalf("test reset left %d annotation entries", store.Size())
	}
	for index := range ownerSpans {
		ownerSpans[index].Store(nil)
	}
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = maxConcurrent
	config.VulnerabilitiesPerRequest = MaxEventVulnerabilities
	t.Cleanup(func() {
		mock.Stop()
		store.Clear()
		for index := range ownerSpans {
			ownerSpans[index].Store(nil)
		}
		config.Enabled = enabled
		config.RequestSamplingPct = sampling
		config.MaxConcurrentRequests = capacity
		config.VulnerabilitiesPerRequest = vulnerabilities
	})
}

// Independent woven-build reproducer for phase-2 finding crash-unsafe-F1,
// written by the phase-3 verifier (node fx-crash-unsafe-F1). This package
// deliberately lives outside internal/ so the customer-facing weaving applies
// to its tracer.StartSpanFromContext call sites.
package fxf1repro

import (
	"context"
	"crypto"
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/crypto/hash"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

func init() {
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 2
}

// TestWovenLateChildRecreatesAnnotationUnderFinishedRoot simulates ordinary
// customer code: a request handler starts a background goroutine that keeps the
// request context; the request (and its root span) finishes first; the
// goroutine later calls tracer.StartSpanFromContext. That call site is woven
// into iast/net/http.BindStartSpan, which reaches spans.BindScope with a live
// child span whose root is already finished, recreating an annotation under
// the finished root key. A later live request whose spans attach to the dead
// trace (woven GLS parent inference, as in a long-lived worker goroutine) then
// has its admission decision hijacked by the stale retained annotation.
func TestWovenLateChildRecreatesAnnotationUnderFinishedRoot(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion weaving, use `go tool orchestrion go test`")
	}

	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	// Request 1: scope (what the woven net/http server hook creates), request
	// root span, binding (what the woven handler advice does), background child.
	reqCtx, created := request.BeginServerContext(context.Background())
	root, rootCtx := tracer.StartSpanFromContext(reqCtx, "http.request")
	ann1 := spans.BindScopeFromContext(rootCtx)
	if ann1 == nil || !ann1.Sampled {
		t.Fatal("request 1 root did not receive a sampled annotation")
	}
	child, childCtx := tracer.StartSpanFromContext(rootCtx, "background.work")

	// Request ends: scope finish (woven net/http defer), then root span finish;
	// the woven tracer.Span.Finish hook runs spans.Finished(root) first.
	request.FinishContext(reqCtx, created)
	root.Finish()
	if _, _, found := spans.ExistingForSpan(root); found {
		t.Fatal("annotation survived request 1 root finish")
	}

	// Late goroutine work: StartSpanFromContext on the live child context.
	// Woven: iast/net/http.BindStartSpan -> spans.BindScopeFromContext.
	late, _ := tracer.StartSpanFromContext(childCtx, "late.work")

	finishedRoot, ann, found := spans.ExistingForSpan(late)
	if !found {
		t.Fatal("woven surface did not recreate an annotation under the finished root")
	}
	if finishedRoot != root {
		t.Fatalf("recreated annotation keyed to %p, want the finished root %p", finishedRoot, root)
	}
	if ann.Closed() {
		t.Fatal("recreated annotation under finished root is already closed")
	}
	if ann.Sampled {
		t.Fatal("recreated annotation is sampled although the request scope finished")
	}
	t.Logf("woven surface recreated an open non-sampled annotation under finished root %p", finishedRoot)

	// Request 2: a fresh, active, 100%-sampled request. In the woven tracer,
	// StartSpanFromContext falls back to the goroutine-local active span when
	// the context chain carries no span, so the still-running background
	// goroutine's late child attaches the new request's root span to the dead
	// trace. Its BindScope then finds the stale non-sampled annotation under
	// its root key and denies the request IAST analysis.
	req2Ctx, created2 := request.BeginServerContext(context.Background())
	root2, root2Ctx := tracer.StartSpanFromContext(req2Ctx, "http.request")
	ann2 := spans.BindScopeFromContext(root2Ctx)
	scope2 := request.FromContext(root2Ctx)
	if scope2 == nil || !scope2.Active() {
		t.Fatal("request 2 scope is not active")
	}
	if root2.Root() != root {
		t.Fatalf("request 2 root %p did not attach to the finished trace root %p", root2.Root(), root)
	}
	if ann2 != nil {
		t.Fatal("request 2 was bound to an annotation although its root key holds a stale marker")
	}
	if _, annStale, staleFound := spans.ExistingForSpan(root2); !staleFound || annStale != ann {
		t.Fatal("stale finished-root annotation missing under request 2 root key")
	}
	t.Logf("live 100%%-sampled request 2 (root=%p) denied IAST analysis by the stale annotation under finished root %p",
		root2, root2.Root())
	request.FinishContext(req2Ctx, created2)
	root2.Finish()

	// Finishing the late child runs spans.Finished(late), which uses the child
	// key, so the stale annotation under the finished root key survives.
	late.Finish()
	_, annAfter, foundAfter := spans.ExistingForSpan(late)
	if !foundAfter || annAfter.Closed() || annAfter != ann {
		t.Fatal("late child finish removed or closed the stale finished-root annotation")
	}
	t.Log("stale annotation survives late child finish: no hook keyed to the finished root remains")

	for _, s := range mock.FinishedSpans() {
		if s.OperationName() == "http.request" {
			t.Logf("finished %q spanID=%d: _dd.iast.enabled=%v", s.OperationName(),
				s.Context().SpanID(), s.Tag(spans.SpanTagEnabled))
		}
	}

	runtime.KeepAlive(root)
	runtime.KeepAlive(root2)
	runtime.KeepAlive(child)
	runtime.KeepAlive(late)
}

// TestWovenWeakHashFindingStrandedUnderFinishedRoot uses the exported public
// sink API (iast/crypto/hash.ReportWeakHash) with a span context whose live
// child belongs to an already-finished root: the reported finding lands in a
// newly created open sampled annotation under the finished root and is never
// emitted by any finish hook.
func TestWovenWeakHashFindingStrandedUnderFinishedRoot(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion weaving, use `go tool orchestrion go test`")
	}

	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	root := tracer.StartSpan("job.root")
	child, _ := tracer.StartSpanFromContext(
		tracer.ContextWithSpan(context.Background(), root), "work")

	// The woven tracer.Span.Finish hook runs spans.Finished(root) first.
	root.Finish()

	// Customer-style context: child span, no request scope.
	spanCtx := tracer.ContextWithSpan(context.Background(), child)
	before := len(mock.FinishedSpans())
	hash.ReportWeakHash(spanCtx, crypto.MD5)

	finished := mock.FinishedSpans()
	if len(finished) != before {
		t.Fatalf("finished spans went %d -> %d; an orphan span emitted the finding",
			before, len(finished))
	}
	for _, s := range finished {
		if s.Tag(spans.SpanTagJson) != nil || s.Tag(spans.SpanTagMetaStruct) != nil {
			t.Fatalf("span %q carries an IAST payload", s.OperationName())
		}
	}

	_, ann, found := spans.ExistingForSpan(child)
	if !found {
		t.Fatal("no replacement annotation was created under the finished root")
	}
	if !ann.Sampled {
		t.Fatal("replacement annotation was not sampled")
	}
	if len(ann.Event.Vulnerabilities) != 1 {
		t.Fatalf("stranded vulnerabilities = %d, want 1", len(ann.Event.Vulnerabilities))
	}

	// Finishing the child runs spans.Finished(child), which uses the child key.
	child.Finish()
	_, ann2, found2 := spans.ExistingForSpan(child)
	if !found2 || ann2.Closed() {
		t.Fatal("child finish removed or closed the stranded annotation")
	}
	if len(ann2.Event.Vulnerabilities) != 1 {
		t.Fatalf("stranded vulnerabilities after child finish = %d, want 1", len(ann2.Event.Vulnerabilities))
	}
	t.Log("weak-hash finding stranded in an open annotation under a finished root; never emitted")

	runtime.KeepAlive(root)
	runtime.KeepAlive(child)
}

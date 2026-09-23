// Reproducer for fx-life-owner-scope-F1, written independently of the phase-2
// finder. It drives the exact callbacks the woven net/http server advice
// invokes (httpbridge.Begin/Finish and EagerHTTP) rather than the internal
// BeginServerContext API directly.

package request

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
)

func fxBegin(ctx context.Context) (context.Context, bool) {
	// Mirrors iast/net/http/orchestrion.yml serverHandler.ServeHTTP advice.
	return httpbridge.Begin(ctx, "GET", "/search?q=secret", map[string][]string{"X-Api-Key": {"secret"}})
}

func fxEager(ctx context.Context, uri, path, query string, headers map[string][]string) map[string][]string {
	return EagerHTTP(ctx, &uri, &path, &query, headers, nil, nil)
}

func TestFXWovenEntryReusesFinishedScopeFromRetainedContext(t *testing.T) {
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 1
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})

	ctx1, created1 := fxBegin(context.Background())
	if !created1 {
		t.Fatal("request 1: created=false; expected the server entry to create a scope")
	}
	scope1 := FromContext(ctx1)
	if !scope1.Active() {
		t.Fatal("request 1: scope inactive; expected a live analysis")
	}
	if _, ok := scope1.Analysis(); !ok {
		t.Fatal("request 1: no analysis handle")
	}
	httpbridge.Finish(ctx1, created1)
	if scope1.Active() {
		t.Fatal("request 1: scope still active after Finish")
	}

	ctrlCtx, ctrlCreated := fxBegin(context.Background())
	if !ctrlCreated || !FromContext(ctrlCtx).Active() {
		t.Fatalf("control fresh context: created=%t active=%t; capacity was free", ctrlCreated, FromContext(ctrlCtx).Active())
	}
	httpbridge.Finish(ctrlCtx, ctrlCreated)

	for i := 0; i < 3; i++ {
		ctx2, created2 := fxBegin(ctx1)
		scope2 := FromContext(ctx2)
		if created2 {
			t.Fatalf("reused-context request %d: created=true (unexpected; bug not reproduced)", i)
		}
		if scope2 == nil || scope2.Active() {
			t.Fatalf("reused-context request %d: active=%v; expected the finished scope to be detected and replaced", i, scope2 != nil && scope2.Active())
		}
		if got := scope2.EnabledTagValue(); got != 0 {
			t.Fatalf("reused-context request %d: _dd.iast.enabled=%d; expected 0", i, got)
		}
		if _, ok := scope2.Analysis(); ok {
			t.Fatalf("reused-context request %d: EagerHTTP would publish sources; analysis handle is live", i)
		}
		if fxEager(ctx2, "/search?q=secret", "/search", "q=secret", map[string][]string{"X-Api-Key": {"secret"}}) == nil {
			t.Fatalf("reused-context request %d: EagerHTTP returned nil", i)
		}
		httpbridge.Finish(ctx2, created2)
	}
}

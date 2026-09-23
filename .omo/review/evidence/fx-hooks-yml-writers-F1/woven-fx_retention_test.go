package propagation_test

import (
	"context"
	"runtime"
	"testing"

	testapp "github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// TestFxBufferInteriorViewRetainsCallerAllocation independently verifies
// hooks-yml-writers-F1 at the woven call-site surface: a bytes.Buffer over a
// small view of a 16 MiB caller allocation lets the writer anchor retain the
// whole allocation while the store charges only the visible capacity, and the
// retention is released by owner finish (proving the writer anchor is the
// retainer).
func TestFxBufferInteriorViewRetainsCallerAllocation(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
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
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	input := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"}, "attack")

	// Sanity: the woven write must track provenance, otherwise the
	// measurement below would be vacuous.
	require.True(t, taint.IsTaintedString(testapp.FxInteriorScratchBuffer(input)),
		"woven buffer write lost provenance; writer state was not created")

	runtime.GC()
	var before, mid, after runtime.MemStats
	runtime.ReadMemStats(&before)

	for index := 0; index < 8; index++ {
		testapp.FxInteriorScratchBuffer(input)
	}

	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&mid)
	retained := int64(mid.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("retained while owner active: %d MiB (caller scratch allocations, all customer references dropped)", retained>>20)
	require.Greaterf(t, retained, int64(24<<20),
		"documented 24 MiB whole-feature envelope not exceeded; anchor retention not reproduced")

	scope.Finish()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	released := int64(mid.HeapAlloc) - int64(after.HeapAlloc)
	t.Logf("released by owner finish: %d MiB", released>>20)
	require.Greaterf(t, released, int64(100<<20),
		"retained memory was not released by owner finish; the retainer is not the writer anchor")
}

// Review-only woven reproducer for fx-perf-hotpath-F2.
package overhead_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/DataDog/dd-iast-go/benchmarks/overhead"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

var f2Parts = []string{"id", "name", "email", "created_at", "updated_at", "status", "owner", "tags"}

func BenchmarkF2WovenWriters(b *testing.B) {
	fmt.Printf("F2: woven=%v instrumentedPropagation=%d\n", built.WithOrchestrion, telemetry.InstrumentedPropagation)
	prevE, prevS, prevM := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 2
	defer func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = prevE, prevS, prevM }()
	run := func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			a, c := overhead.RenderClean(f2Parts)
			resultString = a + c
		}
	}
	b.Run("no-owner", run)
	_, scope, created := request.Begin(context.Background())
	if !created {
		b.Fatal("no owner")
	}
	// The owner belongs to some other sampled request; this goroutine's work is
	// unrelated and entirely clean, yet shares the process-wide gate.
	b.Run("active-clean-owner", run)
	b.Run("active-clean-owner-parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				a, c := overhead.RenderClean(f2Parts)
				resultString = a + c
			}
		})
	})
	scope.Finish()
}

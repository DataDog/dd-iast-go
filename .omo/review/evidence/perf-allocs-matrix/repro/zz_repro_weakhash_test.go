// Review reproducer (perf-allocs-matrix). Not part of the repository.

package overhead_test

import (
	"context"
	"crypto/md5"
	"testing"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

// BenchmarkReproWeakHashQuotaExhausted calls md5.Sum in a hot loop inside ONE
// request span. The per-request vulnerability quota (default 2) is exhausted
// after the first two calls, so every later call performs stack capture, UUID
// generation and model allocation whose result is then discarded.
func BenchmarkReproWeakHashQuotaExhausted(b *testing.B) {
	mt := mocktracer.Start()
	b.Cleanup(mt.Stop)
	payload := []byte("representative request payload")
	b.ReportAllocs()
	b.ResetTimer()
	hashLoopInOneSpan(context.Background(), payload, b)
}

//dd:span span.name:benchmark.request
func hashLoopInOneSpan(ctx context.Context, payload []byte, b *testing.B) {
	_ = ctx
	for b.Loop() {
		md5Result = md5.Sum(payload) //nolint:gosec // reproducer
	}
}

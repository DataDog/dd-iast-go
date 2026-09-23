// Review reproducer (perf-allocs-matrix). Not part of the repository.

package overhead_test

import (
	"context"
	"crypto/md5"
	"os"
	"strings"
	"testing"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

// TestReproWeakHashQuotaDiscardsWork shows that 1000 md5.Sum calls inside one
// request span publish at most the configured quota of vulnerabilities, while
// every call still runs the full reporting path.
func TestReproWeakHashQuotaDiscardsWork(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	hashManyTimes(context.Background(), 1000)
	finished := mt.FinishedSpans()
	if len(finished) == 0 {
		t.Fatal("no finished spans")
	}
	for _, span := range finished {
		payload, _ := span.Tag("_dd.iast.json").(string)
		t.Logf("span %q iast.enabled=%v payload_len=%d WEAK_HASH_count=%d payload=%s",
			span.OperationName(), span.Tag("_dd.iast.enabled"), len(payload),
			strings.Count(payload, "WEAK_HASH"), payload)
	}
}

//dd:span span.name:repro.request
func hashManyTimes(ctx context.Context, n int) {
	_ = ctx
	payload := []byte("representative request payload")
	for range n {
		md5Result = md5.Sum(payload) //nolint:gosec // reproducer
	}
}

// TestReproOrphanSpanWhenSampledOut counts spans emitted by md5.Sum calls made
// outside any span while IAST request sampling is 0.
func TestReproOrphanSpanWhenSampledOut(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion")
	}
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	payload := []byte("representative request payload")
	for range 100 {
		md5Result = md5.Sum(payload) //nolint:gosec // reproducer
	}
	finished := mt.FinishedSpans()
	withPayload := 0
	for _, span := range finished {
		if s, _ := span.Tag("_dd.iast.json").(string); s != "" {
			withPayload++
		}
	}
	t.Logf("DD_IAST_REQUEST_SAMPLING=%s: 100 md5.Sum calls emitted %d spans, %d carrying an IAST payload",
		os.Getenv("DD_IAST_REQUEST_SAMPLING"), len(finished), withPayload)
}

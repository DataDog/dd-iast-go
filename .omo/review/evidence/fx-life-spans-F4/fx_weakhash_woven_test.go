// Review reproducer (fx-life-spans-F4): woven-build verification through the
// real md5.Sum sink hook. Not part of the repository.

package overhead_test

import (
	"crypto/md5"
	"strings"
	"testing"

	mocktracer "github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

var fxHashSink [md5.Size]byte

func fxCountSpans(mt mocktracer.Tracer) (orphans, withPayload, weakHashFindings int) {
	for _, s := range mt.FinishedSpans() {
		if s.OperationName() == "vulnerability" {
			orphans++
		}
		if p, _ := s.Tag("_dd.iast.json").(string); p != "" {
			withPayload++
			weakHashFindings += strings.Count(p, "WEAK_HASH")
		}
	}
	return orphans, withPayload, weakHashFindings
}

// TestFxWeakHashWovenOutsideSpan: md5.Sum calls made outside any traced span
// (the nil-ctx hook surface) with sampling 100%.
func TestFxWeakHashWovenOutsideSpan(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion weaving")
	}
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	payload := []byte("representative request payload")
	const calls = 200
	for range calls {
		fxHashSink = md5.Sum(payload)
	}
	orphans, withPayload, findings := fxCountSpans(mt)
	t.Logf("sampling=100 outside-span: %d md5.Sum calls -> %d finished vulnerability spans, %d with IAST payload, %d WEAK_HASH findings total",
		calls, orphans, withPayload, findings)
	if orphans != calls {
		t.Errorf("got %d spans for %d md5.Sum calls (want %d)", orphans, calls, calls)
	}
	if findings != calls {
		t.Errorf("got %d identical WEAK_HASH findings for %d calls (want %d): no process-level dedup", findings, calls, calls)
	}
}

// TestFxWeakHashWovenInsideSpan: 1000 md5.Sum calls inside one //dd:span
// request span with sampling 100%; shows how many findings survive the
// per-request quota and event-local dedup while every call still pays.
func TestFxWeakHashWovenInsideSpan(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires orchestrion weaving")
	}
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	fxHashLoopInSpan(1000)
	orphans, withPayload, findings := fxCountSpans(mt)
	t.Logf("sampling=100 inside-span: 1000 md5.Sum calls -> %d finished vulnerability spans, %d spans with IAST payload, %d WEAK_HASH findings total",
		orphans, withPayload, findings)
}

//dd:span span.name:fx.request
func fxHashLoopInSpan(n int) {
	payload := []byte("representative request payload")
	for range n {
		fxHashSink = md5.Sum(payload)
	}
}

// BenchmarkFxWeakHashOutsideSpan: per-call cost of md5.Sum woven, outside any
// span, sampling 100% (orphan span per call).
func BenchmarkFxWeakHashOutsideSpan(b *testing.B) {
	mt := mocktracer.Start()
	b.Cleanup(mt.Stop)
	payload := []byte("representative request payload")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		fxHashSink = md5.Sum(payload)
	}
	mt.Reset()
}

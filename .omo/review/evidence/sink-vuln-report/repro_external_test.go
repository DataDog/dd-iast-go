package vulnerability_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-iast-go/internal/vulnerability/reprosink"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// weakHashCallSite mirrors the woven crypto/md5 advice, which always passes a
// nil context: __dd__iast_ReportWeakHash__(nil, crypto.MD5).
func weakHashCallSite(executed *atomic.Uint64) {
	vulnerability.Report(nil, constants.VulnerabilityTypeWeakHash, "MD5", executed, vulnerability.SkipFrame{})
}

func TestReproWeakHashOrphanPerCallNoProcessDedup(t *testing.T) {
	configureReportTest(t, false, true, 2) // stack traces off, DD_IAST_DEDUPLICATION_ENABLED=true
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	for _, pct := range []int{100, 30} {
		config.RequestSamplingPct = pct
		mt.Reset()
		var executed atomic.Uint64
		const calls = 1000
		orphanSpans, reportedVulns := 0, 0
		for range calls {
			weakHashCallSite(&executed) // identical call site / location / hash every time
			for _, finished := range mt.FinishedSpans() {
				span := finished.Unwrap()
				if finished.OperationName() == "vulnerability" {
					orphanSpans++
				}
				if _, ann, ok := spans.ExistingForSpan(span); ok {
					ann.RLock()
					reportedVulns += len(ann.Vulnerabilities)
					ann.RUnlock()
				}
				spans.Finished(span) // emulate the woven Span.Finish hook
			}
			mt.Reset()
		}
		t.Logf("sampling=%d%%: %d identical weak-hash calls -> %d orphan spans started, %d sampled vulnerability events (executed=%d)",
			pct, calls, orphanSpans, reportedVulns, executed.Load())
	}
	config.RequestSamplingPct = 100
	allocs := testing.AllocsPerRun(200, func() {
		weakHashCallSite(nil)
		for _, finished := range mt.FinishedSpans() {
			spans.Finished(finished.Unwrap())
		}
		mt.Reset()
	})
	t.Logf("allocations per instrumented md5 call (sampled): %.0f", allocs)
}

func TestReproDeferredSinkPanicLocation(t *testing.T) {
	configureReportTest(t, false, true, 2)
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	span, _ := tracer.StartSpanFromContext(context.Background(), "request")
	var normal, panicA, panicB vulnerability.CapturedLocation
	reprosink.Query(span, &normal, func() {})
	callSiteA(span, &panicA)
	callSiteB(span, &panicB)
	show := func(name string, c vulnerability.CapturedLocation) int32 {
		v := model.NewVulnerability(constants.VulnerabilityTypeSqlInjection, model.NewEvidenceString("q"), c.Location)
		t.Logf("%-8s path=%s line=%d method=%s hash=%d", name, c.Location.Path, c.Location.Line, c.Location.Method, v.Hash)
		return v.Hash
	}
	show("normal", normal)
	a, b := show("panicA", panicA), show("panicB", panicB)
	if a == b {
		t.Logf("DISTINCT customer call sites share one hash -> process dedup suppresses the second for 1h")
	}
}

func callSiteA(span *tracer.Span, out *vulnerability.CapturedLocation) {
	defer func() { _ = recover() }()
	reprosink.Query(span, out, func() { panic("driver A") })
}

func callSiteB(span *tracer.Span, out *vulnerability.CapturedLocation) {
	defer func() { _ = recover() }()
	reprosink.Query(span, out, func() { panic("driver B") })
}

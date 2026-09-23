// Review reproducer (fx-life-spans-F4). Not part of the repository.
//
// Verifies the phase-2 findings life-spans-F4 / sink-vuln-report-F1 /
// perf-allocs-matrix-F1: vulnerability.Report reached with a nil context (as
// every weak-hash/weak-cipher hook does) starts and finishes one real orphan
// tracer span per call, before any sampling decision, with no process-level
// dedup, paying the full report path per call.
package vulnerability_test

import (
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

// fxWeakHashCallSite mirrors the woven crypto/md5 advice exactly:
// __dd__iast_ReportWeakHash__(nil, crypto.MD5) -> ReportWeakHash -> Report.
func fxWeakHashCallSite(executed *atomic.Uint64) {
	vulnerability.Report(nil, constants.VulnerabilityTypeWeakHash, "MD5", executed, vulnerability.SkipFrame{Namespace: "crypto"})
}

// flushOrphans emulates the woven Span.Finish hook (internal/spans/orchestrion.yml):
// spans.Finished runs in the Finish prologue and attaches the IAST payload.
// Returns the number of orphan "vulnerability" spans and the number of
// vulnerabilities emitted across their events, plus the number of events.
func flushOrphans(t *testing.T, mt mocktracer.Tracer) (orphanSpans, vulns, events int) {
	t.Helper()
	for _, finished := range mt.FinishedSpans() {
		span := finished.Unwrap()
		if finished.OperationName() != "vulnerability" {
			continue
		}
		orphanSpans++
		if _, ann, ok := spans.ExistingForSpan(span); ok {
			ann.RLock()
			n := len(ann.Vulnerabilities)
			ann.RUnlock()
			if n > 0 {
				events++
			}
			vulns += n
		}
		spans.Finished(span) // what the woven Finish prologue does
	}
	mt.Reset()
	return orphanSpans, vulns, events
}

// TestFxWeakHashOrphanPerCallNoProcessDedup: 200 identical weak-hash calls at
// one call site, sampling 100%, produce 200 orphan spans and 200 identical
// vulnerability events (no process dedup; event-local dedup cannot help because
// every orphan carries its own fresh event).
func TestFxWeakHashOrphanPerCallNoProcessDedup(t *testing.T) {
	config.RequestSamplingPct = 100
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)

	const calls = 200
	var executed atomic.Uint64
	totalOrphans, totalVulns, totalEvents := 0, 0, 0
	for range calls {
		fxWeakHashCallSite(&executed)
		o, v, e := flushOrphans(t, mt)
		totalOrphans += o
		totalVulns += v
		totalEvents += e
	}
	t.Logf("sampling=100%%: %d identical weak-hash calls -> %d orphan spans started+finished, %d sampled events, %d WEAK_HASH findings total",
		calls, totalOrphans, totalEvents, totalVulns)
	if totalOrphans != calls {
		t.Errorf("got %d orphan spans for %d calls (want %d): one orphan span per call", totalOrphans, calls, calls)
	}
	if totalVulns != calls {
		t.Errorf("got %d vulnerability findings for %d identical calls (want %d): no process-level dedup", totalVulns, calls, calls)
	}
}

// TestFxWeakHashOrphanSpanBeforeSampling: at sampling 0% every call still
// starts and finishes an orphan span; none carries an IAST payload. Shows the
// span is created before the sampling decision.
func TestFxWeakHashOrphanSpanBeforeSampling(t *testing.T) {
	config.RequestSamplingPct = 0
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)

	const calls = 100
	for range calls {
		fxWeakHashCallSite(nil)
	}
	orphanSpans, withPayload := 0, 0
	for _, finished := range mt.FinishedSpans() {
		if finished.OperationName() != "vulnerability" {
			continue
		}
		orphanSpans++
		if _, ann, ok := spans.ExistingForSpan(finished.Unwrap()); ok && ann.Sampled {
			withPayload++
		}
		spans.Finished(finished.Unwrap())
	}
	t.Logf("sampling=0%%: %d weak-hash calls emitted %d orphan spans, %d carrying an IAST payload", calls, orphanSpans, withPayload)
	if orphanSpans != calls {
		t.Errorf("got %d orphan spans for %d calls at sampling 0 (want %d): span created before sampling decision", orphanSpans, calls, calls)
	}
	if withPayload != 0 {
		t.Errorf("got %d sampled payloads at sampling 0 (want 0)", withPayload)
	}
}

// TestFxWeakHashAllocsPerCall: allocations of one nil-ctx weak-hash report with
// stack traces enabled (the default) versus disabled.
func TestFxWeakHashAllocsPerCall(t *testing.T) {
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	config.RequestSamplingPct = 100

	run := func() {
		fxWeakHashCallSite(nil)
		for _, finished := range mt.FinishedSpans() {
			spans.Finished(finished.Unwrap())
		}
		mt.Reset()
	}
	run() // warm up
	withStack := testing.AllocsPerRun(200, run)

	config.StackTraceEnabled = false
	run()
	withoutStack := testing.AllocsPerRun(200, run)
	config.StackTraceEnabled = true
	t.Logf("allocations per nil-ctx weak-hash report: stack_traces=on %.0f, stack_traces=off %.0f", withStack, withoutStack)
}

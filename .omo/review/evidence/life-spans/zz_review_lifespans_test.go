package vulnerability_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func dumpFinished(t *testing.T, mock mocktracer.Tracer) {
	t.Helper()
	for _, s := range mock.FinishedSpans() {
		_, hasJSON := s.Tag(spans.SpanTagJson).(string)
		t.Logf("finished span name=%q enabled=%v has_iast_json=%t", s.OperationName(), s.Tag(spans.SpanTagEnabled), hasJSON)
	}
}

// F1: with the default DD_IAST_MAX_CONCURRENT_REQUESTS=2, two in-flight
// sampled-out requests fill the span annotation store (negative decisions are
// stored since 87ecf02). A concurrently ACTIVE request (it holds an analysis
// permit and tracks taint) then gets no annotation: its span is tagged
// _dd.iast.enabled=0, its tainted findings are diverted to orphan spans (one
// orphan per sink hit, even when deduplicated), and weak-sink findings are dropped.
func TestReviewNegativeDecisionsCrowdOutActiveRequest(t *testing.T) {
	configureTaintedReportTest(t)
	config.MaxConcurrentRequests = 2 // shipped default
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	config.RequestSamplingPct = 0
	var outSpans []*tracer.Span
	var outScopes []*request.Scope
	for i := range 2 {
		_, scope, created := request.Begin(context.Background())
		if !created || scope.Decision() != request.DecisionSampledOut {
			t.Fatal("sampled-out scope not created")
		}
		span := tracer.StartSpan("sampled-out-request")
		if spans.BindScope(span, scope) != nil {
			t.Fatal("sampled-out scope bound a reporting annotation")
		}
		t.Logf("sampled-out request %d bound (negative decision stored)", i)
		outSpans = append(outSpans, span)
		outScopes = append(outScopes, scope)
	}

	config.RequestSamplingPct = 100
	ctx, scope, query, snapshot := taintedQuerySnapshot(t)
	span := tracer.StartSpan("active-request")
	ann := spans.BindScope(span, scope)
	t.Logf("active request: scope.Active()=%t decision=%v BindScope annotation nil=%t", scope.Active(), scope.Decision(), ann == nil)
	spanCtx := tracer.ContextWithSpan(ctx, span)

	first := vulnerability.ReportTainted(spanCtx, constants.VulnerabilityTypeSqlInjection, snapshot, redaction.AnalyzeSQL(query), 2, sqlSkipPolicy())
	second := vulnerability.ReportTainted(spanCtx, constants.VulnerabilityTypeSqlInjection, snapshot, redaction.AnalyzeSQL(query), 2, sqlSkipPolicy())
	t.Logf("ReportTainted first=%t second(dedup)=%t", first, second)
	weak := spans.AnnotationForContext(spanCtx, span)
	t.Logf("weak-sink annotation for active request sampled=%t", weak.Sampled)
	vulnerability.Report(spanCtx, constants.VulnerabilityTypeWeakHash, "MD5", nil, vulnerability.SkipFrame{})

	spans.Finished(span)
	span.Finish()
	scope.Finish()
	for i := range outSpans {
		spans.Finished(outSpans[i])
		outSpans[i].Finish()
		outScopes[i].Finish()
	}
	dumpFinished(t, mock)

	var activeEnabled any
	activeHasEvent := false
	orphans := 0
	for _, s := range mock.FinishedSpans() {
		switch s.OperationName() {
		case "active-request":
			activeEnabled = s.Tag(spans.SpanTagEnabled)
			_, activeHasEvent = s.Tag(spans.SpanTagJson).(string)
		case "vulnerability":
			orphans++
		}
	}
	if ann == nil || activeEnabled != float64(1) || !activeHasEvent || orphans != 0 {
		t.Errorf("BUG: active request annotation nil=%t enabled tag=%v event on request span=%t orphan spans=%d (want non-nil, 1, true, 0)",
			ann == nil, activeEnabled, activeHasEvent, orphans)
	}
}

// F2: a span start/bind (or weak report) that happens after the request root
// span finished (e.g. a background goroutine still using the request context
// while the scope is live) re-creates a fresh, open annotation for the finished
// root. Later reports commit into it and return true, but nothing ever flushes
// it: the findings are silently lost, while without the late bind the same
// report would at least have produced an orphan event.
func TestReviewLateBindAfterRootFinishLosesFindings(t *testing.T) {
	configureTaintedReportTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	ctx, scope, query, snapshot := taintedQuerySnapshot(t)
	root, rootCtx := tracer.StartSpanFromContext(ctx, "request")
	first := spans.BindScope(root, scope)
	spans.Finished(root) // what the woven Span.Finish prologue does
	root.Finish()
	t.Logf("root finished; original annotation closed=%t", first.Closed())

	// Late child span from the still-live request context. This is what the
	// woven tracer.StartSpanFromContext wrapper (iasthttp.BindStartSpan) does.
	child, childCtx := tracer.StartSpanFromContext(rootCtx, "late-db-call")
	zombie := spans.BindScopeFromContext(childCtx)
	t.Logf("late bind: annotation nil=%t same-as-original=%t closed=%t", zombie == nil, zombie == first, zombie.Closed())

	committed := vulnerability.ReportTainted(childCtx, constants.VulnerabilityTypeSqlInjection, snapshot, redaction.AnalyzeSQL(query), 2, sqlSkipPolicy())
	vulnerability.Report(childCtx, constants.VulnerabilityTypeWeakHash, "MD5", nil, vulnerability.SkipFrame{})
	count := 0
	if zombie != nil {
		zombie.RLock()
		count = len(zombie.Vulnerabilities)
		zombie.RUnlock()
	}
	t.Logf("ReportTainted returned %t; zombie annotation holds %d vulnerabilities", committed, count)

	spans.Finished(child)
	child.Finish()
	scope.Finish()
	_, _, stillStored := spans.ExistingForSpan(root)
	t.Logf("after child+scope finish: zombie still in store for finished root=%t", stillStored)
	dumpFinished(t, mock)

	emitted := 0
	for _, s := range mock.FinishedSpans() {
		if v, ok := s.Tag(spans.SpanTagJson).(string); ok && strings.Contains(v, "vulnerabilities") {
			emitted++
		}
	}
	if committed && emitted == 0 {
		t.Errorf("BUG: ReportTainted reported success and %d findings were committed, but no finished span carries an IAST event", count)
	}
}

// F3: vulnerability.Report is called with a nil context by the weak-crypto
// hooks. Without an active span, every call creates and finishes an orphan
// trace span; sampled calls attach the same (identical-hash) finding again and
// force ManualKeep, because there is no process-level de-duplication.
func TestReviewWeakReportWithoutSpanCreatesOrphanPerCall(t *testing.T) {
	configureReportTest(t, true, true, 2)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	const calls = 100
	for range calls {
		vulnerability.Report(nil, constants.VulnerabilityTypeWeakHash, "MD5", nil, vulnerability.SkipFrame{}) //nolint:staticcheck // mirrors the woven hook's nil ctx
	}
	finished := mock.FinishedSpans()
	withEvent, kept := 0, 0
	hashes := map[string]struct{}{}
	for _, s := range finished {
		if v, ok := s.Tag(spans.SpanTagJson).(string); ok {
			withEvent++
			i := strings.Index(v, `"hash":`)
			if i >= 0 {
				hashes[v[i:min(len(v), i+30)]] = struct{}{}
			}
		}
		if s.Tag("manual.keep") != nil {
			kept++
		}
	}
	t.Logf("%d weak-hash calls at one call site -> %d orphan spans, %d carrying an IAST event, %d manual.keep, %d distinct hashes", calls, len(finished), withEvent, kept, len(hashes))
	allocs := testing.AllocsPerRun(50, func() {
		vulnerability.Report(nil, constants.VulnerabilityTypeWeakHash, "MD5", nil, vulnerability.SkipFrame{}) //nolint:staticcheck
	})
	t.Logf("allocations per weak-hash call with no span in context: %.0f (stack traces enabled)", allocs)
	if withEvent > 1 {
		t.Errorf("BUG: the same finding was emitted %d times (no process-level dedup on the orphan path)", withEvent)
	}
}

// F4 (Critical candidate): a second Finish() of an already-finished root that has
// a (re-created) annotation makes the Finish prologue call SetMetaStruct on a
// finished span. dd-trace-go's setMetaStructLocked has no `finished` guard and the
// trace writer encodes finished spans without the span lock, so this is a data race.
func TestReviewDoubleFinishSetsMetaStructOnFinishedSpan(t *testing.T) {
	configureReportTest(t, false, true, 2)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/info":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/v0.4/traces","/v0.5/traces"],"span_meta_structs":true,"client_drop_p0s":false}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(agent.Close)
	if err := tracer.Start(tracer.WithAgentURL(agent.URL), tracer.WithLogStartup(false), tracer.WithService("review")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tracer.Stop)
	probe := tracer.StartSpan("probe")
	t.Logf("real tracer meta_struct available (SetMetaStruct returned) = %t", probe.SetMetaStruct("probe", &model.Event{}))
	probe.Finish()
	for range 20 {
		root := tracer.StartSpan("request")
		ctx := tracer.ContextWithSpan(context.Background(), root)
		spans.Finished(root) // woven prologue, first Finish
		root.Finish()        // trace complete -> handed to the trace writer
		// Late report recreates an annotation keyed on the finished root.
		vulnerability.Report(ctx, constants.VulnerabilityTypeWeakHash, "MD5", nil, vulnerability.SkipFrame{})
		spans.Finished(root) // woven prologue of a second Finish(): SetMetaStruct on a finished span
		root.Finish()
	}
	tracer.Flush()
}

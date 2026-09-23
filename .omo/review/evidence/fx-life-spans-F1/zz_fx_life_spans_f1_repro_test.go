// Independent reproducer for review finding life-spans-F1.
// It drives the exact call sequence the woven net/http + tracer advice
// performs (httpbridge.Begin / StartSpanFromContext + BindScopeFromContext /
// httpbridge.Finish) at the SHIPPED DEFAULT configuration
// (DD_IAST_REQUEST_SAMPLING=30, DD_IAST_MAX_CONCURRENT_REQUESTS=2), with three
// concurrent server requests per trial. No artificial sampling flipping: the
// decisions come from the real default 30% sampler.
package vulnerability_test

import (
	"context"
	"math/rand/v2"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

type fxRequestOutcome struct {
	decision  request.Decision
	active    bool
	bindNil   bool // BindScopeFromContext returned nil
	bindOrder int
	attempted bool
	reported  bool // ReportTainted returned true
	stored    bool
	weakKept  bool
}

func TestFxLifeSpansF1DefaultConfigCrowdOutDropsTaintedFinding(t *testing.T) {
	// Shipped defaults (internal/config/config.go:66-67): sampling 30%,
	// MaxConcurrentRequests 2. Everything else mirrors configureTaintedReportTest.
	orig := [9]any{
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests,
		config.VulnerabilitiesPerRequest, config.DeduplicationEnabled, config.StackTraceEnabled,
		config.RedactionNamePattern, config.RedactionValuePattern, config.TruncationMaxValue,
	}
	config.Enabled = true
	config.RequestSamplingPct = 30
	config.MaxConcurrentRequests = 2
	config.VulnerabilitiesPerRequest = 64
	config.DeduplicationEnabled = false
	config.StackTraceEnabled = true
	config.RedactionEnabled = true
	config.RedactionNamePattern = regexp.MustCompile(`never-match`)
	config.RedactionValuePattern = regexp.MustCompile(`never-match`)
	config.TruncationMaxValue = 250
	t.Cleanup(func() {
		config.Enabled = orig[0].(bool)
		config.RequestSamplingPct = orig[1].(int)
		config.MaxConcurrentRequests = orig[2].(int)
		config.VulnerabilitiesPerRequest = orig[3].(int)
		config.DeduplicationEnabled = orig[4].(bool)
		config.StackTraceEnabled = orig[5].(bool)
		config.RedactionNamePattern = orig[6].(*regexp.Regexp)
		config.RedactionValuePattern = orig[7].(*regexp.Regexp)
		config.TruncationMaxValue = orig[8].(uint64)
	})

	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	const concurrency = 3
	const maxTrials = 300
	crowded := -1
	var crowdedOutcomes []fxRequestOutcome
	var crowdedOrphans int
	var crowdedSpanEnabledTag any
	for trial := 0; trial < maxTrials && crowded < 0; trial++ {
		finishedBase := len(mock.FinishedSpans())
		outcomes := make([]fxRequestOutcome, concurrency)
		var bindCounter int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range concurrency {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				// Arrival jitter, like real concurrent connections.
				time.Sleep(time.Duration(rand.IntN(2000)) * time.Microsecond)
				<-start
				r := &outcomes[i]
				r.bindOrder = int(atomic.AddInt64(&bindCounter, 1))
				// 1) woven net/http serverHandler.ServeHTTP prepend advice.
				sctx, created := httpbridge.Begin(context.Background(), "GET", "/q", nil)
				scope := request.FromContext(sctx)
				if scope == nil {
					return
				}
				r.decision = scope.Decision()
				r.active = scope.Active()
				// 2) woven tracer.StartSpanFromContext wrapper (iast/net/http
				// BindStartSpan) binds the scope to the new span's root.
				span, spanCtx := tracer.StartSpanFromContext(sctx, "server.request")
				ann := spans.BindScopeFromContext(spanCtx)
				r.bindNil = ann == nil
				_, _, r.stored = spans.ExistingForSpan(span)
				if r.active {
					// 3) tainted SQL sink hit inside this request's scope.
					r.attempted = true
					secret := taint.TaintString(sctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "value"}, "secret")
					query := "SELECT '" + secret + "'"
					query = propagation.JoinString([]string{"SELECT '", secret, "'"}, "", query)
					snapshot, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
					if status == evidence.StatusCollected {
						r.reported = vulnerability.ReportTainted(spanCtx, constants.VulnerabilityTypeSqlInjection, snapshot, redaction.AnalyzeSQL(query), 2, sqlSkipPolicy())
						// Second, identical sink hit: process dedup would normally
						// suppress it once one finding is emitted; here every hit
						// still pays an empty orphan span.
						vulnerability.ReportTainted(spanCtx, constants.VulnerabilityTypeSqlInjection, snapshot, redaction.AnalyzeSQL(query), 2, sqlSkipPolicy())
					}
					// 4) weak-sink path: what vulnerability.Report does first.
					r.weakKept = spans.AnnotationForContext(spanCtx, span).Sampled
				}
				// 5) woven Finish sequence: span finish prologue, then scope finish.
				// A real handler keeps the request span open for its whole body.
				time.Sleep(3 * time.Millisecond)
				spans.Finished(span)
				span.Finish()
				httpbridge.Finish(sctx, created)
			}(i)
		}
		close(start)
		wg.Wait()

		if trial < 8 {
			for i, r := range outcomes {
				t.Logf("trial %d request %d: decision=%d active=%t bindNil=%t stored=%t bindOrder=%d attemptedSink=%t reported=%t weakKept=%t",
					trial, i, r.decision, r.active, r.bindNil, r.stored, r.bindOrder, r.attempted, r.reported, r.weakKept)
			}
		}
		for _, r := range outcomes {
			if r.active && r.bindNil && r.attempted && !r.reported {
				crowded = trial
				crowdedOutcomes = outcomes
				for _, s := range mock.FinishedSpans()[finishedBase:] {
					if s.OperationName() == "vulnerability" {
						crowdedOrphans++
					}
					if s.OperationName() == "server.request" && s.Tag(spans.SpanTagEnabled) == float64(0) {
						crowdedSpanEnabledTag = s.Tag(spans.SpanTagEnabled)
					}
				}
			}
		}
		if crowded < 0 {
			// Keep trials comparable: no leaked annotations between trials.
			for _, s := range mock.FinishedSpans()[finishedBase:] {
				if s.OperationName() == "vulnerability" {
					t.Errorf("trial %d emitted an orphan span without any crowded-out active request: %v", trial, outcomes)
				}
			}
		}
	}
	if crowded < 0 {
		t.Fatalf("crowd-out never observed in %d trials at shipped defaults (finding refuted)", maxTrials)
	}
	for i, r := range crowdedOutcomes {
		t.Logf("crowded trial request %d: decision=%d active=%t bindNil=%t attemptedSink=%t taintedReported=%t weakKept=%t",
			i, r.decision, r.active, r.bindNil, r.attempted, r.reported, r.weakKept)
	}
	t.Logf("crowded trial emitted %d orphan spans named %q", crowdedOrphans, "vulnerability")
	t.Logf("crowded-out active request span _dd.iast.enabled tag=%v", crowdedSpanEnabledTag)

	var crowdedActive, droppedTainted, droppedWeak bool
	for _, r := range crowdedOutcomes {
		if r.active {
			crowdedActive = true
			droppedTainted = droppedTainted || (r.bindNil && r.attempted && !r.reported)
			droppedWeak = droppedWeak || (r.bindNil && !r.weakKept)
		}
	}
	var crowdedActiveCount int
	for _, r := range crowdedOutcomes {
		if r.active && r.bindNil && r.attempted {
			crowdedActiveCount++
		}
	}
	if crowdedActiveCount == 1 && crowdedOrphans != 2 {
		t.Errorf("one crowded-out active request made 2 sink hits but %d orphan spans were emitted (want 2: one empty orphan per sink hit, dedup included)", crowdedOrphans)
	}
	if !crowdedActive || !droppedTainted || !droppedWeak {
		t.Errorf("unexpected crowded-trial shape: active=%t droppedTainted=%t droppedWeak=%t", crowdedActive, droppedTainted, droppedWeak)
	}
}

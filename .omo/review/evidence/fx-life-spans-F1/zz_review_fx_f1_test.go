package testapp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// fx-life-spans-F1 independent reproducer (woven): real net/http server,
// woven serverHandler scope + StartSpanFromContext binding + database/sql sink
// + woven Span.Finish prologue. Only the shipped default capacity (2) is set;
// sampling is toggled to force sampled-out vs active decisions.

type fxResult struct {
	id      string
	active  bool
	enabled any
	hasJSON bool
}

func TestReviewFxF1NegativeDecisionsStarveActive(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	oldMax, oldPct, oldDedup := config.MaxConcurrentRequests, config.RequestSamplingPct, config.DeduplicationEnabled
	t.Cleanup(func() {
		config.MaxConcurrentRequests, config.RequestSamplingPct, config.DeduplicationEnabled = oldMax, oldPct, oldDedup
	})
	config.MaxConcurrentRequests = 2 // shipped default
	config.DeduplicationEnabled = false

	mock := mocktracer.Start()
	defer mock.Stop()

	var mu sync.Mutex
	activeByID := map[string]bool{}
	bound := make(chan struct{}, 8)
	var release chan struct{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		span, ctx := tracer.StartSpanFromContext(r.Context(), "req")
		span.SetTag("req.id", id)
		defer span.Finish()
		scope := taintrequest.FromContext(ctx)
		if strings.HasPrefix(id, "out") {
			bound <- struct{}{}
			<-release
		} else {
			mu.Lock()
			activeByID[id] = scope != nil && scope.Active()
			mu.Unlock()
			if _, err := db.ExecContext(ctx, r.URL.Query().Get("query")); err != nil {
				t.Error(err)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	get := func(id string) {
		v := url.Values{"id": {id}, "query": {"SELECT * FROM t WHERE name = 'x' OR 1=1"}}
		resp, err := server.Client().Get(server.URL + "/?" + v.Encode())
		if err != nil {
			t.Error(err)
			return
		}
		resp.Body.Close()
	}

	for _, inflight := range []int{0, 1, 2} {
		mock.Reset()
		release = make(chan struct{})
		config.RequestSamplingPct = 0
		var wg sync.WaitGroup
		for i := range inflight {
			wg.Go(func() { get(fmt.Sprintf("out%d", i)) })
		}
		for range inflight {
			<-bound
		}
		config.RequestSamplingPct = 100
		activeID := fmt.Sprintf("active-with-%d-sampled-out-inflight", inflight)
		get(activeID)
		close(release)
		wg.Wait()

		var res fxResult
		orphans, orphansWithEvent := 0, 0
		for _, s := range mock.FinishedSpans() {
			raw, hasJSON := s.Tag(spans.SpanTagJson).(string)
			hasJSON = hasJSON && strings.Contains(raw, "SQL_INJECTION")
			switch {
			case s.OperationName() == "vulnerability":
				orphans++
				if hasJSON {
					orphansWithEvent++
				}
			case s.Tag("req.id") == activeID:
				res = fxResult{id: activeID, active: activeByID[activeID], enabled: s.Tag(spans.SpanTagEnabled), hasJSON: hasJSON}
			}
		}
		t.Logf("inflight_sampled_out=%d active_scope=%t request_span _dd.iast.enabled=%v request_span_has_SQLi_event=%t orphan_spans=%d orphan_spans_with_event=%d",
			inflight, res.active, res.enabled, res.hasJSON, orphans, orphansWithEvent)
		if res.active && !res.hasJSON && orphansWithEvent == 0 {
			t.Errorf("BUG: admitted (permit-holding) request with a tainted SQL sink reported NOTHING when %d sampled-out requests were in flight", inflight)
		}
	}
}

// Same surface, pure default sampling (30%) and capacity (2): 4 concurrent
// requests per round, each binds its span then waits for the others before
// hitting the SQL sink. Counts admitted requests whose finding was lost.
func TestReviewFxF1DefaultConfigLossRate(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	oldMax, oldPct, oldDedup := config.MaxConcurrentRequests, config.RequestSamplingPct, config.DeduplicationEnabled
	t.Cleanup(func() {
		config.MaxConcurrentRequests, config.RequestSamplingPct, config.DeduplicationEnabled = oldMax, oldPct, oldDedup
	})
	config.MaxConcurrentRequests = 2 // shipped default
	config.RequestSamplingPct = 30   // shipped default
	config.DeduplicationEnabled = false

	mock := mocktracer.Start()
	defer mock.Stop()
	const rounds, width = 100, 4
	var mu sync.Mutex
	activeByID := map[string]bool{}
	var barrier *sync.WaitGroup
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		span, ctx := tracer.StartSpanFromContext(r.Context(), "req")
		span.SetTag("req.id", id)
		defer span.Finish()
		scope := taintrequest.FromContext(ctx)
		mu.Lock()
		b := barrier
		activeByID[id] = scope != nil && scope.Active()
		mu.Unlock()
		b.Done()
		b.Wait()
		if _, err := db.ExecContext(ctx, r.URL.Query().Get("query")); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	server.Client().Transport.(*http.Transport).MaxIdleConnsPerHost = width

	for round := range rounds {
		b := &sync.WaitGroup{}
		b.Add(width)
		mu.Lock()
		barrier = b
		mu.Unlock()
		var wg sync.WaitGroup
		for i := range width {
			wg.Go(func() {
				v := url.Values{"id": {fmt.Sprintf("r%d-%d", round, i)}, "query": {"SELECT * FROM t WHERE name = 'x' OR 1=1"}}
				resp, err := server.Client().Get(server.URL + "/?" + v.Encode())
				if err != nil {
					t.Error(err)
					return
				}
				resp.Body.Close()
			})
		}
		wg.Wait()
	}
	admitted, reportedOnSpan, lost := 0, 0, 0
	orphans, orphansWithEvent := 0, 0
	for _, s := range mock.FinishedSpans() {
		raw, hasJSON := s.Tag(spans.SpanTagJson).(string)
		hasJSON = hasJSON && strings.Contains(raw, "SQL_INJECTION")
		if s.OperationName() == "vulnerability" {
			orphans++
			if hasJSON {
				orphansWithEvent++
			}
			continue
		}
		id, _ := s.Tag("req.id").(string)
		if !activeByID[id] {
			continue
		}
		admitted++
		if hasJSON {
			reportedOnSpan++
		} else {
			lost++
		}
	}
	t.Logf("default config: requests=%d admitted(active scope)=%d reported_on_request_span=%d lost_on_request_span=%d orphan_spans=%d orphan_spans_with_event=%d",
		rounds*width, admitted, reportedOnSpan, lost, orphans, orphansWithEvent)
	if lost > orphansWithEvent {
		t.Errorf("BUG: %d admitted requests with a tainted SQL sink produced no finding anywhere", lost-orphansWithEvent)
	}
}

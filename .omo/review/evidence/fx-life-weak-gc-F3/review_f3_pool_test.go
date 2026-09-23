// Review reproducer for node fx-life-weak-gc-F3. Not for commit.
// Woven end-to-end check: dd-trace-go span pool + IAST span association.

package testapp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/spans"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/tinylib/msgp/msgp"
)

type f3Agent struct {
	mu       sync.Mutex
	spans    []map[string]any
	received chan struct{}
}

func (a *f3Agent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if strings.HasSuffix(r.URL.Path, "/traces") && len(body) > 0 {
		var js bytes.Buffer
		if _, err := msgp.CopyToJSON(&js, bytes.NewReader(body)); err == nil {
			var traces [][]map[string]any
			if json.Unmarshal(js.Bytes(), &traces) == nil {
				a.mu.Lock()
				for _, tr := range traces {
					a.spans = append(a.spans, tr...)
				}
				a.mu.Unlock()
				select {
				case a.received <- struct{}{}:
				default:
				}
			}
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

// iastPayload returns the decoded IAST event (JSON text) carried by a span, if any.
func iastPayload(span map[string]any) string {
	if meta, ok := span["meta"].(map[string]any); ok {
		if s, ok := meta[spans.SpanTagJson].(string); ok {
			return s
		}
	}
	ms, ok := span["meta_struct"].(map[string]any)
	if !ok {
		return ""
	}
	raw, ok := ms[spans.SpanTagMetaStruct].(string)
	if !ok {
		return ""
	}
	bin, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	var js bytes.Buffer
	if _, err := msgp.CopyToJSON(&js, bytes.NewReader(bin)); err != nil {
		return ""
	}
	return js.String()
}

func (a *f3Agent) waitFor(t *testing.T, resource string) map[string]any {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		a.mu.Lock()
		for _, s := range a.spans {
			if s["resource"] == resource {
				a.mu.Unlock()
				return s
			}
		}
		a.mu.Unlock()
		tracer.Flush()
		select {
		case <-a.received:
		case <-deadline:
			t.Fatalf("agent never received span %q", resource)
		}
	}
}

type f3Observation struct {
	recycled        bool
	scopeActive     bool
	foundAnnotation bool
	vulnsOnArrival  int
	resource        string
	spanID          uint64
	traceIDLower    uint64
}

func TestReviewF3WovenSpanPool(t *testing.T) {
	requireWoven(t)
	for _, variant := range []string{"control-no-late-span", "negative-after-request", "sampled-bleed"} {
		t.Run(variant, func(t *testing.T) { runF3(t, variant) })
	}
}

func runF3(t *testing.T, variant string) {
	t.Setenv("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "false")
	t.Setenv("DD_REMOTE_CONFIGURATION_ENABLED", "false")
	t.Setenv("DD_TRACE_STARTUP_LOGS", "false")
	prevProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prevProcs)
	prevCap := config.MaxConcurrentRequests
	config.MaxConcurrentRequests = 2 // shipped default (DD_IAST_MAX_CONCURRENT_REQUESTS)
	defer func() { config.MaxConcurrentRequests = prevCap }()

	agentState := &f3Agent{received: make(chan struct{}, 1)}
	agent := httptest.NewServer(agentState)
	defer agent.Close()
	if err := tracer.Start(tracer.WithAgentURL(agent.URL), tracer.WithSpanPool(true),
		tracer.WithLogStartup(false), tracer.WithService("f3")); err != nil {
		t.Fatal(err)
	}
	defer tracer.Stop()
	db := openDB(t)

	var (
		mu      sync.Mutex
		rootA   *tracer.Span
		workA   *tracer.Span
		ctxA    context.Context
		obs     f3Observation
		counter int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch q.Get("step") {
		case "A":
			span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request", tracer.ResourceName("request-A"))
			mu.Lock()
			rootA, ctxA = span, ctx
			mu.Unlock()
			if variant == "sampled-bleed" {
				// The request span is finished before the remaining work of the
				// handler (e.g. a tracing middleware nested inside an outer
				// handler, or an explicit early Finish), while the IAST scope
				// opened by serverHandler.ServeHTTP is still active.
				span.Finish()
				late, lctx := tracer.StartSpanFromContext(ctx, "late.db") // woven -> BindStartSpan
				chain := testapp.BuildSQLChain(q.Get("colA"), "tableA")
				_, _ = db.ExecContext(lctx, chain.Query) // SQLi committed to resurrected annotation
				late.Finish()
			} else {
				if variant == "negative-after-request" {
					work, wctx := tracer.StartSpanFromContext(ctx, "async.work")
					mu.Lock()
					workA, ctxA = work, wctx
					mu.Unlock()
				}
				span.Finish()
			}
		case "B":
			counter++
			resource := "request-B-" + q.Get("n")
			span, ctx := tracer.StartSpanFromContext(r.Context(), "http.request", tracer.ResourceName(resource))
			mu.Lock()
			recycled := span == rootA
			mu.Unlock()
			o := f3Observation{recycled: recycled, resource: resource, spanID: span.Context().SpanID()}
			o.scopeActive = taintrequest.FromContext(ctx).Active()
			if _, ann, found := spans.ExistingForSpan(span); found {
				o.foundAnnotation = true
				ann.TryUseOpen(func(a *spans.Annotation) { o.vulnsOnArrival = len(a.Event.Vulnerabilities) })
			}
			if recycled {
				mu.Lock()
				obs = o
				mu.Unlock()
				if variant != "sampled-bleed" {
					// Request B has its own genuine SQL injection.
					chain := testapp.BuildSQLChain(q.Get("colB"), "tableB")
					_, _ = db.ExecContext(ctx, chain.Query)
				}
			}
			span.Finish()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	do := func(values url.Values) {
		resp, err := server.Client().Get(server.URL + "/?" + values.Encode())
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}

	attemptsA := 0
	for attemptsA < 50 {
		attemptsA++
		do(url.Values{"step": {"A"}, "colA": {"aa_from_request_A"}})
		if variant != "negative-after-request" {
			break
		}
		lateIsRootA := false
		{
			// Fire-and-forget work that outlives request A and traces with its
			// context (the response has been delivered, so the IAST scope is finished).
			done := make(chan struct{})
			go func() {
				defer close(done)
				mu.Lock()
				c := ctxA
				mu.Unlock()
				late, lctx := tracer.StartSpanFromContext(c, "late.async") // woven -> BindStartSpan
				mu.Lock()
				r := rootA
				mu.Unlock()
				_, lateAnn, lateFound := spans.ExistingForSpan(late)
				_, rootAnn, rootFound := spans.ExistingForSpan(r)
				t.Logf("late goroutine: late.Root()==rootA:%t late.Root()==nil:%t scopeActive=%t ExistingForSpan(late)=%t sampled=%t ExistingForSpan(rootA)=%t sampled=%t",
					late.Root() == r, late.Root() == nil, taintrequest.FromContext(lctx).Active(), lateFound, lateAnn != nil && lateAnn.Sampled, rootFound, rootAnn != nil && rootAnn.Sampled)
				lateIsRootA = late == r
				t.Logf("attemptA=%d lateSpanIsRecycledRootAObject=%t", attemptsA, lateIsRootA)
				late.Finish()
				mu.Lock()
				w := workA
				mu.Unlock()
				w.Finish()
			}()
			<-done
		}
		if !lateIsRootA {
			break
		}
	}

	for n := 0; n < 200; n++ {
		tracer.Flush()
		runtime.Gosched()
		do(url.Values{"step": {"B"}, "n": {itoa(n)}, "colB": {"bb_from_request_B"}})
		mu.Lock()
		got := obs
		mu.Unlock()
		if got.recycled {
			break
		}
	}
	mu.Lock()
	got := obs
	mu.Unlock()
	if !got.recycled {
		t.Skipf("span pool never handed request A's root object to a later request (requests=%d)", counter)
	}
	emitted := agentState.waitFor(t, got.resource)
	payload := iastPayload(emitted)
	var orphanPayloads []string
	if variant != "sampled-bleed" {
		deadline := time.Now().Add(5 * time.Second)
		for len(orphanPayloads) == 0 && time.Now().Before(deadline) {
			agentState.mu.Lock()
			for _, s := range agentState.spans {
				if s["name"] == "vulnerability" {
					if p := iastPayload(s); strings.Contains(p, "bb_from_request_B") || strings.Contains(p, "colB") {
						orphanPayloads = append(orphanPayloads, p)
					}
				}
			}
			agentState.mu.Unlock()
			if len(orphanPayloads) == 0 {
				tracer.Flush()
				select {
				case <-agentState.received:
				case <-time.After(time.Second):
				}
			}
		}
	}
	t.Logf("variant=%s requestsB=%d recycledRootA=true resource=%s scopeActive=%t ExistingForSpan(found)=%t vulnsOnArrival=%d",
		variant, counter, got.resource, got.scopeActive, got.foundAnnotation, got.vulnsOnArrival)
	t.Logf("agent span %s: meta[_dd.iast.enabled]=%v metrics[_dd.iast.enabled]=%v iastEvent=%s",
		got.resource, metaOf(emitted, spans.SpanTagEnabled), metricOf(emitted, spans.SpanTagEnabled), payload)
	t.Logf("orphan 'vulnerability' spans carrying request B's finding: %d %v", len(orphanPayloads), orphanPayloads)

	switch variant {
	case "control-no-late-span":
		if !got.foundAnnotation || payload == "" || !strings.Contains(payload, "colB") {
			t.Errorf("control: recycled root without stale entry should be analyzed normally")
		}
	case "negative-after-request":
		if got.scopeActive && !got.foundAnnotation {
			t.Errorf("BUG (false negative): active request B reused request A's root object and inherited A's stale negative entry; request span has no IAST annotation")
		}
		if payload == "" {
			t.Errorf("BUG: request B's own SQL injection is not attached to request B's span (payload empty)")
		}
	case "sampled-bleed":
		if got.vulnsOnArrival > 0 {
			t.Errorf("BUG (cross-request bleed): request B's root arrived with %d finding(s) from request A", got.vulnsOnArrival)
		}
		if strings.Contains(payload, "aa_from_request_A") || strings.Contains(payload, "colA") {
			t.Errorf("BUG (cross-request bleed): agent received request B's span %s carrying request A's finding", got.resource)
		}
	}
}

func metaOf(span map[string]any, key string) any {
	if m, ok := span["meta"].(map[string]any); ok {
		return m[key]
	}
	return nil
}

func metricOf(span map[string]any, key string) any {
	if m, ok := span["metrics"].(map[string]any); ok {
		return m[key]
	}
	return nil
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

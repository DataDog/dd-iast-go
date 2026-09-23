// Review reproducers (life-async): tainted values and request owners used across
// goroutines and after request end, through the real woven net/http server.

package testapp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/spans"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

var reviewStore *store.Store

func reviewGet(t *testing.T, srv *httptest.Server, values url.Values, header string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/?"+values.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if header != "" {
		req.Header.Set("X-Review", header)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// tracedHandler mirrors captureRequestEvent: a root span from the request context.
func tracedHandler(op func(ctx context.Context, w http.ResponseWriter, r *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.review.request")
		defer span.Finish()
		if reviewStore == nil {
			reviewStore = taintrequest.ActiveStore()
		}
		op(ctx, w, r.WithContext(ctx))
		w.WriteHeader(http.StatusNoContent)
	})
}

type reviewSpanEvent struct {
	name  string
	value string
	event model.Event
	has   bool
}

func reviewEvents(t *testing.T, mt mocktracer.Tracer) []reviewSpanEvent {
	t.Helper()
	var out []reviewSpanEvent
	for _, s := range mt.FinishedSpans() {
		e := reviewSpanEvent{name: s.OperationName()}
		e.value, _ = s.Tag("review.value").(string)
		if raw, _ := s.Tag(spans.SpanTagJson).(string); raw != "" {
			if err := json.Unmarshal([]byte(raw), &e.event); err != nil {
				t.Fatal(err)
			}
			e.has = true
		}
		out = append(out, e)
	}
	return out
}

func evidenceValue(v model.Vulnerability) string {
	if v.Evidence == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range v.Evidence.ValueParts {
		b.WriteString(p.Value)
		b.WriteString(p.Pattern)
	}
	return b.String()
}

func reviewCounters(t *testing.T, label string) {
	t.Helper()
	if reviewStore == nil {
		t.Logf("%s: store not captured", label)
		return
	}
	t.Logf("%s: ProcessCharged=%d ProcessValues=%d ActiveStore!=nil=%v", label, reviewStore.ProcessCharged(), reviewStore.ProcessValues(), taintrequest.ActiveStore() != nil)
}

// A goroutine that outlives its request keeps using tainted values, the
// request context, a WithoutCancel copy and a background context.
func TestReviewLateGoroutineAfterRequestEnd(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	mt := mocktracer.Start()
	defer mt.Stop()

	proceed := make(chan struct{})
	done := make(chan []string, 1)
	srv := httptest.NewServer(tracedHandler(func(ctx context.Context, _ http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		derivedIn := testapp.ReviewDerive(q)
		if !taint.IsTaintedString(q) || !taint.IsTaintedString(derivedIn) {
			t.Errorf("precondition: in-request taint q=%v derived=%v", taint.IsTaintedString(q), taint.IsTaintedString(derivedIn))
		}
		detached := context.WithoutCancel(ctx)
		go func() {
			<-proceed
			var notes []string
			if taintrequest.FromContext(ctx).Active() {
				notes = append(notes, "PRECONDITION FAILED: scope still active")
			}
			derived := testapp.ReviewDerive(q)
			concat := testapp.ReviewConcat(q, derivedIn)
			notes = append(notes, fmt.Sprintf("after end: tainted q=%v derivedIn=%v derived=%v concat=%v",
				taint.IsTaintedString(q), taint.IsTaintedString(derivedIn), taint.IsTaintedString(derived), taint.IsTaintedString(concat)))
			for i, c := range []context.Context{ctx, detached, context.Background()} {
				_, err := db.ExecContext(c, q)
				_, err2 := db.ExecContext(c, derivedIn)
				if err != nil || err2 != nil {
					notes = append(notes, fmt.Sprintf("ctx%d exec error %v %v", i, err, err2))
				}
			}
			done <- notes
		}()
	}))
	defer srv.Close()
	reviewGet(t, srv, url.Values{"q": {"SELECT late_goroutine FROM t"}}, "")
	// The client has the response: serverHandler.ServeHTTP (and its deferred
	// scope Finish) returned before net/http wrote it.
	close(proceed)
	notes := <-done
	for _, n := range notes {
		t.Log(n)
		if strings.Contains(n, "true") || strings.Contains(n, "FAILED") {
			t.Errorf("unexpected: %s", n)
		}
	}
	for _, e := range reviewEvents(t, mt) {
		t.Logf("span %q hasEvent=%v vulns=%d", e.name, e.has, len(e.event.Vulnerabilities))
		if e.has {
			t.Errorf("late goroutine produced a report on span %q: %+v", e.name, e.event)
		}
	}
	reviewCounters(t, "after late goroutine")
}

// A tainted value stored in a global in request A must not be reported (or be
// tainted) in a later request B that reuses A's owner slot; a clean value that
// reuses A's freed address must be clean.
func TestReviewGlobalAcrossRequests(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	mt := mocktracer.Start()
	defer mt.Stop()

	var global, globalDerived string
	var freedPtr uintptr
	var freedLen int
	phase := "A"
	var reuseHits, reuseTainted int
	srv := httptest.NewServer(tracedHandler(func(ctx context.Context, _ http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		span, _ := tracer.SpanFromContext(ctx)
		span.SetTag("review.value", q)
		switch phase {
		case "A":
			global = q
			globalDerived = testapp.ReviewDerive(q)
			_, _ = db.ExecContext(ctx, q) // control: reported on A
			f := r.URL.Query().Get("f")   // freed below
			freedPtr, freedLen = uintptr(unsafe.Pointer(unsafe.StringData(f))), len(f)
			if !taint.IsTaintedString(f) {
				t.Errorf("precondition: f not tainted")
			}
		case "B":
			if taint.IsTaintedString(global) || taint.IsTaintedString(globalDerived) {
				t.Errorf("global from finished request A is tainted in B: %v %v", taint.IsTaintedString(global), taint.IsTaintedString(globalDerived))
			}
			_, _ = db.ExecContext(ctx, global)
			_, _ = db.ExecContext(ctx, globalDerived)
			_, _ = db.ExecContext(ctx, q) // control: reported on B with B's source only
			runtime.GC()
			runtime.GC()
			pattern := strings.Repeat("c", freedLen)
			keep := make([]string, 0, 20000)
			for i := 0; i < 20000; i++ {
				s := strings.Clone(pattern)
				keep = append(keep, s)
				if uintptr(unsafe.Pointer(unsafe.StringData(s))) == freedPtr {
					reuseHits++
					if taint.IsTaintedString(s) {
						reuseTainted++
					}
					_, _ = db.ExecContext(ctx, s)
				}
			}
			runtime.KeepAlive(keep)
		}
	}))
	defer srv.Close()
	reviewGet(t, srv, url.Values{"q": {"SELECT request_a_value FROM t"}, "f": {"freed-value-xyz"}}, "")
	runtime.GC()
	runtime.GC()
	phase = "B"
	reviewGet(t, srv, url.Values{"q": {"SELECT request_b_value FROM t"}}, "")
	t.Logf("address reuse: hits=%d tainted=%d (freed len %d)", reuseHits, reuseTainted, freedLen)
	if reuseTainted != 0 {
		t.Errorf("clean value at a freed address is tainted")
	}
	for _, e := range reviewEvents(t, mt) {
		t.Logf("span %q value=%q vulns=%d sources=%d", e.name, e.value, len(e.event.Vulnerabilities), len(e.event.Sources))
		for _, v := range e.event.Vulnerabilities {
			t.Logf("   evidence=%q", evidenceValue(v))
		}
		for _, s := range e.event.Sources {
			if s.Value != e.value {
				t.Errorf("span for %q carries foreign source %q", e.value, s.Value)
			}
		}
		if len(e.event.Vulnerabilities) != 1 {
			t.Errorf("span for %q: vulnerabilities=%d want 1", e.value, len(e.event.Vulnerabilities))
		}
	}
	reviewCounters(t, "after global across requests")
}

// A long-lived worker goroutine started by request A captures a detached
// request context. Later, active request B hands it a value tainted by B.
func TestReviewWorkerWithFinishedRequestContext(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	mt := mocktracer.Start()
	defer mt.Stop()

	type job struct {
		q    string
		done chan string
	}
	jobs := make(chan job)
	phase := "A"
	srv := httptest.NewServer(tracedHandler(func(ctx context.Context, _ http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		span, _ := tracer.SpanFromContext(ctx)
		span.SetTag("review.value", q)
		if phase == "A" {
			workerCtx := context.WithoutCancel(ctx) // a common "detached background work" idiom
			go func() {
				for j := range jobs {
					active := taintrequest.FromContext(workerCtx).Active()
					_, _ = db.ExecContext(workerCtx, j.q)                                            // sink #1: finished request A's ctx
					_, _ = db.ExecContext(context.Background(), testapp.ReviewConcat(j.q, " -- bg")) // sink #2: background ctx
					j.done <- fmt.Sprintf("worker: A-scope active=%v valueTainted=%v", active, taint.IsTaintedString(j.q))
				}
			}()
			return
		}
		j := job{q: q, done: make(chan string)}
		jobs <- j
		t.Log(<-j.done)
	}))
	defer srv.Close()
	defer close(jobs)
	reviewGet(t, srv, url.Values{"q": {"SELECT request_a FROM t"}}, "")
	phase = "B"
	reviewGet(t, srv, url.Values{"q": {"SELECT request_b_worker FROM t"}}, "")
	var sawWorkerCtx, sawBackground bool
	for _, e := range reviewEvents(t, mt) {
		t.Logf("span %q value=%q vulns=%d", e.name, e.value, len(e.event.Vulnerabilities))
		for _, v := range e.event.Vulnerabilities {
			ev := evidenceValue(v)
			t.Logf("   evidence=%q", ev)
			if e.value == "SELECT request_b_worker FROM t" {
				if ev == "SELECT request_b_worker FROM t" {
					sawWorkerCtx = true
				}
				if strings.HasSuffix(ev, " -- bg") {
					sawBackground = true
				}
			}
		}
	}
	t.Logf("RESULT sink with finished-A ctx reported=%v; same value via background ctx reported=%v", sawWorkerCtx, sawBackground)
	if !sawWorkerCtx {
		t.Errorf("FALSE NEGATIVE: value tainted by live request B is dropped because the sink context carries finished request A's scope")
	}
}

// Many concurrent requests; each spawns a goroutine that keeps sinking its own
// tainted value while the request ends. No report may land on another
// request's span; orphan spans are counted.
func TestReviewConcurrentOwnerEndVsSink(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	mt := mocktracer.Start()
	defer mt.Stop()

	const n = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	iterations := map[string]int{}
	srv := httptest.NewServer(tracedHandler(func(ctx context.Context, _ http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		span, _ := tracer.SpanFromContext(ctx)
		span.SetTag("review.value", q)
		useReqCtx := strings.Contains(q, "ctx")
		started := make(chan struct{})
		var once sync.Once
		signal := func() { once.Do(func() { close(started) }) }
		wg.Add(1)
		go func() {
			defer wg.Done()
			i := 0
			for ; i < 20000; i++ {
				if i == 1 {
					signal() // first sink done while the request is live
				}
				c := context.Background()
				if useReqCtx {
					c = ctx
				}
				_, _ = db.ExecContext(c, q)
				if d := testapp.ReviewDeriveIdent(q); i%2 == 1 {
					_, _ = db.ExecContext(c, d) // propagation racing owner Finish
				}
				if !taint.IsTaintedString(q) {
					break
				}
			}
			signal()
			mu.Lock()
			iterations[q] = i
			mu.Unlock()
		}()
		<-started
	}))
	defer srv.Close()
	var cw sync.WaitGroup
	for i := 0; i < n; i++ {
		cw.Add(1)
		go func(i int) {
			defer cw.Done()
			kind := "bg"
			if i%2 == 0 {
				kind = "ctx"
			}
			reviewGet(t, srv, url.Values{"q": {fmt.Sprintf("SELECT v%02d_%s_xxxxxxxx FROM t", i, kind)}}, "")
		}(i)
	}
	cw.Wait()
	wg.Wait()
	values := map[string]bool{}
	for q := range iterations {
		values[q] = true
	}
	var requestVulns, orphanSpans, orphanVulns, foreign int
	for _, e := range reviewEvents(t, mt) {
		if e.name == "vulnerability" {
			orphanSpans++
			orphanVulns += len(e.event.Vulnerabilities)
			for _, s := range e.event.Sources {
				if !values[s.Value] {
					t.Errorf("orphan span with unknown source %q", s.Value)
				}
			}
			continue
		}
		requestVulns += len(e.event.Vulnerabilities)
		for _, s := range e.event.Sources {
			if s.Redacted || s.Value != e.value {
				foreign++
				t.Errorf("WRONG SPAN: span for %q carries source %q", e.value, s.Value)
			}
		}
	}
	t.Logf("RESULT requests=%d requestVulns=%d orphanSpans=%d orphanVulns=%d foreignSources=%d", n, requestVulns, orphanSpans, orphanVulns, foreign)
	reviewCounters(t, "after concurrent owner-end vs sink")
}

// Middleware replaces the request context with a non-derived context before an
// application-root handler (woven with BeginContext).
func TestReviewMiddlewareDetachedContext(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	for _, tc := range []struct {
		name    string
		detach  bool
		permits int
	}{
		{"control passthrough", false, 64},
		{"detached, permits free", true, 64},
		{"detached, one permit", true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := config.MaxConcurrentRequests
			config.MaxConcurrentRequests = tc.permits
			defer func() { config.MaxConcurrentRequests = saved }()
			mt := mocktracer.Start()
			defer mt.Stop()
			var obs string
			inner := testapp.ReviewInner{DB: db, Observe: func(r *http.Request, q, hv string) {
				scope := taintrequest.FromContext(r.Context())
				var refs [store.MaxSnapshotOwners]store.OwnerRef
				urlOwners := taintrequest.LookupObject(r.URL, store.BindingURL, refs[:])
				obs = fmt.Sprintf("inner scope=%v active=%v decision=%v urlBoundOwners=%d queryTainted=%v headerTainted=%v",
					scope != nil, scope.Active(), scope.Decision(), urlOwners, taint.IsTaintedString(q), taint.IsTaintedString(hv))
			}}
			var h http.Handler = testapp.ReviewPassthrough{Next: inner}
			if tc.detach {
				h = testapp.ReviewDetach{Next: inner}
			}
			srv := httptest.NewServer(tracedHandler(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
				span, _ := tracer.SpanFromContext(ctx)
				span.SetTag("review.value", "outer")
				h.ServeHTTP(w, r)
			}))
			defer srv.Close()
			reviewGet(t, srv, url.Values{"q": {"SELECT mw_query FROM t"}}, "SELECT mw_header FROM t")
			t.Log(obs)
			total := 0
			for _, e := range reviewEvents(t, mt) {
				t.Logf("span %q vulns=%d", e.name, len(e.event.Vulnerabilities))
				for _, v := range e.event.Vulnerabilities {
					t.Logf("   evidence=%q", evidenceValue(v))
				}
				total += len(e.event.Vulnerabilities)
			}
			t.Logf("RESULT %s: reported=%d of 2 tainted sinks", tc.name, total)
			if total != 2 {
				t.Errorf("FALSE NEGATIVE: %d of 2 tainted sinks reported", total)
			}
		})
	}
}

// Standard middleware that copies the *url.URL (http.StripPrefix, Request.Clone)
// while keeping the request context.
func TestReviewMiddlewareURLCopy(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	for _, tc := range []struct {
		name string
		wrap func(http.Handler) http.Handler
	}{
		{"control WithContext", func(h http.Handler) http.Handler { return testapp.ReviewPassthrough{Next: h} }},
		{"http.StripPrefix", func(h http.Handler) http.Handler { return http.StripPrefix("/api", h) }},
		{"Request.Clone", func(h http.Handler) http.Handler { return testapp.ReviewClone{Next: h} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mt := mocktracer.Start()
			defer mt.Stop()
			var obs string
			inner := testapp.ReviewInner{DB: db, Observe: func(r *http.Request, q, hv string) {
				scope := taintrequest.FromContext(r.Context())
				var refs [store.MaxSnapshotOwners]store.OwnerRef
				urlOwners := taintrequest.LookupObject(r.URL, store.BindingURL, refs[:])
				obs = fmt.Sprintf("scopeActive=%v urlBoundOwners=%d URL.Query tainted=%v RawQuery tainted=%v FormValue tainted=%v header tainted=%v",
					scope.Active(), urlOwners, taint.IsTaintedString(q), taint.IsTaintedString(r.URL.RawQuery), taint.IsTaintedString(r.FormValue("q")), taint.IsTaintedString(hv))
			}}
			h := tc.wrap(inner)
			srv := httptest.NewServer(tracedHandler(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
				h.ServeHTTP(w, r)
			}))
			defer srv.Close()
			req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/items?"+url.Values{"q": {"SELECT mw_query FROM t"}}.Encode(), nil)
			req.Header.Set("X-Review", "SELECT mw_header FROM t")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			t.Log(obs)
			total := 0
			for _, e := range reviewEvents(t, mt) {
				for _, v := range e.event.Vulnerabilities {
					t.Logf("   span %q evidence=%q", e.name, evidenceValue(v))
				}
				total += len(e.event.Vulnerabilities)
			}
			t.Logf("RESULT %s: reported=%d of 2 tainted sinks", tc.name, total)
			if total != 2 {
				t.Errorf("FALSE NEGATIVE: %d of 2 tainted sinks reported", total)
			}
		})
	}
}

// A goroutine from finished request A calls lazy source APIs on A's *http.Request
// and sinks with a background context while request B (reusing A's owner/permit
// slot) is live. Nothing may be tainted or reported on B.
func TestReviewLateLazySourcesDuringNextRequest(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	mt := mocktracer.Start()
	defer mt.Stop()
	var reqA *http.Request
	var ctxA context.Context
	phase := "A"
	notes := make(chan string, 1)
	srv := httptest.NewServer(tracedHandler(func(ctx context.Context, _ http.ResponseWriter, r *http.Request) {
		span, _ := tracer.SpanFromContext(ctx)
		span.SetTag("review.value", phase)
		if phase == "A" {
			reqA, ctxA = r, ctx
			return
		}
		// Request B is live; run A's late work now.
		qB := r.URL.Query().Get("q")
		done := make(chan struct{})
		go func() {
			defer close(done)
			q := reqA.URL.Query().Get("q")
			fv := reqA.FormValue("q")
			hv := reqA.Header.Get("X-Review")
			c, _ := reqA.Cookie("c")
			cv := ""
			if c != nil {
				cv = c.Value
			}
			for _, v := range []string{q, fv, hv, cv} {
				_, _ = db.ExecContext(context.Background(), v)
				_, _ = db.ExecContext(context.WithoutCancel(ctxA), v)
			}
			notes <- fmt.Sprintf("late lazy on A while B live: query=%v form=%v header=%v cookie=%v (B value tainted=%v)",
				taint.IsTaintedString(q), taint.IsTaintedString(fv), taint.IsTaintedString(hv), taint.IsTaintedString(cv), taint.IsTaintedString(qB))
		}()
		<-done
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/?"+url.Values{"q": {"SELECT late_lazy_a FROM t"}}.Encode(), nil)
	req.Header.Set("X-Review", "SELECT late_header_a FROM t")
	req.AddCookie(&http.Cookie{Name: "c", Value: "late_cookie_a"})
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	phase = "B"
	reviewGet(t, srv, url.Values{"q": {"SELECT live_b FROM t"}}, "")
	n := <-notes
	t.Log(n)
	if strings.Count(n, "=true") != 1 { // only B's own value
		t.Errorf("late lazy source on finished request is tainted: %s", n)
	}
	for _, e := range reviewEvents(t, mt) {
		t.Logf("span %q value=%q vulns=%d", e.name, e.value, len(e.event.Vulnerabilities))
		if len(e.event.Vulnerabilities) != 0 {
			t.Errorf("unexpected report on %q: %+v", e.value, e.event)
		}
	}
}

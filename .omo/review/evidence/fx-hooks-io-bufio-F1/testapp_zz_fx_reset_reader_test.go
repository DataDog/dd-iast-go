package testapp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func fxRanges(s string) string {
	var out []string
	taint.VisitString(s, func(r taint.Range) bool {
		raw, _ := json.Marshal(r.Source)
		out = append(out, string(raw))
		return true
	})
	return strings.Join(out, " ")
}

func fxDescribe(t *testing.T, label string, event model.Event) {
	t.Helper()
	for i, v := range event.Vulnerabilities {
		raw, _ := json.Marshal(v.Evidence)
		t.Logf("%s vuln[%d] type=%s evidence=%s", label, i, v.Type, raw)
	}
	for i, s := range event.Sources {
		raw, _ := json.Marshal(s)
		t.Logf("%s source[%d]=%s", label, i, raw)
	}
	t.Logf("%s summary vulns=%d sources=%d", label, len(event.Vulnerabilities), len(event.Sources))
}

func fxServe(t *testing.T, handler func(label string, w http.ResponseWriter, r *http.Request, span *tracer.Span)) (*httptest.Server, mocktracer.Tracer) {
	mock := mocktracer.Start()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		label := r.Header.Get("X-FX")
		span, ctx := tracer.StartSpanFromContext(r.Context(), "fx.request")
		span.SetTag("fx.req", label)
		defer span.Finish()
		handler(label, w, r.WithContext(ctx), span)
		w.WriteHeader(http.StatusNoContent)
	}))
	return server, mock
}

func fxPost(t *testing.T, server *httptest.Server, label, body string) {
	req, _ := http.NewRequest(http.MethodPost, server.URL, strings.NewReader(body))
	req.Header.Set("X-FX", label)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	resp.Body.Close()
}

func fxEvents(t *testing.T, mock mocktracer.Tracer) map[string]model.Event {
	t.Helper()
	out := map[string]model.Event{}
	for _, span := range mock.FinishedSpans() {
		label, _ := span.Tag("fx.req").(string)
		raw, _ := span.Tag(spans.SpanTagJson).(string)
		var event model.Event
		if raw != "" {
			if err := json.Unmarshal([]byte(raw), &event); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("span fx.req=%s iast.enabled=%v hasJSON=%v", label, span.Tag(spans.SpanTagEnabled), raw != "")
		out[label] = event
	}
	return out
}

func TestFXResetOntoConstantInRequest(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	server, mock := fxServe(t, func(label string, _ http.ResponseWriter, r *http.Request, _ *tracer.Span) {
		switch label {
		case "reset":
			body, q, query, err := testapp.FXResetOntoConstant(r.Context(), db, r.Body)
			t.Logf("diag reset body=%q body-tainted=%v q-tainted=%v query=%q query-ranges=%s err=%v",
				body, taint.IsTaintedBytes(body), taint.IsTaintedBytes(q), query, fxRanges(query), err)
		case "control":
			q, query, err := testapp.FXControl(r.Context(), db, r.Body)
			t.Logf("diag control q-tainted=%v query=%q query-ranges=%s err=%v", taint.IsTaintedBytes(q), query, fxRanges(query), err)
		}
	})
	defer mock.Stop()
	fxPost(t, server, "reset", "name=alice")
	fxPost(t, server, "control", "name=alice")
	server.Close()
	events := fxEvents(t, mock)
	fxDescribe(t, "case=in-request-reset", events["reset"])
	fxDescribe(t, "case=in-request-control", events["control"])
}

func TestFXPooledReaderAcrossRequests(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	var pool testapp.FXReaderPool
	aReleased := make(chan struct{})
	bDone := make(chan struct{})
	server, mock := fxServe(t, func(label string, _ http.ResponseWriter, r *http.Request, _ *tracer.Span) {
		switch label {
		case "A":
			data := testapp.FXPooledA(&pool, r.Body)
			t.Logf("diag A body=%q tainted=%v", data, taint.IsTaintedBytes(data))
			close(aReleased)
			<-bDone
		case "B":
			<-aReleased
			defer close(bDone)
			q, query, err := testapp.FXPooledBInternal(r.Context(), db, &pool)
			t.Logf("diag B internal q-tainted=%v query=%q query-ranges=%s err=%v", taint.IsTaintedBytes(q), query, fxRanges(query), err)
			q2, query2, err := testapp.FXPooledBBody(r.Context(), db, &pool, r.Body)
			t.Logf("diag B own-body q-tainted=%v query=%q query-ranges=%s err=%v", taint.IsTaintedBytes(q2), query2, fxRanges(query2), err)
		}
	})
	defer mock.Stop()
	var wg sync.WaitGroup
	for _, label := range []string{"A", "B"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fxPost(t, server, label, "body_of_"+label+"=1")
		}()
	}
	wg.Wait()
	server.Close()
	events := fxEvents(t, mock)
	fxDescribe(t, "case=pooled-A", events["A"])
	fxDescribe(t, "case=pooled-B", events["B"])
}

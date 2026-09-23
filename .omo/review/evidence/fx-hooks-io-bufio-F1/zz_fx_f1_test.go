package testapp_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
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

func fxRanges(data string) string {
	var out []string
	taint.VisitString(data, func(r taint.Range) bool {
		out = append(out, string(r.Source.Origin.String())+"="+r.Source.Value)
		return true
	})
	return strings.Join(out, ",")
}

const fxConstQuery = "SELECT name FROM constant_table"

func TestFxF1PooledBufioReaderCrossOwner(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	mock := mocktracer.Start()
	defer mock.Stop()

	aRead := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	logs := map[string]string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "req"+r.URL.Path)
		defer span.Finish()
		var line string
		switch r.URL.Path {
		case "/a": // owner A: reads its own body via the pool, then keeps working.
			data := testapp.FxReadAllPooled(r.Body)
			line = "data=" + data + " tainted=" + boolStr(taint.IsTaintedString(data)) + " ranges=" + fxRanges(data)
			close(aRead)
			<-release
		case "/b": // request B, active: its body through the reused reader.
			data := testapp.FxReadAllPooled(r.Body)
			line = "data=" + data + " tainted=" + boolStr(taint.IsTaintedString(data)) + " ranges=" + fxRanges(data)
			_, _ = db.ExecContext(ctx, data)
		case "/c": // request C, active: a clean constant through the reused reader, then SQL.
			query := testapp.FxReadAllPooled(strings.NewReader(fxConstQuery))
			line = "data=" + query + " tainted=" + boolStr(taint.IsTaintedString(query)) + " ranges=" + fxRanges(query)
			_, _ = db.ExecContext(ctx, query)
		case "/c0": // control: same constant, fresh reader (no pool).
			data, _ := io.ReadAll(bufio.NewReader(strings.NewReader(fxConstQuery)))
			query := testapp.BytesToStringForFx(data)
			line = "data=" + query + " tainted=" + boolStr(taint.IsTaintedString(query))
			_, _ = db.ExecContext(ctx, query)
		}
		mu.Lock()
		logs[r.URL.Path] = line
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	post := func(path, body string) {
		resp, err := server.Client().Post(server.URL+path, "text/plain", strings.NewReader(body))
		if err != nil {
			t.Error(err)
			return
		}
		resp.Body.Close()
	}

	aDone := make(chan struct{})
	go func() { defer close(aDone); post("/a", "body-of-request-A") }()
	<-aRead
	post("/c0", "")
	post("/b", "SELECT * FROM t WHERE name = 'body-of-B'")
	post("/c", "")
	// D: background job (no request scope) reusing the pooled reader.
	dQuery := testapp.FxReadAllPooled(strings.NewReader(fxConstQuery))
	t.Logf("case=/d(background) data=%s tainted=%v ranges=%s", dQuery, taint.IsTaintedString(dQuery), fxRanges(dQuery))
	_, _ = db.ExecContext(context.Background(), dQuery)
	close(release)
	<-aDone
	// E: after A finished, the same pooled reader must be clean.
	eData := testapp.FxReadAllPooled(strings.NewReader(fxConstQuery))
	t.Logf("case=/e(after-A-finish) tainted=%v", taint.IsTaintedString(eData))

	for _, p := range []string{"/a", "/c0", "/b", "/c"} {
		t.Logf("case=%s %s", p, logs[p])
	}
	for _, s := range mock.FinishedSpans() {
		raw, _ := s.Tag(spans.SpanTagJson).(string)
		if raw == "" {
			t.Logf("span=%s event=<none>", s.OperationName())
			continue
		}
		var ev model.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			t.Fatal(err)
		}
		for _, v := range ev.Vulnerabilities {
			t.Logf("span=%s vuln=%s", s.OperationName(), v.Type)
		}
		for _, src := range ev.Sources {
			b, _ := json.Marshal(src)
			t.Logf("span=%s source=%s", s.OperationName(), b)
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

package testapp_test

// crash-race-hunt: concurrent woven HTTP requests through sources,
// propagation, writers, JSON, SQL and exec sinks. Run under -race.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/spans"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestRaceHuntConcurrentWovenRequests(t *testing.T) {
	if os.Getenv("RACEHUNT_PLAIN") != "1" {
		requireWoven(t)
	}
	db := openDB(t)
	mock := mocktracer.Start()
	defer mock.Stop()
	var handled, failures atomic.Int64
	var counter atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.racehunt.request")
		defer span.Finish()
		n, err := testapp.RaceHuntHandle(ctx, r.WithContext(ctx), db, counter.Add(1)%16 == 0)
		if err != nil {
			failures.Add(1)
		}
		handled.Add(int64(n))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	const clients = 24
	const perClient = 20
	var wg sync.WaitGroup
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			client := server.Client()
			for i := 0; i < perClient; i++ {
				values := url.Values{"name": {fmt.Sprintf(" n%d-%d' OR 1=1 ", c, i)}}
				var req *http.Request
				var err error
				switch i % 3 {
				case 0:
					req, err = http.NewRequest(http.MethodGet, server.URL+"/?"+values.Encode()+"&id=g"+fmt.Sprint(i), nil)
				case 1:
					form := url.Values{"id": {fmt.Sprintf("form-%d-%d", c, i)}}
					req, err = http.NewRequest(http.MethodPost, server.URL+"/?"+values.Encode(), strings.NewReader(form.Encode()))
					if req != nil {
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}
				default:
					body := fmt.Sprintf(`{"value":"json-%d-%d","list":["a%d","b%d"]}`, c, i, c, i)
					req, err = http.NewRequest(http.MethodPost, server.URL+"/?"+values.Encode(), strings.NewReader(body))
					if req != nil {
						req.Header.Set("Content-Type", "application/json")
					}
				}
				if err != nil {
					t.Error(err)
					return
				}
				req.Header.Set("X-Hunt", fmt.Sprintf("hdr-%d", c))
				req.AddCookie(&http.Cookie{Name: "session", Value: fmt.Sprintf("sess%d", i)})
				resp, err := client.Do(req)
				if err != nil {
					t.Error(err)
					return
				}
				resp.Body.Close()
			}
		}(c)
	}
	wg.Wait()
	testapp.RaceHuntDetached.Wait()
	if failures.Load() != 0 {
		t.Fatalf("handler failures: %d", failures.Load())
	}
	vulnSpans := 0
	for _, s := range mock.FinishedSpans() {
		if raw, _ := s.Tag(spans.SpanTagJson).(string); raw != "" {
			vulnSpans++
		}
	}
	t.Logf("goroutine sinks=%d spans=%d spansWithIAST=%d", handled.Load(), len(mock.FinishedSpans()), vulnSpans)
}

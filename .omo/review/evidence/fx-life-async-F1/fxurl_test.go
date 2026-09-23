// Phase-3 reproducer (fx-life-async-F1): URL.Query taint behind stdlib sub-routing.

package testapp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestFxURLQueryBehindStdlibRouting(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	type build func(seen *testapp.FxObservation) (http.Handler, string)
	cases := []struct {
		name  string
		build build
	}{
		{"control: ServeMux, URL.Query", func(seen *testapp.FxObservation) (http.Handler, string) {
			mux := http.NewServeMux()
			mux.Handle("/items", testapp.FxItemsByQuery(db, seen))
			return mux, "/items"
		}},
		{"ServeMux + http.StripPrefix sub-router, URL.Query", func(seen *testapp.FxObservation) (http.Handler, string) {
			api := http.NewServeMux()
			api.Handle("/items", testapp.FxItemsByQuery(db, seen))
			mux := http.NewServeMux()
			mux.Handle("/api/", http.StripPrefix("/api", api))
			return mux, "/api/items"
		}},
		{"ServeMux + http.StripPrefix sub-router, FormValue", func(seen *testapp.FxObservation) (http.Handler, string) {
			api := http.NewServeMux()
			api.Handle("/items", testapp.FxItemsByForm(db, seen))
			mux := http.NewServeMux()
			mux.Handle("/api/", http.StripPrefix("/api", api))
			return mux, "/api/items"
		}},
		{"Request.Clone middleware, URL.Query", func(seen *testapp.FxObservation) (http.Handler, string) {
			return testapp.FxCloneMiddleware(testapp.FxItemsByQuery(db, seen)), "/items"
		}},
		{"http.TimeoutHandler (shallow copy, same *URL), URL.Query", func(seen *testapp.FxObservation) (http.Handler, string) {
			return http.TimeoutHandler(testapp.FxItemsByQuery(db, seen), 10e9, "timeout"), "/items"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mt := mocktracer.Start()
			defer mt.Stop()
			var seen testapp.FxObservation
			app, path := tc.build(&seen)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				span, ctx := tracer.StartSpanFromContext(r.Context(), "web.request")
				defer span.Finish()
				app.ServeHTTP(w, r.WithContext(ctx))
			}))
			defer srv.Close()
			resp, err := srv.Client().Get(srv.URL + path + "?" + url.Values{"name": {"widget' OR '1'='1"}}.Encode())
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			sqli := 0
			for _, s := range mt.FinishedSpans() {
				raw, _ := s.Tag(spans.SpanTagJson).(string)
				if raw == "" {
					continue
				}
				var ev model.Event
				if err := json.Unmarshal([]byte(raw), &ev); err != nil {
					t.Fatal(err)
				}
				for _, v := range ev.Vulnerabilities {
					if v.Type == constants.VulnerabilityTypeSqlInjection {
						sqli++
					}
				}
			}
			t.Logf("FX (in-request) status=%d value=%q valueTainted=%v rawQueryTainted=%v queryTainted=%v SQLi_reported=%d",
				resp.StatusCode, seen.Value, seen.ValueTainted, seen.RawQueryTainted, seen.QueryTainted, sqli)
			if sqli != 1 {
				t.Errorf("FALSE NEGATIVE: SQLi from ?name= reported %d times, want 1", sqli)
			}
		})
	}
}

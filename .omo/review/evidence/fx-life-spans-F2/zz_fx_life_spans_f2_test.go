// Independent phase-3 reproducer for life-spans-F2 / life-spans-F3 (woven build).
// Everything below goes through the real woven surfaces: the net/http
// serverHandler scope aspect, the woven tracer.StartSpanFromContext wrapper
// (iasthttp.BindStartSpan), the woven Span.Finish prologue (spans.Finished) and
// the woven database/sql ExecContext sink. No internal IAST API is called to
// drive the scenario; spans.ExistingForSpan is only used to observe the store.

package testapp_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

const fxQuery = "SELECT * FROM users WHERE id = 1 OR 1=1"

func fxGet(t *testing.T, server *httptest.Server) {
	t.Helper()
	resp, err := server.Client().Get(server.URL + "/?" + url.Values{"q": {fxQuery}}.Encode())
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
}

// TestFxLateBindAfterRootFinish: customer handler that creates its own root
// span (the repository's own e2e harness pattern), finishes it, then keeps
// working with the context derived from that span.
func TestFxLateBindAfterRootFinish(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	for _, mode := range []string{"control-before-finish", "control-after-finish-no-new-span", "late-child-span-after-finish"} {
		t.Run(mode, func(t *testing.T) {
			mock := mocktracer.Start()
			defer mock.Stop()
			rootCh := make(chan *tracer.Span, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query().Get("q")
				root, ctx := tracer.StartSpanFromContext(r.Context(), "handler.root")
				if mode == "control-before-finish" {
					_, _ = db.ExecContext(ctx, q)
				}
				root.Finish()
				switch mode {
				case "control-after-finish-no-new-span":
					_, _ = db.ExecContext(ctx, q)
				case "late-child-span-after-finish":
					child, childCtx := tracer.StartSpanFromContext(ctx, "late.child")
					_, _ = db.ExecContext(childCtx, q)
					child.Finish()
				}
				rootCh <- root
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			fxGet(t, server)
			root := <-rootCh

			total := 0
			for _, s := range mock.FinishedSpans() {
				raw, _ := s.Tag(spans.SpanTagJson).(string)
				n := 0
				if raw != "" {
					var event model.Event
					require.NoError(t, json.Unmarshal([]byte(raw), &event))
					n = len(event.Vulnerabilities)
				}
				total += n
				t.Logf("finished span=%q enabled=%v vulnerabilities=%d", s.OperationName(), s.Tag(spans.SpanTagEnabled), n)
			}
			_, zombie, open := spans.ExistingForSpan(root)
			held := 0
			if open {
				zombie.RLock()
				held = len(zombie.Vulnerabilities)
				zombie.RUnlock()
			}
			t.Logf("mode=%s emitted vulnerabilities=%d; open annotation still stored for finished root=%t holding %d vulnerabilities", mode, total, open, held)
			if total == 0 {
				t.Errorf("BUG(%s): SQLi on a tainted request parameter was committed=%t but no finished span carries an IAST event", mode, held > 0)
			}
		})
	}
}

// TestFxDoubleFinishRace: same handler shape plus the common
// `defer span.Finish()` safety net, against a real tracer whose (fake) agent
// advertises meta_struct support, as current Datadog agents do.
func TestFxDoubleFinishRace(t *testing.T) {
	requireWoven(t)
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"endpoints":["/v0.4/traces"],"span_meta_structs":true,"client_drop_p0s":false}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer agent.Close()
	require.NoError(t, tracer.Start(tracer.WithAgentURL(agent.URL), tracer.WithLogStartup(false), tracer.WithService("fx-life-spans-f2")))
	defer tracer.Stop()
	probe := tracer.StartSpan("probe")
	t.Logf("real tracer meta_struct available = %t", probe.SetMetaStruct("probe", &model.Event{}))
	probe.Finish()

	db := openDB(t)
	done := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		root, ctx := tracer.StartSpanFromContext(r.Context(), "handler.root")
		defer func() {
			root.Finish() // safety-net second Finish: woven prologue runs spans.Finished again
			_, _, open := spans.ExistingForSpan(root)
			done <- fmt.Sprintf("after second Finish open annotation stored=%t", open)
		}()
		root.Finish() // explicit early Finish: trace chunk handed to the writer
		child, childCtx := tracer.StartSpanFromContext(ctx, "late.child")
		_, _ = db.ExecContext(childCtx, r.URL.Query().Get("q"))
		child.Finish()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for i := range 20 {
		fxGet(t, server)
		if msg := <-done; i == 0 {
			t.Log(msg)
		}
	}
	tracer.Flush()
}

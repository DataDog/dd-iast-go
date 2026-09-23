package testapp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

// Controls for TestFxDoubleFinishRace, same real tracer + meta_struct agent.
// mode "double-finish-no-late-bind": sink before the first Finish, then a second Finish.
// mode "single-finish-late-bind": late child + sink after Finish, no second Finish.
func fxRaceControl(t *testing.T, mode string) {
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
	require.NoError(t, tracer.Start(tracer.WithAgentURL(agent.URL), tracer.WithLogStartup(false), tracer.WithService("fx-ctl")))
	defer tracer.Stop()
	db := openDB(t)
	done := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { done <- struct{}{} }()
		root, ctx := tracer.StartSpanFromContext(r.Context(), "handler.root")
		q := r.URL.Query().Get("q")
		switch mode {
		case "double-finish-no-late-bind":
			_, _ = db.ExecContext(ctx, q)
			root.Finish()
			root.Finish()
		case "single-finish-late-bind":
			root.Finish()
			child, childCtx := tracer.StartSpanFromContext(ctx, "late.child")
			_, _ = db.ExecContext(childCtx, q)
			child.Finish()
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for range 20 {
		fxGet(t, server)
		<-done
	}
	tracer.Flush()
	t.Logf("control %s completed 20 requests", mode)
}

func TestFxCtlDoubleFinishNoLateBind(t *testing.T) { fxRaceControl(t, "double-finish-no-late-bind") }
func TestFxCtlSingleFinishLateBind(t *testing.T)   { fxRaceControl(t, "single-finish-late-bind") }

package testapp_test

// crash-race-hunt minimal reproducer: once a request's form is parsed,
// net/http's ParseForm is a read-only no-op, so a second ParseForm call can run
// concurrently with readers of r.Form/r.PostForm in plain Go without a race.
// The woven ParseForm advice unconditionally re-assigns r.Form and r.PostForm
// in a deferred closure, turning that into a data race.
//
// Woven:  go tool orchestrion go test -race -run TestRaceHuntParseFormReparse -count=1 -v .
// Plain:  RACEHUNT_PLAIN=1 go test -race -run TestRaceHuntParseFormReparse -count=1 -v .

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestRaceHuntParseFormReparse(t *testing.T) {
	if os.Getenv("RACEHUNT_PLAIN") != "1" {
		requireWoven(t)
	}
	t.Logf("woven=%v iastEnabled=%v", built.WithOrchestrion, config.Enabled)
	raceHuntParseFormReparse(t)
}

// Same, with IAST disabled at runtime: the advice still re-assigns the fields.
func TestRaceHuntParseFormReparseIASTDisabled(t *testing.T) {
	if os.Getenv("RACEHUNT_PLAIN") != "1" {
		requireWoven(t)
	}
	oldEnabled, oldPct := config.Enabled, config.RequestSamplingPct
	config.Enabled, config.RequestSamplingPct = false, 0
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct = oldEnabled, oldPct })
	t.Logf("woven=%v iastEnabled=%v", built.WithOrchestrion, config.Enabled)
	raceHuntParseFormReparse(t)
}

func raceHuntParseFormReparse(t *testing.T) {
	mock := mocktracer.Start()
	defer mock.Stop()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil { // first parse, single goroutine
			t.Error(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { // e.g. middleware/helper re-parsing defensively
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = r.ParseForm()
			}
		}()
		go func() { // concurrent reader of the already-parsed form
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_ = r.FormValue("id")
				_ = r.PostForm.Get("id")
			}
		}()
		wg.Wait()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	form := url.Values{"id": {"attacker-controlled"}}
	resp, err := http.Post(server.URL+"/?q=value", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

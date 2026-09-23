package http_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

// Handler parses once, then fans out workers that each "ensure parsed" and
// read the form. In plain Go every repeated parse is a documented no-op
// ("After one call to ParseMultipartForm, subsequent calls have no effect"),
// so this handler is race-free without IAST.
func fanOutHandler(t *testing.T, parse func(*http.Request) error, tainted *bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := parse(r); err != nil {
			t.Error(err)
		}
		*tainted = request.IsTaintedString(r.FormValue("field"))
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 200 {
					_ = parse(r)
					_ = r.FormValue("field")
					_ = r.Form["field"][0]
					_ = r.PostForm["field"][0]
				}
			}()
		}
		wg.Wait()
		_, _ = io.WriteString(w, "ok")
	}
}

func runFanOut(t *testing.T, parse func(*http.Request) error, body io.Reader, contentType string) {
	testConfig(t, 100, 1)
	var tainted bool
	server := httptest.NewServer(fanOutHandler(t, parse, &tainted))
	defer server.Close()
	resp, err := http.Post(server.URL+"/", contentType, body)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	t.Logf("WithOrchestrion=%v field tainted=%v", built.WithOrchestrion, tainted)
}

func TestFxRepeatedMultipartParseFanOut(t *testing.T) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("field", "attacker-input"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	runFanOut(t, func(r *http.Request) error { return r.ParseMultipartForm(1 << 20) }, &body, mw.FormDataContentType())
}

func TestFxRepeatedParseFormFanOut(t *testing.T) {
	runFanOut(t, func(r *http.Request) error { return r.ParseForm() },
		strings.NewReader("field=attacker-input"), "application/x-www-form-urlencoded")
}

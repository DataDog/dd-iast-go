package http_test

import (
	"bytes"
	"fmt"
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

// Each subtest runs a real woven net/http server. The handler parses the form
// once, then lets a helper goroutine read the already-parsed form while the
// handler goroutine re-calls the parse method. In uninstrumented net/http the
// repeated calls only read request fields, so this program is race-free.
func TestFxRepeatedParse(t *testing.T) {
	cases := []struct {
		name   string
		multi  bool
		sample int
		read   func(r *http.Request) string
		parse  func(r *http.Request) error
	}{
		{"MultipartFormValue", true, 100,
			func(r *http.Request) string { return r.FormValue("field") },
			func(r *http.Request) error { return r.ParseMultipartForm(1 << 20) }},
		{"MultipartPostFormValue", true, 100,
			func(r *http.Request) string { return r.PostFormValue("field") },
			func(r *http.Request) error { return r.ParseMultipartForm(1 << 20) }},
		{"MultipartValueField", true, 100,
			func(r *http.Request) string { return strings.Join(r.MultipartForm.Value["field"], ",") },
			func(r *http.Request) error { return r.ParseMultipartForm(1 << 20) }},
		{"URLEncodedParseForm", false, 100,
			func(r *http.Request) string { return r.FormValue("field") },
			func(r *http.Request) error { return r.ParseForm() }},
		// Sampled-out requests (70% under the default 30% sampling): no IAST
		// analysis, but the woven advice still assigns request fields.
		{"SampledOutMultipartValueField", true, 0,
			func(r *http.Request) string { return strings.Join(r.MultipartForm.Value["field"], ",") },
			func(r *http.Request) error { return r.ParseMultipartForm(1 << 20) }},
		{"SampledOutURLEncodedParseForm", false, 0,
			func(r *http.Request) string { return r.FormValue("field") },
			func(r *http.Request) error { return r.ParseForm() }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testConfig(t, tc.sample, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := tc.parse(r); err != nil {
					http.Error(w, err.Error(), 400)
					return
				}
				first := tc.read(r)
				tainted := request.IsTaintedString(first)
				var wg sync.WaitGroup
				wg.Add(1)
				go func() { // started after the first parse (happens-before via go stmt)
					defer wg.Done()
					for range 500 {
						_ = tc.read(r)
					}
				}()
				var perr error
				for range 500 {
					if err := tc.parse(r); err != nil {
						perr = err
						break
					}
				}
				wg.Wait()
				fmt.Fprintf(w, "woven=%v value=%q tainted=%v repeatErr=%v", built.WithOrchestrion, first, tainted, perr)
			}))
			defer srv.Close()
			var body bytes.Buffer
			ct := "application/x-www-form-urlencoded"
			if tc.multi {
				mw := multipart.NewWriter(&body)
				if err := mw.WriteField("field", "attacker-input"); err != nil {
					t.Fatal(err)
				}
				if err := mw.Close(); err != nil {
					t.Fatal(err)
				}
				ct = mw.FormDataContentType()
			} else {
				body.WriteString("field=attacker-input")
			}
			resp, err := http.Post(srv.URL+"/", ct, &body)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			out, _ := io.ReadAll(resp.Body)
			t.Logf("status=%d %s", resp.StatusCode, out)
			if resp.StatusCode != 200 {
				t.Fatalf("unexpected status")
			}
		})
	}
}

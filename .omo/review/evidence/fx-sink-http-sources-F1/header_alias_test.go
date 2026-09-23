package reviewhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/DataDog/dd-iast-go/iast/net/http"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestHeaderMapAliases(t *testing.T) {
	for _, seed := range []bool{false, true} {
		name := "empty"
		if seed {
			name = "eligible"
		}
		t.Run(name, func(t *testing.T) {
			// Given a caller retaining the same request header map.
			req := httptest.NewRequest(http.MethodGet, "/dispatch", nil)
			if seed {
				req.Header.Set("X-Input", "external-value")
			}
			alias := req.Header
			var received *http.Request
			var tainted bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received = r
				tainted = taint.IsTaintedString(r.Header.Get("X-Input"))
				r.Header.Set("X-Result", "visible")
				w.WriteHeader(http.StatusNoContent)
			})

			// When normal custom dispatch calls the public Handler interface.
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			// Then the handler's mutation remains visible through the alias.
			t.Logf("woven=%t request_copied=%t source_tainted=%t handler=%q caller=%q",
				built.WithOrchestrion, received != req, tainted,
				received.Header.Get("X-Result"), alias.Get("X-Result"))
			require.Equal(t, http.StatusNoContent, recorder.Code)
			require.Equal(t, "visible", alias.Get("X-Result"))
		})
	}
}

func TestHeaderValueSliceAliases(t *testing.T) {
	// Given an existing alias to a header's value slice.
	req := httptest.NewRequest(http.MethodGet, "/dispatch", nil)
	req.Header["X-Input"] = []string{"external-value"}
	alias := req.Header["X-Input"]
	var observed string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		r.Header["X-Input"][0] = "changed"
		observed = r.Header.Get("X-Input")
	})

	// When the handler updates an existing slice element.
	handler.ServeHTTP(httptest.NewRecorder(), req)

	// Then the retained slice sees the same mutation.
	t.Logf("woven=%t handler=%q caller_slice=%q", built.WithOrchestrion, observed, alias[0])
	require.Equal(t, "changed", alias[0])
}

// This is an observation probe, not a probabilistic regression assertion.
// Run with IAST environment variables unset. The two tests above use explicit
// 100% sampling for deterministic reproduction and 0% sampling as a control.
func TestDefaultSamplingObservation(t *testing.T) {
	var tainted, lost int
	for range 64 {
		req := httptest.NewRequest(http.MethodGet, "/dispatch", nil)
		req.Header.Set("X-Input", "external-value")
		alias := req.Header
		handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if taint.IsTaintedString(r.Header.Get("X-Input")) {
				tainted++
			}
			r.Header.Set("X-Result", "visible")
		})
		handler.ServeHTTP(httptest.NewRecorder(), req)
		if alias.Get("X-Result") != "visible" {
			lost++
		}
	}
	t.Logf("woven=%t default_requests=64 source_tainted=%d alias_lost=%d",
		built.WithOrchestrion, tainted, lost)
}

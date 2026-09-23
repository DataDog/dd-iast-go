package http_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
)

func TestReview_HeaderAliasReflectsHandlerMutation_whenFallbackTaintsRequest(t *testing.T) {
	testConfig(t, 100, 1)

	// Given a request whose header map is also retained by the caller.
	req := httptest.NewRequest(http.MethodGet, "/source", nil)
	req.Header.Set("X-Input", "attacker-value")
	originalHeaders := req.Header
	handler := func(_ http.ResponseWriter, incoming *http.Request) {
		// When the handler mutates the same logical request's headers.
		incoming.Header.Set("X-Result", "observed")
	}
	handler(httptest.NewRecorder(), req)

	// Then the original map alias sees that mutation, as in plain net/http.
	if got := originalHeaders.Get("X-Result"); got != "observed" {
		t.Fatalf("header map alias lost handler mutation: got %q, want %q", got, "observed")
	}
}

func TestReview_QueryValueRemainsClean_whenApplicationReplacesRequestQuery(t *testing.T) {
	testConfig(t, 100, 1)

	// Given an incoming request whose attacker-controlled query differs from
	// the application's trusted replacement.
	req := httptest.NewRequest(http.MethodGet, "/source?cmd=attacker-value", nil)
	handler := func(_ http.ResponseWriter, incoming *http.Request) {
		// When application code replaces the query before reading its values.
		incoming.URL.RawQuery = "cmd=trusted-value"
		value := incoming.URL.Query().Get("cmd")

		// Then the newly supplied literal must not inherit HTTP provenance.
		if value != "trusted-value" || taint.IsTaintedString(value) {
			t.Errorf("replaced query yielded value %q, tainted=%t; want clean trusted-value",
				value, taint.IsTaintedString(value))
		}
	}
	handler(httptest.NewRecorder(), req)
}

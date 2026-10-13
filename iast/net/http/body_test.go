// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package http_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type bodyResult struct {
	value   string
	tainted bool
}

// readBodyEndpoint reads the body with direct Read calls, and sends the
// result on results.
func readBodyEndpoint(results chan<- bodyResult) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		data := make([]byte, 64)
		n, _ := io.ReadFull(req.Body, data)
		data = data[:n]
		got := bodyResult{
			value:   string(data),
			tainted: taintedBytesFrom(req.Context(), data, taint.OriginHttpRequestBody),
		}
		results <- got
		w.WriteHeader(http.StatusNoContent)
	}
}

// TestExpectContinueBodyIsTainted checks that the entry registers the body
// inside the expectContinueReader of the server (plan section 4.4).
func TestExpectContinueBodyIsTainted(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	results := make(chan bodyResult, 1)
	server := httptest.NewServer(readBodyEndpoint(results))
	defer server.Close()

	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.ExpectContinueTimeout = 5 * time.Second
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("continued-body"))
	require.NoError(t, err)
	req.Header.Set("Expect", "100-continue")
	response, err := client.Do(req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	require.NoError(t, response.Body.Close())

	got := <-results
	require.Equal(t, "continued-body", got.value)
	require.True(t, got.tainted)
}

// TestClientResponseBodyIsNotTainted checks that the Read hook of the body
// type of net/http, which client responses also use, taints only the
// registered body of a request (risk R7).
func TestClientResponseBodyIsNotTainted(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 2)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "backend-response")
	}))
	defer backend.Close()

	type result struct {
		value   string
		anyBits bool
		body    bodyResult
	}
	results := make(chan result, 1)
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		data := make([]byte, 64)
		n, _ := io.ReadFull(req.Body, data)
		data = data[:n]
		got := result{body: bodyResult{
			value:   string(data),
			tainted: taintedBytesFrom(req.Context(), data, taint.OriginHttpRequestBody),
		}}
		// The client response body is a *body too, read while the request
		// owner is active.
		response, err := backend.Client().Get(backend.URL)
		if err == nil {
			buffer := make([]byte, 64)
			n, _ := io.ReadFull(response.Body, buffer)
			got.value = string(buffer[:n])
			got.anyBits = heapbits.AnyBytes(buffer[:n])
			_ = response.Body.Close()
		}
		results <- got
		w.WriteHeader(http.StatusNoContent)
	}))
	defer frontend.Close()

	response, err := frontend.Client().Post(frontend.URL, "text/plain", strings.NewReader("request-body"))
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	require.NoError(t, response.Body.Close())

	got := <-results
	require.Equal(t, "request-body", got.body.value)
	require.True(t, got.body.tainted, "the request body is tainted")
	require.Equal(t, "backend-response", got.value)
	require.False(t, got.anyBits, "a client response body is not tainted")
}

type queryResult struct {
	original, replaced           bool
	originalBits, replacedBits   bool
	originalValue, replacedValue string
}

// TestReplacedURLIsNotARequestURL checks plan section 6.5: only the URL
// object of the request entry has the owner of the request. A URL that the
// application puts in its place is not a request source.
func TestReplacedURLIsNotARequestURL(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	results := make(chan queryResult, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var got queryResult
		original := req.URL.Query()
		got.originalValue = original.Get("query")
		got.original = taintedFrom(req.Context(), got.originalValue, taint.OriginHttpRequestParameter)
		got.originalBits = heapbits.AnyString(got.originalValue)
		replacement, err := url.Parse("/other?query=" + strings.Repeat("v", 8))
		if err == nil {
			req.URL = replacement
			got.replacedValue = req.URL.Query().Get("query")
			got.replaced = taintedFrom(req.Context(), got.replacedValue, taint.OriginHttpRequestParameter)
			got.replacedBits = heapbits.AnyString(got.replacedValue)
		}
		results <- got
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	response, err := server.Client().Get(server.URL + "/source?query=attacker")
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	require.NoError(t, response.Body.Close())

	got := <-results
	require.Equal(t, "attacker", got.originalValue)
	require.True(t, got.original)
	require.True(t, got.originalBits)
	require.Equal(t, "vvvvvvvv", got.replacedValue)
	require.False(t, got.replaced)
	require.False(t, got.replacedBits)
}

// TestURLQueryWithoutRequestIsUnchanged checks that URL.Query outside of a
// request returns the parsed values without taint.
func TestURLQueryWithoutRequestIsUnchanged(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	u, err := url.Parse("/path?name=value-of-name")
	require.NoError(t, err)
	values := u.Query()
	require.Equal(t, url.Values{"name": {"value-of-name"}}, values)
	require.False(t, heapbits.AnyString(values.Get("name")))
}

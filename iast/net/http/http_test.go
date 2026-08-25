// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package http_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var upgradeObserved chan observation

type observation struct {
	HasScope             bool             `json:"has_scope"`
	SourceCountAtHandler int              `json:"source_count_at_handler"`
	SourceCountAfterLazy int              `json:"source_count_after_lazy"`
	Active               bool             `json:"active"`
	Entry                request.Entry    `json:"entry"`
	Decision             request.Decision `json:"decision"`
	Tainted              bool             `json:"tainted"`
	RequestURITainted    bool             `json:"request_uri_tainted"`
	PathTainted          bool             `json:"path_tainted"`
	QueryTainted         bool             `json:"query_tainted"`
	HeaderNameTainted    bool             `json:"header_name_tainted"`
	HeaderTainted        bool             `json:"header_tainted"`
	LiteralTainted       bool             `json:"literal_tainted"`
	BodyBound            bool             `json:"body_bound"`
	QueryNameTainted     bool             `json:"query_name_tainted"`
	QueryValueTainted    bool             `json:"query_value_tainted"`
	FormNameTainted      bool             `json:"form_name_tainted"`
	FormValueTainted     bool             `json:"form_value_tainted"`
	PostFormTainted      bool             `json:"post_form_tainted"`
	PathValueTainted     bool             `json:"path_value_tainted"`
	CookieNameTainted    bool             `json:"cookie_name_tainted"`
	CookieValueTainted   bool             `json:"cookie_value_tainted"`
}

func tracedEndpoint(w http.ResponseWriter, req *http.Request) {
	req.SetPathValue("user", "alice")
	span, spanCtx := tracer.StartSpanFromContext(req.Context(), "iast.http.request")
	defer span.Finish()
	boundEndpoint(w, req.WithContext(spanCtx))
}

func boundEndpoint(w http.ResponseWriter, req *http.Request) {
	scope := request.FromContext(req.Context())
	got := observation{HasScope: scope != nil}
	if scope != nil {
		got.Active = scope.Active()
		got.Entry = scope.Entry()
		got.Decision = scope.Decision()
		if analysis, ok := scope.Analysis(); ok {
			got.SourceCountAtHandler = analysis.SourceCount()
		}
	}
	got.RequestURITainted = taint.IsTaintedString(req.RequestURI)
	if req.URL != nil {
		got.PathTainted = taint.IsTaintedString(req.URL.Path)
		got.QueryTainted = taint.IsTaintedString(req.URL.RawQuery)
	}
	for name, values := range req.Header {
		if name == "Content-Type" {
			got.HeaderNameTainted = taint.IsTaintedString(name)
			if len(values) != 0 {
				got.HeaderTainted = taint.IsTaintedString(values[0])
			}
		}
	}
	got.LiteralTainted = taint.IsTaintedString("Content-Type")
	var bodyOwners [1]store.OwnerRef
	got.BodyBound = request.LookupObject(req.Body, store.BindingReader, bodyOwners[:]) == 1
	for range 100 {
		query := req.URL.Query()
		for name, values := range query {
			if name == "query" {
				got.QueryNameTainted = taintedFrom(name, taint.OriginHttpRequestParameterName)
				if len(values) != 0 {
					got.QueryValueTainted = taintedFrom(values[0], taint.OriginHttpRequestParameter)
				}
			}
		}
	}
	for range 100 {
		_ = req.ParseForm()
		for name, values := range req.Form {
			if name == "form" {
				got.FormNameTainted = taintedFrom(name, taint.OriginHttpRequestParameterName)
				if len(values) != 0 {
					got.FormValueTainted = taintedFrom(values[0], taint.OriginHttpRequestParameter)
				}
			}
		}
		got.PostFormTainted = taintedFrom(req.PostFormValue("form"), taint.OriginHttpRequestParameter)
		got.PathValueTainted = taintedFrom(req.PathValue("user"), taint.OriginHttpRequestPathParameter)
		if cookie, err := req.Cookie("session"); err == nil {
			got.CookieNameTainted = taintedFrom(cookie.Name, taint.OriginHttpRequestCookieName)
			got.CookieValueTainted = taintedFrom(cookie.Value, taint.OriginHttpRequestCookieValue)
		}
		_ = req.Cookies()
		_ = req.CookiesNamed("session")
	}
	if analysis, ok := scope.Analysis(); ok {
		got.SourceCountAfterLazy = analysis.SourceCount()
	}
	managed := taint.TaintString(req.Context(), taint.Source{
		Origin: taint.OriginHttpRequestParameter,
		Name:   "q",
	}, "attacker")
	got.Tainted = taint.IsTaintedString(managed)
	_ = json.NewEncoder(w).Encode(got)
}

func directEndpoint(w http.ResponseWriter, req *http.Request) {
	boundEndpoint(w, req)
}

type expectedScopeKey struct{}

func nestedOuterEndpoint(w http.ResponseWriter, req *http.Request) {
	scope := request.FromContext(req.Context())
	ctx := context.WithValue(req.Context(), expectedScopeKey{}, scope)
	nestedInnerEndpoint(w, req.WithContext(ctx))
}

func nestedInnerEndpoint(w http.ResponseWriter, req *http.Request) {
	scope := request.FromContext(req.Context())
	expected, _ := req.Context().Value(expectedScopeKey{}).(*request.Scope)
	_ = json.NewEncoder(w).Encode(scope != nil && scope == expected && scope.Entry() == request.EntryFallback)
}

func panicEndpoint(http.ResponseWriter, *http.Request) {
	panic("expected test panic")
}

func nilRequestHelper(http.ResponseWriter, *http.Request) {}

func nonHandlerHelper(_ http.ResponseWriter, req *http.Request, _ string) bool {
	return request.FromContext(req.Context()) != nil
}

func immediateBindingEndpoint(w http.ResponseWriter, req *http.Request) {
	span, _ := tracer.StartSpanFromContext(req.Context(), "iast.immediate-binding")
	span.Finish()
	_ = json.NewEncoder(w).Encode(true)
}

func upgradeEndpoint(w http.ResponseWriter, req *http.Request) {
	scope := request.FromContext(req.Context())
	got := observation{HasScope: scope != nil}
	if scope != nil {
		got.Active = scope.Active()
		got.Entry = scope.Entry()
		got.Decision = scope.Decision()
		if analysis, ok := scope.Analysis(); ok {
			got.SourceCountAtHandler = analysis.SourceCount()
		}
	}
	managed := taint.TaintString(req.Context(), taint.Source{Origin: taint.OriginHttpRequestParameter}, "upgrade")
	got.Tainted = taint.IsTaintedString(managed)
	upgradeObserved <- got
	w.WriteHeader(http.StatusNoContent)
}

func taintedFrom(value string, origin taint.Origin) bool {
	found := false
	taint.VisitString(value, func(r taint.Range) bool {
		found = found || r.Source.Origin == origin
		return !found
	})
	return found
}

type multipartObservation struct {
	NameTainted      bool `json:"name_tainted"`
	ValueTainted     bool `json:"value_tainted"`
	FormValueTainted bool `json:"form_value_tainted"`
	FirstSourceCount int  `json:"first_source_count"`
	SourceCount      int  `json:"source_count"`
}

func multipartEndpoint(w http.ResponseWriter, req *http.Request) {
	got := multipartObservation{}
	for iteration := range 100 {
		_ = req.ParseMultipartForm(1 << 20)
		if req.MultipartForm == nil {
			continue
		}
		for name, values := range req.MultipartForm.Value {
			if name == "upload-field" {
				got.NameTainted = taintedFrom(name, taint.OriginHttpRequestMultipartParameter)
				if len(values) != 0 {
					got.ValueTainted = taintedFrom(values[0], taint.OriginHttpRequestMultipartParameter)
				}
			}
		}
		got.FormValueTainted = taintedFrom(req.FormValue("upload-field"), taint.OriginHttpRequestMultipartParameter)
		if iteration == 0 {
			if scope := request.FromContext(req.Context()); scope != nil {
				if analysis, ok := scope.Analysis(); ok {
					got.FirstSourceCount = analysis.SourceCount()
				}
			}
		}
	}
	if scope := request.FromContext(req.Context()); scope != nil {
		if analysis, ok := scope.Analysis(); ok {
			got.SourceCount = analysis.SourceCount()
		}
	}
	_ = json.NewEncoder(w).Encode(got)
}

func weakBeforeBindingEndpoint(w http.ResponseWriter, req *http.Request) {
	span, spanCtx := tracer.StartSpanFromContext(req.Context(), "iast.weak-before-binding")
	vulnerability.Report(spanCtx, constants.VulnerabilityTypeWeakHash, "MD5", nil, vulnerability.SkipFrame{})
	managed := taint.TaintString(spanCtx, taint.Source{Origin: taint.OriginHttpRequestParameter}, "attacker")
	_ = json.NewEncoder(w).Encode(taint.IsTaintedString(managed))
	span.Finish()
}

func testConfig(t *testing.T, sampling, maxConcurrent int) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = sampling
	config.MaxConcurrentRequests = maxConcurrent
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
}

func getObservation(t *testing.T, client *http.Client, url string) observation {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url+"/source?query=attacker", strings.NewReader("form=posted"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", "session=cookie-value")
	response, err := client.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	var got observation
	require.NoError(t, json.NewDecoder(response.Body).Decode(&got))
	_, _ = io.Copy(io.Discard, response.Body)
	return got
}

func requireActiveRequest(t *testing.T, got observation, entry request.Entry) {
	t.Helper()
	require.True(t, got.HasScope)
	require.True(t, got.Active)
	require.Equal(t, entry, got.Entry)
	require.Equal(t, request.DecisionActive, got.Decision)
	require.Greater(t, got.SourceCountAtHandler, 0)
	require.True(t, got.Tainted)
}

func TestDirectNestedAndPanicLifecycle(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)

	for range 2 {
		recorder := httptest.NewRecorder()
		directEndpoint(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		var got observation
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&got))
		require.True(t, got.Active)
		require.True(t, got.Tainted)
		require.Equal(t, request.EntryFallback, got.Entry)
	}

	nested := httptest.NewRecorder()
	nestedOuterEndpoint(nested, httptest.NewRequest(http.MethodGet, "/", nil))
	var reused bool
	require.NoError(t, json.NewDecoder(nested.Body).Decode(&reused))
	require.True(t, reused)

	func() {
		defer func() { require.Equal(t, "expected test panic", recover()) }()
		panicEndpoint(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	recorder := httptest.NewRecorder()
	directEndpoint(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	var afterPanic observation
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&afterPanic))
	require.True(t, afterPanic.Active, "panic unwind did not release the permit")
}

func TestFallbackIgnoresNilAndNonHandlerHelpers(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	require.NotPanics(t, func() { nilRequestHelper(httptest.NewRecorder(), nil) })
	require.False(t, nonHandlerHelper(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
		"extra",
	))
}

func TestSamplingAndCapacityDecisions(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 0, 1)
	recorder := httptest.NewRecorder()
	directEndpoint(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	var sampledOut observation
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&sampledOut))
	require.Equal(t, request.DecisionSampledOut, sampledOut.Decision)
	require.False(t, sampledOut.Active)
	require.False(t, sampledOut.Tainted)

	config.RequestSamplingPct = 100
	heldCtx, held, created := request.Begin(context.Background())
	require.True(t, created)
	require.True(t, held.Active())
	t.Cleanup(func() { request.FinishContext(heldCtx, true) })
	recorder = httptest.NewRecorder()
	directEndpoint(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	var capacity observation
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&capacity))
	require.Equal(t, request.DecisionCapacityDropped, capacity.Decision)
	require.False(t, capacity.Active)
	require.False(t, capacity.Tainted)
	held.Finish()

	config.Enabled = false
	recorder = httptest.NewRecorder()
	directEndpoint(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	var disabled observation
	require.NoError(t, json.NewDecoder(recorder.Body).Decode(&disabled))
	require.False(t, disabled.HasScope)
}

func TestSampledOutAndCapacitySpansAreTaggedDisabled(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 0, 1)

	assertTag := func(t *testing.T) {
		mockTracer := mocktracer.Start()
		defer mockTracer.Stop()
		server := httptest.NewServer(http.HandlerFunc(tracedEndpoint))
		defer server.Close()
		_ = getObservation(t, server.Client(), server.URL)
		finished := mockTracer.FinishedSpans()
		require.Len(t, finished, 1)
		require.Equal(t, 0.0, finished[0].Tag(spans.SpanTagEnabled))
	}

	t.Run("sampled-out", assertTag)
	config.RequestSamplingPct = 100
	heldCtx, held, created := request.Begin(context.Background())
	require.True(t, created)
	require.True(t, held.Active())
	t.Run("capacity", assertTag)
	request.FinishContext(heldCtx, true)
}

func TestStartSpanCallSiteBindsBeforeNextStatement(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	mockTracer := mocktracer.Start()
	defer mockTracer.Stop()
	server := httptest.NewServer(http.HandlerFunc(immediateBindingEndpoint))
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	require.NoError(t, err)
	var bound bool
	require.NoError(t, json.NewDecoder(response.Body).Decode(&bound))
	response.Body.Close()
	require.True(t, bound)
	finished := mockTracer.FinishedSpans()
	require.Len(t, finished, 1)
	require.Equal(t, 1.0, finished[0].Tag(spans.SpanTagEnabled))
}

func TestWeakFindingBeforeHandlerBindingReusesScope(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	mockTracer := mocktracer.Start()
	defer mockTracer.Stop()
	server := httptest.NewServer(http.HandlerFunc(weakBeforeBindingEndpoint))
	defer server.Close()

	response, err := server.Client().Get(server.URL)
	require.NoError(t, err)
	var tainted bool
	require.NoError(t, json.NewDecoder(response.Body).Decode(&tainted))
	response.Body.Close()
	require.True(t, tainted, "the weak finding consumed a competing permit")
	finished := mockTracer.FinishedSpans()
	require.Len(t, finished, 1, "weak finding created a competing orphan span")
	require.Equal(t, 1.0, finished[0].Tag(spans.SpanTagEnabled))
}

func TestH2CUpgradeDoesNotOwnConnectionScope(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	upgradeObserved = make(chan observation, 2)
	t.Cleanup(func() { upgradeObserved = nil })
	server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(upgradeEndpoint), new(http2.Server)))
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "GET /upgrade HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n", server.Listener.Addr().String())
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, status, "101")
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if line == "\r\n" {
			break
		}
	}
	_, err = io.WriteString(conn, http2.ClientPreface)
	require.NoError(t, err)
	framer := http2.NewFramer(conn, reader)
	require.NoError(t, framer.WriteSettings())
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	for {
		frame, err := framer.ReadFrame()
		require.NoError(t, err)
		if frame.Header().StreamID == 1 && frame.Header().Flags.Has(http2.FlagDataEndStream) {
			break
		}
	}
	upgrade := <-upgradeObserved
	requireActiveRequest(t, upgrade, request.EntryFallback)

	plain := getObservationFromUpgradeHandler(t, server.Client(), server.URL+"/plain")
	requireActiveRequest(t, plain, request.EntryServer)
}

func getObservationFromUpgradeHandler(t *testing.T, client *http.Client, url string) observation {
	t.Helper()
	response, err := client.Get(url)
	require.NoError(t, err)
	response.Body.Close()
	select {
	case got := <-upgradeObserved:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("handler observation timed out")
		return observation{}
	}
}

func TestMultipartValueSourcesAreIdempotent(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	require.NoError(t, writer.WriteField("upload-field", "multipart-value"))
	require.NoError(t, writer.Close())
	server := httptest.NewServer(http.HandlerFunc(multipartEndpoint))
	defer server.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/multipart", &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := server.Client().Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	var got multipartObservation
	require.NoError(t, json.NewDecoder(response.Body).Decode(&got))
	require.True(t, got.NameTainted)
	require.True(t, got.ValueTainted)
	require.True(t, got.FormValueTainted)
	// Eager URI/path/header sources plus one multipart name and value.
	require.GreaterOrEqual(t, got.SourceCount, 5)
	require.Equal(t, got.FirstSourceCount, got.SourceCount)
}

func TestServerProtocolsReleasePerRequest(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	testConfig(t, 100, 1)

	tests := []struct {
		name  string
		entry request.Entry
		serve func(t *testing.T, handler http.Handler) (*http.Client, string, func())
	}{
		{
			name:  "HTTP1",
			entry: request.EntryServer,
			serve: func(t *testing.T, handler http.Handler) (*http.Client, string, func()) {
				server := httptest.NewServer(handler)
				return server.Client(), server.URL, server.Close
			},
		},
		{
			name:  "TLS_HTTP2",
			entry: request.EntryServer,
			serve: func(t *testing.T, handler http.Handler) (*http.Client, string, func()) {
				server := httptest.NewUnstartedServer(handler)
				server.EnableHTTP2 = true
				server.StartTLS()
				return server.Client(), server.URL, server.Close
			},
		},
		{
			name:  "h2c",
			entry: request.EntryFallback,
			serve: func(t *testing.T, handler http.Handler) (*http.Client, string, func()) {
				server := httptest.NewServer(h2c.NewHandler(handler, new(http2.Server)))
				transport := &http2.Transport{
					AllowHTTP: true,
					DialTLSContext: func(ctx context.Context, network, address string, _ *tls.Config) (net.Conn, error) {
						return (&net.Dialer{}).DialContext(ctx, network, address)
					},
				}
				client := &http.Client{Transport: transport}
				return client, server.URL, func() {
					transport.CloseIdleConnections()
					server.Close()
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockTracer := mocktracer.Start()
			defer mockTracer.Stop()
			client, url, closeServer := test.serve(t, http.HandlerFunc(tracedEndpoint))
			defer closeServer()

			first := getObservation(t, client, url)
			second := getObservation(t, client, url)
			requireActiveRequest(t, first, test.entry)
			requireActiveRequest(t, second, test.entry)
			require.Equal(t, first.SourceCountAtHandler, second.SourceCountAtHandler)
			for _, got := range []observation{first, second} {
				require.True(t, got.RequestURITainted)
				require.True(t, got.PathTainted)
				require.True(t, got.QueryTainted)
				require.True(t, got.HeaderNameTainted)
				require.True(t, got.HeaderTainted)
				require.False(t, got.LiteralTainted)
				require.True(t, got.BodyBound)
				require.True(t, got.QueryNameTainted)
				require.True(t, got.QueryValueTainted)
				require.True(t, got.FormNameTainted)
				require.True(t, got.FormValueTainted)
				require.True(t, got.PostFormTainted)
				require.True(t, got.PathValueTainted)
				require.True(t, got.CookieNameTainted)
				require.True(t, got.CookieValueTainted)
				require.Equal(t, got.SourceCountAtHandler+7, got.SourceCountAfterLazy)
			}
			finished := mockTracer.FinishedSpans()
			require.Len(t, finished, 2)
			for _, span := range finished {
				require.Equal(t, 1.0, span.Tag(spans.SpanTagEnabled))
			}
		})
	}
}

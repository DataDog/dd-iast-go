// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// liveTimeout is the maximum time that the test waits for one request step.
const liveTimeout = 10 * time.Second

// liveServer serves HTTP requests that stay live until the test ends them.
// The test runs each step of a request in the handler goroutine of that
// request. Thus two or more requests can be live at the same time, in an
// order that the test controls.
type liveServer struct {
	t      *testing.T
	mock   mocktracer.Tracer
	server *httptest.Server

	mu       sync.Mutex
	requests map[string]*liveRequest
}

// liveRequest is one HTTP request of a liveServer. The fields ctx, w, r, and
// scope are set by the handler before it runs the first step. Read them only
// in a step, or after the first step.
type liveRequest struct {
	server *liveServer
	name   string
	steps  chan func()
	done   chan struct{}
	ended  chan error
	// closed is true when steps is closed. Only the test goroutine uses it.
	closed bool

	ctx   context.Context
	w     http.ResponseWriter
	r     *http.Request
	scope *taintrequest.Scope
}

// newLiveServer starts a mock tracer and an HTTP server. The cleanup of t
// stops them.
func newLiveServer(t *testing.T) *liveServer {
	t.Helper()
	live := &liveServer{t: t, requests: map[string]*liveRequest{}}
	live.mock = mocktracer.Start()
	live.server = httptest.NewServer(http.HandlerFunc(live.serve))
	t.Cleanup(func() {
		// A test that failed before it ended a request leaves its handler
		// in the step loop. End the loop, else Close waits for the handler.
		live.mu.Lock()
		for _, request := range live.requests {
			if !request.closed {
				request.closed = true
				close(request.steps)
			}
		}
		live.mu.Unlock()
		live.server.Close()
		live.mock.Stop()
	})
	return live
}

func (s *liveServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	request := s.requests[strings.TrimPrefix(r.URL.Path, "/")]
	s.mu.Unlock()
	if request == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.live/"+request.name)
	defer span.Finish()
	request.ctx, request.w, request.r = ctx, w, r.WithContext(ctx)
	request.scope = taintrequest.FromContext(ctx)
	for step := range request.steps {
		func() {
			// Always tell the test that the step is done, also when the
			// step stops its goroutine (for example with t.FailNow).
			defer func() { request.done <- struct{}{} }()
			step()
		}()
	}
	w.WriteHeader(http.StatusNoContent)
}

// start sends a POST request with body to the server, and waits until its
// handler runs. The request must be analyzed.
func (s *liveServer) start(name, body string) *liveRequest {
	s.t.Helper()
	request := &liveRequest{
		server: s,
		name:   name,
		steps:  make(chan func()),
		done:   make(chan struct{}, 1),
		ended:  make(chan error, 1),
	}
	s.mu.Lock()
	s.requests[name] = request
	s.mu.Unlock()
	go func() {
		response, err := s.server.Client().Post(s.server.URL+"/"+name, "application/json", strings.NewReader(body))
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			err = response.Body.Close()
		}
		request.ended <- err
	}()
	request.do(func() {})
	require.True(s.t, request.scope.Active(), "the request %s is not analyzed", name)
	return request
}

// do runs step in the handler goroutine of the request, and waits until the
// step is done. Use assert (not require) in a step.
func (r *liveRequest) do(step func()) {
	r.server.t.Helper()
	select {
	case r.steps <- step:
	case err := <-r.ended:
		r.server.t.Fatalf("the request %s ended before its step: %v", r.name, err)
	case <-time.After(liveTimeout):
		r.server.t.Fatalf("the request %s did not start its step", r.name)
	}
	select {
	case <-r.done:
	case <-time.After(liveTimeout):
		r.server.t.Fatalf("the step of the request %s did not end", r.name)
	}
}

// end ends the request, and waits until its analysis is finished.
func (r *liveRequest) end() {
	r.server.t.Helper()
	r.closed = true
	close(r.steps)
	select {
	case err := <-r.ended:
		require.NoError(r.server.t, err)
	case <-time.After(liveTimeout):
		r.server.t.Fatalf("the request %s did not end", r.name)
	}
	require.Eventually(r.server.t, func() bool { return !r.scope.Active() }, liveTimeout, time.Millisecond,
		"the analysis of the request %s did not finish", r.name)
}

// sourceCount returns the number of sources of the live request. Call it in
// a step or between steps.
func (r *liveRequest) sourceCount() int {
	analysis, ok := r.scope.Analysis()
	if !ok {
		return -1
	}
	return analysis.SourceCount()
}

// sink sends a query that contains value to the SQL sink of the test driver,
// in the request. Call it in a step.
func (r *liveRequest) sink(db *sql.DB, value string) {
	_, err := db.ExecContext(r.ctx, testapp.BuildTableQuery(value))
	assert.NoError(r.server.t, err)
}

// event returns the event of the request. Call it after end.
func (r *liveRequest) event() model.Event {
	r.server.t.Helper()
	for _, span := range r.server.mock.FinishedSpans() {
		if span.OperationName() != "iast.live/"+r.name {
			continue
		}
		raw, _ := span.Tag(spans.SpanTagJson).(string)
		if raw == "" {
			require.Equal(r.server.t, float64(1), span.Tag(spans.SpanTagEnabled), "the request %s was not analyzed", r.name)
			return model.Event{}
		}
		var event model.Event
		require.NoError(r.server.t, json.Unmarshal([]byte(raw), &event))
		return event
	}
	r.server.t.Fatalf("no span for the request %s", r.name)
	return model.Event{}
}

// bodyRange returns the one range of a string of length bytes with the body
// source value document.
func bodyRange(length int, document string) []taint.Range {
	return []taint.Range{{
		Length: uint32(length),
		Source: taint.SourceValue{Source: taint.Source{Origin: taint.OriginHttpRequestBody}, Value: document},
	}}
}

// requireSQLFindings checks that event has count SQL injection findings and
// no other finding. When count is not zero, the only source of event is the
// request body with the value document. When count is zero, event has no
// source.
func requireSQLFindings(t *testing.T, event model.Event, count int, document string) {
	t.Helper()
	require.Len(t, event.Vulnerabilities, count, "the findings of the request")
	if count == 0 {
		require.Empty(t, event.Sources)
		return
	}
	require.Equal(t, count, countType(event, constants.VulnerabilityTypeSqlInjection))
	require.Equal(t, []model.Source{model.NewSourceString(constants.OriginHttpRequestBody, "", document)}, event.Sources)
	assertSourcesReferenced(t, event)
}

// assertNoTaint checks that value has no taint of any request.
func assertNoTaint(t *testing.T, value string) {
	t.Helper()
	assert.False(t, taint.IsTaintedString(value), "the value %q is tainted", value)
}

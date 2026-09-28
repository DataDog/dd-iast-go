// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentRequestsSharingValueKeepOwnEvidence runs two concurrent
// requests. Request bravo gives its tainted parameter to request alpha and
// stays active. Request alpha puts the value of bravo into SQL queries. The
// event of alpha must contain only the source of alpha, and the query that
// contains only the value of bravo must not be reported.
func TestConcurrentRequestsSharingValueKeepOwnEvidence(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	mock := mocktracer.Start()
	defer mock.Stop()

	const timeout = 10 * time.Second
	foreign := make(chan string, 1)
	release := make(chan struct{})
	// Request alpha starts only after request bravo has its value. The
	// owner acquisition never waits: two requests that start at the same
	// time can cause one of them to not be analyzed.
	bravoReady := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.e2e"+r.URL.Path)
		defer span.Finish()
		value := r.URL.Query().Get(r.URL.Path[1:])
		switch r.URL.Path {
		case "/bravo":
			foreign <- value
			close(bravoReady)
			select {
			case <-release:
			case <-time.After(timeout):
				t.Error("request alpha did not release request bravo")
			}
		case "/alpha":
			defer close(release)
			var other string
			select {
			case other = <-foreign:
			case <-time.After(timeout):
				t.Error("request bravo did not share its value")
				return
			}
			_, err := db.ExecContext(ctx, testapp.BuildSharedQuery(value, other))
			assert.NoError(t, err)
			_, err = db.ExecContext(ctx, testapp.BuildForeignQuery(other))
			assert.NoError(t, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	get := func(path, value string) error {
		response, err := server.Client().Get(server.URL + path + "?" + url.Values{path[1:]: {value}}.Encode())
		if err != nil {
			return err
		}
		return response.Body.Close()
	}
	bravoDone := make(chan error, 1)
	go func() { bravoDone <- get("/bravo", "bravo-secret") }()
	select {
	case <-bravoReady:
	case err := <-bravoDone:
		t.Fatalf("request bravo ended before it shared its value: %v", err)
	case <-time.After(timeout):
		t.Fatal("request bravo did not share its value")
	}
	require.NoError(t, get("/alpha", "alpha-secret"))
	require.NoError(t, <-bravoDone)

	events := map[string]model.Event{}
	for _, span := range mock.FinishedSpans() {
		var event model.Event
		if raw, _ := span.Tag(spans.SpanTagJson).(string); raw != "" {
			require.NoError(t, json.Unmarshal([]byte(raw), &event))
		}
		events[span.OperationName()] = event
	}
	require.Contains(t, events, "iast.e2e/alpha")
	require.Contains(t, events, "iast.e2e/bravo")

	alpha := events["iast.e2e/alpha"]
	require.Equal(t, 1, countType(alpha, constants.VulnerabilityTypeSqlInjection), "only the shared query is tainted for alpha")
	// The SQL analyzer redacts literal values, so the source name identifies
	// the request.
	require.Len(t, alpha.Sources, 1)
	require.Equal(t, constants.OriginHttpRequestParameter, alpha.Sources[0].Origin)
	require.Equal(t, "alpha", alpha.Sources[0].Name)
	assertSourcesReferenced(t, alpha)
	require.Empty(t, events["iast.e2e/bravo"].Vulnerabilities)
	require.Empty(t, events["iast.e2e/bravo"].Sources)
}

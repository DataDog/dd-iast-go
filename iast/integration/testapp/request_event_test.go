// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

func captureRequestEvent(t *testing.T, operation func(context.Context, *http.Request), request *http.Request) model.Event {
	t.Helper()
	mock := mocktracer.Start()
	defer mock.Stop()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.e2e.request")
		defer span.Finish()
		operation(ctx, r.WithContext(ctx))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	request.URL.Scheme = "http"
	request.URL.Host = server.Listener.Addr().String()
	request.Host = request.URL.Host
	response, err := server.Client().Do(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	finished := mock.FinishedSpans()
	require.Len(t, finished, 1)
	raw, _ := finished[0].Tag(spans.SpanTagJson).(string)
	if raw == "" {
		require.Equal(t, float64(1), finished[0].Tag(spans.SpanTagEnabled), "request was not analyzed")
		return model.Event{}
	}
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(raw), &event))
	return event
}

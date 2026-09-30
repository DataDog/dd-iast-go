// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package http_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type closingReader struct{ strings.Reader }

func (*closingReader) Close() error { return nil }

// TestMaxBytesReaderOfExclusiveInputIsExclusive checks plan encoding-json-v2,
// section 6.5: a MaxBytesReader of an exclusive input is exclusive, because
// user code cannot retarget it.
func TestMaxBytesReaderOfExclusiveInputIsExclusive(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	otherCtx, other, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(other.Finish)

	body := &closingReader{}
	body.Reset("request-body")
	require.True(t, request.BindReader(ctx, body))
	limited := http.MaxBytesReader(httptest.NewRecorder(), body, 1024)
	_, _, ok := request.ReaderOwner(limited).Identity()
	require.True(t, ok)
	_, _ = limited.Read(make([]byte, 4))
	_, _, ok = request.ReaderOwner(limited).Identity()
	require.True(t, ok)

	// Rule (e): a second owner of the input removes the exclusivity of the
	// MaxBytesReader.
	require.True(t, request.BindReader(otherCtx, body))
	_, _, ok = request.ReaderOwner(limited).Identity()
	require.False(t, ok, "a MaxBytesReader of an input with two owners is exclusive")
	// The loss is sticky: it stays after the second owner ends (follow-up
	// review 1 of batch 1, finding 1).
	_, _ = limited.Read(make([]byte, 4))
	other.Finish()
	require.Equal(t, 1, request.LookupObject(body, store.BindingReader, make([]store.OwnerRef, 4)),
		"the input has one owner again")
	_, _, ok = request.ReaderOwner(body).Identity()
	require.False(t, ok, "the loss of the input is sticky too (rule (f))")
	_, _, ok = request.ReaderOwner(limited).Identity()
	require.False(t, ok, "a MaxBytesReader of an input that had a second owner is exclusive")

	otherCtx, other, created = request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(other.Finish)
	shared := &closingReader{}
	shared.Reset("shared")
	require.True(t, request.BindReader(ctx, shared))
	require.True(t, request.BindReader(otherCtx, shared))
	_, _, ok = request.ReaderOwner(http.MaxBytesReader(httptest.NewRecorder(), shared, 1024)).Identity()
	require.False(t, ok, "a MaxBytesReader of a reader with two owners is exclusive")
}

// TestRequestBodyIsExclusiveAtEntry checks that the HTTP entry binds the
// request body exclusively (plan encoding-json-v2, section 6.5, rule (a)).
func TestRequestBodyIsExclusiveAtEntry(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	previousEnabled, previousSampling, previousMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = previousEnabled, previousSampling, previousMax
	})
	observed := make(chan [2]bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _, body := request.ReaderOwner(req.Body).Identity()
		_, _, limited := request.ReaderOwner(http.MaxBytesReader(w, req.Body, 1024)).Identity()
		observed <- [2]bool{body, limited}
	}))
	t.Cleanup(server.Close)
	response, err := http.Post(server.URL, "text/plain", strings.NewReader("request-body"))
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, response.Body)
	require.NoError(t, response.Body.Close())
	require.Equal(t, [2]bool{true, true}, <-observed)
}

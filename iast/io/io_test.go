// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package io_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

var errRead = errors.New("read failure")

type errorReader struct {
	data  []byte
	reads int
}

func (r *errorReader) Read(dst []byte) (int, error) {
	r.reads++
	if r.data == nil {
		return 0, errRead
	}
	n := copy(dst, r.data)
	r.data = nil
	return n, errRead
}

func activeContext(t *testing.T) (context.Context, *request.Scope) {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	return ctx, scope
}

func bodySource(data []byte) (taint.SourceValue, bool) {
	var source taint.SourceValue
	found := false
	taint.VisitBytes(data, func(r taint.Range) bool {
		if r.Source.Origin == taint.OriginHttpRequestBody {
			source = r.Source
			found = true
			return false
		}
		return true
	})
	return source, found
}

func TestReadAllThroughSupportedWrappers(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx, _ := activeContext(t)
	input := &errorReader{data: []byte("request-body")}
	require.True(t, request.BindReader(ctx, input))
	limited := io.LimitReader(input, 1024)
	var side bytes.Buffer
	tee := io.TeeReader(limited, &side)
	multi := io.MultiReader(strings.NewReader(""), tee)
	buffered := bufio.NewReaderSize(multi, 32)

	data, err := io.ReadAll(buffered)
	require.ErrorIs(t, err, errRead)
	require.Equal(t, []byte("request-body"), data)
	require.Equal(t, "request-body", side.String())
	require.Equal(t, 1, input.reads, "ReadAll must not add reads")
	source, found := bodySource(data)
	require.True(t, found)
	require.Equal(t, "request-body", source.Value)
}

func TestOversizedBufferedReaderDropsProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx, _ := activeContext(t)
	input := bytes.NewReader([]byte("request-body"))
	require.True(t, request.BindReader(ctx, input))
	data, err := io.ReadAll(bufio.NewReaderSize(input, 8192))
	require.NoError(t, err)
	_, found := bodySource(data)
	require.False(t, found)
}

func TestReadAllBodySizeBound(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, test := range []struct {
		size    int
		tainted bool
	}{
		{size: 0, tainted: false},
		{size: 1, tainted: false},
		{size: 2, tainted: true},
		{size: 1024, tainted: true},
		{size: store.MaxRootBytes - 1, tainted: true},
		{size: store.MaxRootBytes, tainted: true},
		{size: store.MaxRootBytes + 1, tainted: false},
	} {
		t.Run(fmt.Sprint(test.size), func(t *testing.T) {
			ctx, _ := activeContext(t)
			input := bytes.NewReader(bytes.Repeat([]byte{'x'}, test.size))
			require.True(t, request.BindReader(ctx, input))
			data, err := io.ReadAll(input)
			require.NoError(t, err)
			require.Len(t, data, test.size)
			_, tainted := bodySource(data)
			require.Equal(t, test.tainted, tainted)
		})
	}
}

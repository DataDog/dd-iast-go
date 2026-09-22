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
	data     []byte
	terminal error
	reads    int
}

func (r *errorReader) Read(dst []byte) (int, error) {
	r.reads++
	if r.data == nil {
		return 0, r.terminal
	}
	n := copy(dst, r.data)
	r.data = nil
	return n, r.terminal
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

func requireBodyRange(t *testing.T, data []byte, sourceValue string) {
	t.Helper()
	var observed []taint.Range
	require.True(t, taint.VisitBytes(data, func(r taint.Range) bool {
		observed = append(observed, r)
		return true
	}))
	require.Equal(t, []taint.Range{{
		Start:  0,
		Length: uint32(len(data)),
		Source: taint.SourceValue{
			Source: taint.Source{Origin: taint.OriginHttpRequestBody},
			Value:  sourceValue,
		},
		Marks: taint.Marks{},
	}}, observed)
}

func TestReadAllThroughSupportedWrappers(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx, _ := activeContext(t)
	input := &errorReader{data: []byte("request-body"), terminal: errRead}
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
	require.False(t, taint.IsTaintedString(side.String()), "TeeReader must not bind its side writer")
	require.Equal(t, 1, input.reads, "ReadAll must not add reads")
	requireBodyRange(t, data, "request-body")
}

func TestMultiReaderInspectionBoundAndCleanup(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	includedCtx, includedScope := activeContext(t)
	excludedCtx, excludedScope := activeContext(t)
	readers := make([]io.Reader, 9)
	for index := range 7 {
		readers[index] = strings.NewReader("")
	}
	included := strings.NewReader("included-")
	excluded := strings.NewReader("excluded")
	readers[7] = included
	readers[8] = excluded
	require.True(t, request.BindReader(includedCtx, included))
	require.True(t, request.BindReader(excludedCtx, excluded))

	composed := io.MultiReader(readers...)
	data, err := io.ReadAll(composed)
	require.NoError(t, err)
	require.Equal(t, []byte("included-excluded"), data)
	requireBodyRange(t, data, "included-excluded")
	includedAnalysis, ok := includedScope.Analysis()
	require.True(t, ok)
	require.Equal(t, 1, includedAnalysis.SourceCount())
	excludedAnalysis, ok := excludedScope.Analysis()
	require.True(t, ok)
	require.Zero(t, excludedAnalysis.SourceCount(), "the ninth reader is outside MultiReader's inspection bound")

	includedScope.Finish()
	require.Nil(t, request.CloneReaderBytes(composed, []byte("after")), "finishing the only included owner must remove the composed binding")
	excludedScope.Finish()
}

func TestReadAllEOFWithData(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx, _ := activeContext(t)
	input := &errorReader{data: []byte("request-body"), terminal: io.EOF}
	require.True(t, request.BindReader(ctx, input))
	data, err := io.ReadAll(input)
	require.NoError(t, err)
	require.Equal(t, []byte("request-body"), data)
	require.Equal(t, 1, input.reads)
	_, found := bodySource(data)
	require.True(t, found)
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

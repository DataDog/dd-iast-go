// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"context"
	"testing"
	"unicode"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func activeBytes(t *testing.T, value []byte) []byte {
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
	return taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"}, value)
}

func requireTaintedBytes(t *testing.T, values ...[]byte) {
	t.Helper()
	for _, value := range values {
		if len(value) == 0 {
			continue
		}
		var observed []taint.Range
		require.Truef(t, taint.VisitBytes(value, func(r taint.Range) bool {
			observed = append(observed, r)
			return true
		}), "value %q is not tainted", value)
		require.Len(t, observed, 1)
		require.Zero(t, observed[0].Start)
		require.Equal(t, uint32(len(value)), observed[0].Length)
		require.Equal(t, taint.OriginHttpRequestBody, observed[0].Source.Origin)
	}
}

func TestByteWindowOperations(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	value := activeBytes(t, []byte("  alpha,beta,omega  "))
	requireTaintedBytes(t, testapp.BytesClone(value))
	before, after, found := testapp.BytesCut(value, []byte(","))
	require.True(t, found)
	requireTaintedBytes(t, before, after)
	withoutPrefix, found := testapp.BytesCutPrefix(value, []byte("  "))
	require.True(t, found)
	withoutSuffix, found := testapp.BytesCutSuffix(value, []byte("  "))
	require.True(t, found)
	requireTaintedBytes(t, withoutPrefix, withoutSuffix)
	requireTaintedBytes(t, testapp.BytesSplit(value, []byte(","))...)
	requireTaintedBytes(t, testapp.BytesSplitN(value, []byte(","), 2)...)
	requireTaintedBytes(t, testapp.BytesSplitAfter(value, []byte(","))...)
	requireTaintedBytes(t, testapp.BytesSplitAfterN(value, []byte(","), 2)...)
	requireTaintedBytes(t, testapp.BytesFields(value)...)
	requireTaintedBytes(t, testapp.BytesFieldsFunc(value, unicode.IsSpace)...)
	requireTaintedBytes(t,
		testapp.BytesTrim(value, " "),
		testapp.BytesTrimSpace(value),
		testapp.BytesTrimLeft(value, " "),
		testapp.BytesTrimRight(value, " "),
		testapp.BytesTrimPrefix(value, []byte("  ")),
		testapp.BytesTrimSuffix(value, []byte("  ")),
		testapp.BytesTrimFunc(value, unicode.IsSpace),
		testapp.BytesTrimLeftFunc(value, unicode.IsSpace),
		testapp.BytesTrimRightFunc(value, unicode.IsSpace),
	)
}

func TestValidUTF8IgnoresUnusedReplacement(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	replacement := activeBytes(t, []byte("??"))
	result := testapp.BytesToValidUTF8([]byte("valid"), replacement)
	require.False(t, taint.IsTaintedBytes(result))
}

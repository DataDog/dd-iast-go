// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func requireWriterRange(t *testing.T, value string, start, length uint32) {
	t.Helper()
	var observed []taint.Range
	require.True(t, taint.VisitString(value, func(r taint.Range) bool {
		observed = append(observed, r)
		return true
	}))
	require.Len(t, observed, 1)
	require.Equal(t, start, observed[0].Start)
	require.Equal(t, length, observed[0].Length)
}

func TestBuilderAndBufferPropagation(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	input := activeString(t, "attack")
	builder := testapp.BuilderString(input)
	require.Equal(t, "prefix:attack!", builder)
	requireWriterRange(t, builder, 7, 6)
	buffer := testapp.BufferString(input)
	require.Equal(t, "prefix:attack!", buffer)
	requireWriterRange(t, buffer, 7, 6)

	byteInput := activeBytes(t, []byte("bytes"))
	requireWriterRange(t, testapp.BuilderBytes(byteInput), 0, 5)
	requireWriterRange(t, testapp.BufferBytes(byteInput), 0, 5)
}

func TestWriterResetTruncateAndIndirectMutation(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	input := activeString(t, "attack")
	require.False(t, taint.IsTaintedString(testapp.BuilderReset(input)))
	require.False(t, taint.IsTaintedString(testapp.BufferReset(input)))
	truncated := testapp.BufferTruncate(input)
	require.Equal(t, "at", truncated)
	requireWriterRange(t, truncated, 0, 2)

	// Method values and mutable buffer access bypass call-site wrappers. The
	// bytes function-body invalidator drops stale state before each mutation.
	require.False(t, taint.IsTaintedString(testapp.BufferIndirectRead(input)))
	require.False(t, taint.IsTaintedString(testapp.BufferBytesMutation(input)))
	requireWriterRange(t, testapp.BufferGrow(input), 0, uint32(len(input)))
}

func TestNilBufferStringPreservesHostBehavior(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	_ = activeString(t, "activate")
	require.Equal(t, "<nil>", testapp.NilBufferString())
}

func TestBufferWrapperPreservesPanic(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	require.Panics(t, testapp.BufferInvalidTruncate)
}

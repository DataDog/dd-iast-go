// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestWriterAdmissionLimitsKeepNativeResults(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	t.Run("builder", func(t *testing.T) {
		input := activeString(t, "attack")
		for index := range store.MaxWriters + 1 {
			writer := new(strings.Builder)
			n, err := writer.WriteString(input)
			require.NoError(t, err)
			require.Equal(t, len(input), n)
			requireWriterCapacityResult(t, index, writer.String())
		}
	})
	t.Run("buffer", func(t *testing.T) {
		input := activeString(t, "attack")
		for index := range store.MaxWriters + 1 {
			writer := new(bytes.Buffer)
			n, err := writer.WriteString(input)
			require.NoError(t, err)
			require.Equal(t, len(input), n)
			requireWriterCapacityResult(t, index, writer.String())
		}
	})
}

func requireWriterCapacityResult(t *testing.T, index int, result string) {
	t.Helper()
	require.Equal(t, "attack", result)
	if index < store.MaxWriters {
		requireBufferSource(t, result, 0, 6, "attack")
	} else {
		require.False(t, taint.IsTaintedString(result), "writer above the admission limit")
	}
}

func TestWriterOwnerFanoutKeepsOwnerLocalSources(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	writer := new(strings.Builder)
	expected := make([]expectedWriterRange, 0, store.MaxSnapshotOwners)
	for index := range store.MaxSnapshotOwners + 1 {
		name := fmt.Sprintf("owner-%d", index)
		input := activeStringSource(t, name, "attack")
		n, err := writer.WriteString(input)
		require.NoError(t, err)
		require.Equal(t, len(input), n)
		if index < store.MaxSnapshotOwners {
			expected = append(expected, expectedWriterRange{
				start:  uint32(index * len(input)),
				length: uint32(len(input)),
				source: taint.SourceValue{
					Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: name},
					Value:  "attack",
				},
			})
		}
	}
	result := writer.String()
	require.Equal(t, strings.Repeat("attack", store.MaxSnapshotOwners+1), result)
	requireExactWriterRanges(t, result, expected...)
}

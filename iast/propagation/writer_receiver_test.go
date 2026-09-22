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

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type expectedWriterRange struct {
	start, length uint32
	source        taint.SourceValue
	mark          taint.VulnerabilityType
}

func markWriterString(t *testing.T, input string, mark taint.VulnerabilityType) string {
	t.Helper()
	s := request.ActiveStore()
	require.NotNil(t, s)
	key, ok := store.StringKey(input)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	owner, ok := entry.Handle(s)
	require.True(t, ok)
	var marked ranges.Set
	require.True(t, ranges.MarkAll(&marked, &entry.Ranges, mark).Valid)
	input = strings.Clone(input)
	_, ok = owner.AdoptString(input, &marked)
	require.True(t, ok)
	return input
}

func requireExactWriterRanges(t *testing.T, value string, expected ...expectedWriterRange) {
	t.Helper()
	var observed []taint.Range
	require.True(t, taint.VisitString(value, func(r taint.Range) bool {
		observed = append(observed, r)
		return true
	}))
	require.Len(t, observed, len(expected))
	for index, want := range expected {
		require.Equal(t, want.start, observed[index].Start)
		require.Equal(t, want.length, observed[index].Length)
		require.Equal(t, want.source, observed[index].Source)
		for vulnerability := taint.VulnerabilityType(1); uint(vulnerability) <= constants.VulnerabilityTypeCount; vulnerability++ {
			require.Equal(t, vulnerability == want.mark, observed[index].Marks.Has(vulnerability))
		}
	}
}

func TestWriterPointerReceiverFormsPreserveExactProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	t.Run("strings.Builder", func(t *testing.T) {
		byteInput := activeBytes(t, []byte("bytes"))
		stringInput := markWriterString(t, activeStringSource(t, "parameter", "attack"), taint.VulnerabilityTypeSqlInjection)
		builder := new(strings.Builder)

		n, err := builder.Write(byteInput)
		require.NoError(t, err)
		require.Equal(t, len(byteInput), n)
		oldCapacity := builder.Cap()
		builder.Grow(oldCapacity + 1)
		require.Greater(t, builder.Cap(), oldCapacity)
		require.NoError(t, builder.WriteByte(':'))
		n, err = builder.WriteRune('\u754c')
		require.NoError(t, err)
		require.Equal(t, len("\u754c"), n)
		n, err = builder.WriteString(stringInput)
		require.NoError(t, err)
		require.Equal(t, len(stringInput), n)

		result := builder.String()
		require.Equal(t, "bytes:\u754cattack", result)
		requireExactWriterRanges(t, result,
			expectedWriterRange{
				start:  0,
				length: uint32(len(byteInput)),
				source: taint.SourceValue{
					Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"},
					Value:  "bytes",
				},
			},
			expectedWriterRange{
				start:  uint32(len("bytes:\u754c")),
				length: uint32(len(stringInput)),
				source: taint.SourceValue{
					Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "parameter"},
					Value:  "attack",
				},
				mark: taint.VulnerabilityTypeSqlInjection,
			},
		)

		builder.Reset()
		n, err = builder.WriteString("plain")
		require.NoError(t, err)
		require.Equal(t, len("plain"), n)
		require.Equal(t, "plain", builder.String())
		require.False(t, taint.IsTaintedString(builder.String()))
	})

	t.Run("bytes.Buffer", func(t *testing.T) {
		byteInput := activeBytes(t, []byte("bytes"))
		stringInput := markWriterString(t, activeStringSource(t, "parameter", "attack"), taint.VulnerabilityTypeSqlInjection)
		buffer := new(bytes.Buffer)

		n, err := buffer.Write(byteInput)
		require.NoError(t, err)
		require.Equal(t, len(byteInput), n)
		oldCapacity := buffer.Cap()
		buffer.Grow(oldCapacity + 1)
		require.Greater(t, buffer.Cap(), oldCapacity)
		require.NoError(t, buffer.WriteByte(':'))
		n, err = buffer.WriteRune('\u754c')
		require.NoError(t, err)
		require.Equal(t, len("\u754c"), n)
		n, err = buffer.WriteString(stringInput)
		require.NoError(t, err)
		require.Equal(t, len(stringInput), n)

		buffer.Truncate(len("bytes:\u754catt"))
		result := buffer.String()
		require.Equal(t, "bytes:\u754catt", result)
		requireExactWriterRanges(t, result,
			expectedWriterRange{
				start:  0,
				length: uint32(len(byteInput)),
				source: taint.SourceValue{
					Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"},
					Value:  "bytes",
				},
			},
			expectedWriterRange{
				start:  uint32(len("bytes:\u754c")),
				length: uint32(len("att")),
				source: taint.SourceValue{
					Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "parameter"},
					Value:  "attack",
				},
				mark: taint.VulnerabilityTypeSqlInjection,
			},
		)

		buffer.Reset()
		n, err = buffer.WriteString("plain")
		require.NoError(t, err)
		require.Equal(t, len("plain"), n)
		require.Equal(t, "plain", buffer.String())
		require.False(t, taint.IsTaintedString(buffer.String()))
	})
}

func TestWriterPointerReceiverFormsPreserveHostPanics(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	capture := func(fn func()) (result any) {
		defer func() { result = recover() }()
		fn()
		return nil
	}
	tests := []struct {
		name string
		fn   func()
	}{
		{name: "builder grow", fn: func() { new(strings.Builder).Grow(-1) }},
		{name: "buffer grow", fn: func() { new(bytes.Buffer).Grow(-1) }},
		{name: "buffer truncate", fn: func() { new(bytes.Buffer).Truncate(1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := capture(test.fn)
			_ = activeString(t, "activate")
			actual := capture(test.fn)
			require.NotNil(t, expected)
			require.IsType(t, expected, actual)
			require.Equal(t, fmt.Sprint(expected), fmt.Sprint(actual))
		})
	}
}

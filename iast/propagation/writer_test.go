// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestBufferCopyReadProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, mode := range []string{"direct", "value", "return", "struct"} {
		t.Run(mode, func(t *testing.T) {
			input := activeString(t, "attack")
			result := testapp.BufferCopyRead(input, mode)
			require.Equal(t, "attack", result)
			requireBufferSource(t, result, 0, 6, "attack")
		})
	}
}

func requireBufferSource(t *testing.T, value string, start, length uint32, source string) {
	t.Helper()
	var observed []taint.Range
	require.True(t, taint.VisitString(value, func(r taint.Range) bool {
		observed = append(observed, r)
		return true
	}))
	require.Len(t, observed, 1)
	require.Equal(t, start, observed[0].Start)
	require.Equal(t, length, observed[0].Length)
	require.Equal(t, taint.SourceValue{Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"}, Value: source}, observed[0].Source)
	require.Equal(t, taint.Marks{}, observed[0].Marks)
}

func TestBufferPeekOverwrite(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, mode := range []string{"direct", "method", "copy", "interface", "eof", "zero"} {
		t.Run(mode, func(t *testing.T) {
			input := activeString(t, "attack")
			result, err := testapp.BufferPeekOverwrite(input, mode)
			if mode == "eof" {
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, "plain!", result)
			require.False(t, taint.IsTaintedString(result), "Peek alias overwrote the tracked bytes")
		})
	}
}

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

func TestBufferCopyAppend(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, mode := range []string{"string", "bytes", "byte", "rune", "wide-rune", "grow"} {
		t.Run(mode, func(t *testing.T) {
			input := activeString(t, "attack")
			suffix := "!"
			if mode == "wide-rune" {
				suffix = "界"
			}
			result, n, err := testapp.BufferCopyAppend(input, suffix, mode)
			require.NoError(t, err)
			require.Equal(t, len(suffix), n)
			require.Equal(t, "attack"+suffix, result)
			requireBufferSource(t, result, 0, 6, "attack")
		})
	}
}

func TestBufferCopyAppendSeparateOwners(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	first, second := activeString(t, "attack"), activeString(t, "second")
	result, n, err := testapp.BufferCopyAppend(first, second, "string")
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Equal(t, "attacksecond", result)
	var observed []taint.Range
	require.True(t, taint.VisitString(result, func(r taint.Range) bool {
		observed = append(observed, r)
		return true
	}))
	require.Len(t, observed, 2)
	for _, r := range observed {
		require.Equal(t, uint32(6), r.Length)
		require.Equal(t, taint.Marks{}, r.Marks)
		require.Equal(t, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"}, r.Source.Source)
		switch r.Source.Value {
		case "attack":
			require.Zero(t, r.Start)
		case "second":
			require.Equal(t, uint32(6), r.Start)
		default:
			t.Fatalf("unexpected source: %+v", r)
		}
	}
	require.NotEqual(t, observed[0].Source.Value, observed[1].Source.Value)
}

func TestBufferCopyResetThenOverwrite(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, indirect := range []bool{false, true} {
		t.Run(fmt.Sprint(indirect), func(t *testing.T) {
			input := activeString(t, "attack")
			unchanged, overwritten, before, after := testapp.BufferCopyReset(input, indirect)
			require.Equal(t, "attack", unchanged)
			requireBufferSource(t, unchanged, 0, 6, "attack")
			require.Equal(t, before, after)
			require.Equal(t, "plain!", overwritten)
			require.False(t, taint.IsTaintedString(overwritten))
		})
	}
}

func TestBufferCopyInteriorCompaction(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	result, before, after := testapp.BufferCopyCompaction(activeString(t, "attack"))
	require.Equal(t, "\x00\x00\x00\x00attack", result)
	require.Equal(t, 22, before)
	require.Equal(t, 118, after)
	requireBufferSource(t, result, 4, 6, "attack")
}

func TestBufferCopyExhaustedBackingInvalidation(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	result := testapp.BufferCopyExhausted(activeString(t, "attack"))
	require.Equal(t, "plain!", result)
	require.False(t, taint.IsTaintedString(result))
}

func TestBufferCopyOldAndAssignedBacking(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	input := activeString(t, "attack")
	requireBufferSource(t, testapp.BufferOldAllocation(input), 0, 6, "attack")
	old, current := testapp.BufferAssignedReceiver(input)
	require.Equal(t, "attack", old)
	requireBufferSource(t, old, 0, 6, "attack")
	require.Equal(t, "clean!", current)
	require.False(t, taint.IsTaintedString(current))
}

func TestBufferCopyIndependentAndPeerWrites(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	first, second := activeString(t, "attack"), activeString(t, "attack")
	changed, independent, clean := testapp.BufferIndependent(first, second)
	require.Equal(t, "plain!", changed)
	require.False(t, taint.IsTaintedString(changed))
	require.Equal(t, "attack", clean)
	require.False(t, taint.IsTaintedString(clean))
	requireBufferSource(t, independent, 0, 6, "attack")
	peer := testapp.BufferExpectedPeerWrite(first)
	require.Equal(t, "attackplain!", peer)
	require.False(t, taint.IsTaintedString(peer))
}

func TestBufferCopyTruncate(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	input := activeString(t, "attack")
	result := testapp.BufferCopyTruncate(input, 2)
	require.Equal(t, "at", result)
	requireBufferSource(t, result, 0, 2, "attack")
	require.Empty(t, testapp.BufferCopyTruncate(input, 0))
}

func TestBufferOriginalPanics(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, mode := range []string{"peek", "truncate", "grow", "nil-grow", "nil-write"} {
		t.Run(mode, func(t *testing.T) {
			native := func() {
				var buffer bytes.Buffer
				switch mode {
				case "peek":
					buffer.Peek(-1)
				case "truncate":
					buffer.Truncate(-1)
				case "grow":
					buffer.Grow(-1)
				case "nil-grow":
					var nilBuffer *bytes.Buffer
					nilBuffer.Grow(-1)
				case "nil-write":
					var nilBuffer *bytes.Buffer
					nilBuffer.WriteString("hello")
				}
			}
			capture := func(fn func()) (result any) {
				defer func() { result = recover() }()
				fn()
				return nil
			}
			expected := capture(native)
			_ = activeString(t, "active")
			actual := capture(func() { testapp.BufferHostPanic(mode) })
			require.NotNil(t, expected)
			require.IsType(t, expected, actual)
			require.Equal(t, fmt.Sprint(expected), fmt.Sprint(actual))
		})
	}
}

type bufferErrorReader struct{ err error }

func (r bufferErrorReader) Read(dst []byte) (int, error) {
	return copy(dst, "io"), r.err
}

func TestBufferOriginalReadFromError(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	want := errors.New("reader failure")
	result, n, err := testapp.BufferReadFrom(activeString(t, "attack"), bufferErrorReader{want})
	require.Same(t, want, err)
	require.Equal(t, int64(2), n)
	require.Equal(t, "attackio", result)
	require.False(t, taint.IsTaintedString(result))
}

func TestBufferCopyPreservesSecureMarks(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	input := activeString(t, "attack")
	s := request.ActiveStore()
	key, ok := store.StringKey(input)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	owner, ok := entry.Handle(s)
	require.True(t, ok)
	var marked ranges.Set
	require.True(t, ranges.MarkAll(&marked, &entry.Ranges, taint.VulnerabilityTypeSqlInjection).Valid)
	// Seed marked provenance; the application operations below remain ordinary
	// Buffer calls. Clone provides the complete allocation AdoptString requires.
	input = strings.Clone(input)
	_, ok = owner.AdoptString(input, &marked)
	require.True(t, ok)
	read := testapp.BufferCopyRead(input, "value")
	written, _, err := testapp.BufferCopyAppend(input, "!", "grow")
	require.NoError(t, err)
	for _, result := range []string{read, written} {
		count := 0
		require.True(t, taint.VisitString(result, func(r taint.Range) bool {
			count++
			require.Zero(t, r.Start)
			require.Equal(t, uint32(6), r.Length)
			require.Equal(t, taint.SourceValue{Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"}, Value: "attack"}, r.Source)
			require.True(t, r.Marks.Has(taint.VulnerabilityTypeSqlInjection))
			require.False(t, r.Marks.Has(taint.VulnerabilityTypeCommandInjection))
			return true
		}))
		require.Equal(t, 1, count)
	}
}

func TestBufferCopyDivergentViewsRemainSafeMisses(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	for _, truncate := range []bool{false, true} {
		input := activeString(t, "attack")
		result := testapp.BufferDivergentCopy(input, truncate)
		require.Equal(t, "attack", result)
		require.False(t, taint.IsTaintedString(result))
	}
}

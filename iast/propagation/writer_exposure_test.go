// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func trackedBuffer(t *testing.T, value string) *bytes.Buffer {
	t.Helper()
	input := activeString(t, value)
	buffer := new(bytes.Buffer)
	n, err := buffer.WriteString(input)
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	requireBufferSource(t, buffer.String(), 0, uint32(len(input)), input)
	return buffer
}

func TestBufferExposureMethodsInvalidateBeforeSubsequentReads(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	t.Run("ReadByte", func(t *testing.T) {
		buffer := trackedBuffer(t, "attack")
		value, err := buffer.ReadByte()
		require.NoError(t, err)
		require.Equal(t, byte('a'), value)
		require.Equal(t, "ttack", buffer.String())
		require.False(t, taint.IsTaintedString(buffer.String()))
	})
	t.Run("ReadRune", func(t *testing.T) {
		buffer := trackedBuffer(t, "\u754cattack")
		value, size, err := buffer.ReadRune()
		require.NoError(t, err)
		require.Equal(t, '\u754c', value)
		require.Equal(t, len("\u754c"), size)
		require.Equal(t, "attack", buffer.String())
		require.False(t, taint.IsTaintedString(buffer.String()))
	})
	t.Run("ReadBytes", func(t *testing.T) {
		buffer := trackedBuffer(t, "attack")
		value, err := buffer.ReadBytes('|')
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, []byte("attack"), value)
		require.False(t, taint.IsTaintedBytes(value))
		_, err = buffer.ReadByte()
		require.ErrorIs(t, err, io.EOF)
		require.Empty(t, buffer.String())
	})
	t.Run("ReadString", func(t *testing.T) {
		buffer := trackedBuffer(t, "attack|tail")
		value, err := buffer.ReadString('|')
		require.NoError(t, err)
		require.Equal(t, "attack|", value)
		require.False(t, taint.IsTaintedString(value))
		require.Equal(t, "tail", buffer.String())
		require.False(t, taint.IsTaintedString(buffer.String()))
	})
	t.Run("WriteTo", func(t *testing.T) {
		buffer := trackedBuffer(t, "attack")
		var destination bytes.Buffer
		n, err := buffer.WriteTo(&destination)
		require.NoError(t, err)
		require.Equal(t, int64(len("attack")), n)
		require.Equal(t, "attack", destination.String())
		require.False(t, taint.IsTaintedString(destination.String()))
		_, err = buffer.ReadByte()
		require.ErrorIs(t, err, io.EOF)
	})
}

func TestBufferAvailableBufferInvalidatesBeforeOverwrite(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	input := activeString(t, "attack")
	buffer := new(bytes.Buffer)
	buffer.Grow(32)
	n, err := buffer.WriteString(input)
	require.NoError(t, err)
	require.Equal(t, len(input), n)
	requireBufferSource(t, buffer.String(), 0, uint32(len(input)), input)

	exposed := buffer.AvailableBuffer()
	require.Empty(t, exposed)
	require.GreaterOrEqual(t, cap(exposed), len("plain"))
	require.False(t, taint.IsTaintedBytes(exposed))
	exposed = append(exposed, "plain"...)
	n, err = buffer.Write(exposed)
	require.NoError(t, err)
	require.Equal(t, len("plain"), n)
	require.Equal(t, "attackplain", buffer.String())
	require.False(t, taint.IsTaintedString(buffer.String()))
}

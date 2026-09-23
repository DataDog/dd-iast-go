// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

func TestWriterWrappersWithoutActiveRequest(t *testing.T) {
	require.Nil(t, request.ActiveStore())
	t.Run("builder", func(t *testing.T) {
		var builder strings.Builder
		propagation.BuilderGrow(&builder, 32)
		require.GreaterOrEqual(t, builder.Cap(), 32)
		written, err := propagation.BuilderWrite(&builder, []byte("ab"))
		require.NoError(t, err)
		require.Equal(t, 2, written)
		written, err = propagation.BuilderWriteString(&builder, "CD")
		require.NoError(t, err)
		require.Equal(t, 2, written)
		require.NoError(t, propagation.BuilderWriteByte(&builder, '!'))
		written, err = propagation.BuilderWriteRune(&builder, '\u00e9')
		require.NoError(t, err)
		require.Equal(t, 2, written)
		require.Equal(t, "abCD!\u00e9", propagation.BuilderString(&builder))
		propagation.BuilderReset(&builder)
		require.Zero(t, builder.Len())
		require.Empty(t, propagation.BuilderString(&builder))
		require.Panics(t, func() { propagation.BuilderGrow(&builder, -1) })
	})
	t.Run("buffer", func(t *testing.T) {
		var buffer bytes.Buffer
		propagation.BufferGrow(&buffer, 32)
		require.GreaterOrEqual(t, buffer.Cap(), 32)
		written, err := propagation.BufferWrite(&buffer, []byte("ab"))
		require.NoError(t, err)
		require.Equal(t, 2, written)
		written, err = propagation.BufferWriteString(&buffer, "CD")
		require.NoError(t, err)
		require.Equal(t, 2, written)
		require.NoError(t, propagation.BufferWriteByte(&buffer, '!'))
		written, err = propagation.BufferWriteRune(&buffer, '\u00e9')
		require.NoError(t, err)
		require.Equal(t, 2, written)
		require.Equal(t, "abCD!\u00e9", propagation.BufferString(&buffer))
		propagation.BufferTruncate(&buffer, 2)
		require.Equal(t, "ab", propagation.BufferString(&buffer))
		require.Panics(t, func() { propagation.BufferTruncate(&buffer, 3) })
		propagation.BufferReset(&buffer)
		require.Zero(t, buffer.Len())
		require.Empty(t, propagation.BufferString(&buffer))
		require.Equal(t, "<nil>", propagation.BufferString(nil))
		require.Panics(t, func() { propagation.BufferGrow(nil, 1) })
	})
	require.Nil(t, request.ActiveStore())
}

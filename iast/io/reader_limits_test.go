// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package io_test

import (
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestReaderBindingAdmissionLimitKeepsNativeData(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx, scope := activeContext(t)
	input := strings.NewReader("request-body")
	require.True(t, request.BindReader(ctx, input))
	var lastIncluded, firstExcluded io.Reader
	for index := 1; index <= store.MaxReaderBindings; index++ {
		output := io.LimitReader(input, 1024)
		if index < store.MaxReaderBindings {
			lastIncluded = output
		} else {
			firstExcluded = output
		}
	}
	require.NotNil(t, lastIncluded)
	require.NotNil(t, firstExcluded)

	included, err := io.ReadAll(lastIncluded)
	require.NoError(t, err)
	require.Equal(t, []byte("request-body"), included)
	requireBodyRange(t, included, "request-body")

	input.Reset("request-body")
	excluded, err := io.ReadAll(firstExcluded)
	require.NoError(t, err)
	require.Equal(t, []byte("request-body"), excluded)
	require.False(t, taint.IsTaintedBytes(excluded))

	scope.Finish()
	require.Nil(t, request.CloneReaderBytes(lastIncluded, []byte("after")))
}

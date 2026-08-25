// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

func TestBeginDisabled(t *testing.T) {
	restoreConfig(t)
	config.Enabled = false
	ctx := context.Background()
	derived, scope, created := request.Begin(ctx)
	require.False(t, created)
	require.Nil(t, scope)
	require.Equal(t, ctx, derived)
}

func TestBeginSampledOutAndNestedReuse(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 0
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	require.Equal(t, request.DecisionSampledOut, scope.Decision())
	require.False(t, scope.Active())
	require.Zero(t, scope.EnabledTagValue())

	nestedCtx, nested, nestedCreated := request.Begin(ctx)
	require.False(t, nestedCreated)
	require.Same(t, scope, nested)
	require.Equal(t, ctx, nestedCtx)
	scope.Finish()
}

func TestBeginCapacityDropped(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 0
	_, scope, created := request.Begin(nil)
	require.True(t, created)
	require.Equal(t, request.DecisionCapacityDropped, scope.Decision())
	require.False(t, scope.Active())
	require.Zero(t, scope.EnabledTagValue())
}

func TestBeginActiveAndFinish(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	require.Equal(t, request.DecisionActive, scope.Decision())
	require.True(t, scope.Active())
	require.Equal(t, 1, scope.EnabledTagValue())
	require.Same(t, scope, request.FromContext(ctx))
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	require.True(t, analysis.Active())

	scope.Finish()
	scope.Finish()
	require.False(t, scope.Active())
	_, ok = scope.Analysis()
	require.False(t, ok)
}

func restoreConfig(t *testing.T) {
	t.Helper()
	enabled := config.Enabled
	sampling := config.RequestSamplingPct
	maxConcurrent := config.MaxConcurrentRequests
	t.Cleanup(func() {
		config.Enabled = enabled
		config.RequestSamplingPct = sampling
		config.MaxConcurrentRequests = maxConcurrent
	})
}

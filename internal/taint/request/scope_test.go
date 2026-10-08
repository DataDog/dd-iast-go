// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
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

// TestInactiveScopeAllocations pins the cost of a request without analysis:
// one allocation (the context value). The scope is shared, and Finish and the
// readers do not change it.
func TestInactiveScopeAllocations(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sampling int
		capacity int
		decision request.Decision
	}{
		{name: "sampled-out", sampling: 0, capacity: 1, decision: request.DecisionSampledOut},
		{name: "capacity-dropped", sampling: 100, capacity: 0, decision: request.DecisionCapacityDropped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restoreConfig(t)
			config.Enabled = true
			config.RequestSamplingPct = tc.sampling
			config.MaxConcurrentRequests = tc.capacity
			parent := context.Background()
			for _, entry := range []request.Entry{request.EntryFallback, request.EntryServer} {
				begin := request.BeginContext
				if entry == request.EntryServer {
					begin = request.BeginServerContext
				}
				ctx, created := begin(parent)
				require.True(t, created)
				scope := request.FromContext(ctx)
				require.Equal(t, entry, scope.Entry())
				require.Equal(t, tc.decision, scope.Decision())
				require.False(t, scope.Active())
				require.Zero(t, scope.EnabledTagValue())
				_, ok := scope.Analysis()
				require.False(t, ok)
				request.FinishContext(ctx, created)
				require.Equal(t, tc.decision, scope.Decision())
				require.Equal(t, entry, scope.Entry())

				allocations := testing.AllocsPerRun(100, func() {
					ctx, created := begin(parent)
					scope := request.FromContext(ctx)
					_ = scope.Active()
					_ = scope.Decision()
					request.FinishContext(ctx, created)
				})
				require.Equal(t, 1.0, allocations, "entry %d", entry)
			}
		})
	}
}

func TestServerContextEntryAndNestedFinish(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	ctx, created := request.BeginServerContext(context.Background())
	require.True(t, created)
	scope := request.FromContext(ctx)
	require.NotNil(t, scope)
	require.Equal(t, request.EntryServer, scope.Entry())

	nestedCtx, nestedCreated := request.BeginContext(ctx)
	require.False(t, nestedCreated)
	require.Equal(t, ctx, nestedCtx)
	request.FinishContext(nestedCtx, nestedCreated)
	require.True(t, scope.Active())
	request.FinishContext(ctx, created)
	require.False(t, scope.Active())
}

func TestServerContextSkipsH2CPreface(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	original := context.Background()
	ctx, created := httpbridge.Begin(original, "PRI", "*", nil)
	require.False(t, created)
	require.Equal(t, original, ctx)
	require.Nil(t, request.FromContext(ctx))
}

func TestServerContextSkipsH2CUpgrade(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	headers := map[string][]string{
		"Upgrade":        {"H2C"},
		"Connection":     {"keep-alive, Upgrade, HTTP2-Settings"},
		"Http2-Settings": {"AAMAAABkAAQAAP__"},
	}
	original := context.Background()
	ctx, created := httpbridge.Begin(original, "GET", "/", headers)
	require.False(t, created)
	require.Equal(t, original, ctx)
	require.Nil(t, request.FromContext(ctx))
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

// TestProcessManagerBindsRuntimeBridge checks that the process manager binds
// its store to the runtime bridge (see the runtime hook rules in the
// internal/taint/runtimebridge package doc, rule 6) with the string-to-slice
// switch of the configuration.
func TestProcessManagerBindsRuntimeBridge(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	active := request.ActiveStore()
	require.NotNil(t, active)
	require.True(t, runtimebridge.Bound())
	require.Same(t, active, store.RuntimeStore())
	require.Equal(t, config.StringToSlicePropagationEnabled, runtimebridge.StringToSliceEnabled())
	require.False(t, store.New().BindRuntimeBridge(runtimebridge.Options{}), "only one store is bound")
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

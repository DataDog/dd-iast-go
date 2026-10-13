// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/scopebridge"
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

// TestProcessManagerAndBridges checks that the first sampled request makes
// the process manager, and that init set the string-to-slice switch of the
// configuration.
func TestProcessManagerAndBridges(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	manager := request.ProcessManager()
	require.NotNil(t, manager)
	require.True(t, manager.Active())
	require.Equal(t, config.StringToSlicePropagationEnabled, propbridge.StringToSlice())
}

// TestFinishCallsScopeBridge checks that Finish tells the scope bridge the
// identity of the finished owner.
func TestFinishCallsScopeBridge(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	var got request.Owner
	scopebridge.Register(func(index uint8, id, generation uint64) {
		got = request.Owner{ID: id, Generation: generation, Index: index}
	})
	t.Cleanup(func() { scopebridge.Register(func(uint8, uint64, uint64) {}) })
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	owner, ok := analysis.Owner()
	require.True(t, ok)
	scope.Finish()
	require.Equal(t, owner, got)
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

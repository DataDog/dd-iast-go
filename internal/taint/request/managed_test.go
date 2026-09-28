// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
)

// TestManagedSourceIsCompleteRoot checks that a window of a tainted root (for
// example a query value inside the raw query) is tainted but is not a managed
// source, so lazy management still gives it its own parameter source.
func TestManagedSourceIsCompleteRoot(t *testing.T) {
	manager := NewManager(nil)
	previous := processManager.Swap(manager)
	t.Cleanup(func() { processManager.Store(previous) })
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	t.Cleanup(analysis.Finish)
	query, ok := analysis.TaintString(constants.OriginHttpRequestQuery, "", "name=query-value&other=x")
	require.True(t, ok)
	value := query[5:16]
	require.Equal(t, "query-value", value)
	require.True(t, IsTaintedString(value))
	require.False(t, isManagedString(value))
	require.True(t, isManagedString(query))
	require.False(t, isManagedString("clean-value"))

	ctx := context.WithValue(context.Background(), contextKey{}, &Scope{decision: DecisionActive, analysis: analysis})
	managed := ManageParameter(ctx, "name", value)
	require.True(t, isManagedString(managed))
	var origins []constants.Origin
	VisitString(managed, func(r ResolvedRange) bool {
		origins = append(origins, r.Source.Origin)
		return true
	})
	require.Equal(t, []constants.Origin{constants.OriginHttpRequestParameter}, origins)
	require.Equal(t, managed, ManageParameter(ctx, "name", managed), "a managed source is not managed again")
}

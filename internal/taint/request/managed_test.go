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
	analysis, ok := manager.Acquire(2)
	require.True(t, ok)
	t.Cleanup(analysis.Finish)
	other, ok := manager.Acquire(2)
	require.True(t, ok)
	t.Cleanup(other.Finish)
	query, ok := analysis.TaintString(constants.OriginHttpRequestQuery, "", "name=query-value&other=x")
	require.True(t, ok)
	value := query[5:16]
	require.Equal(t, "query-value", value)
	require.True(t, IsTaintedString(value))
	require.False(t, analysis.isManagedSource(value))
	require.True(t, analysis.isManagedSource(query))
	require.False(t, other.isManagedSource(query), "a source root of a different owner is not a source of this owner")
	require.False(t, analysis.isManagedSource("clean-value"))
	require.False(t, Analysis{}.isManagedSource(query))

	ctx := context.WithValue(context.Background(), contextKey{}, &Scope{decision: DecisionActive, analysis: analysis})
	managed := ManageParameter(ctx, "name", value)
	require.True(t, analysis.isManagedSource(managed))
	var origins []constants.Origin
	VisitString(managed, func(r ResolvedRange) bool {
		origins = append(origins, r.Source.Origin)
		return true
	})
	require.Equal(t, []constants.Origin{constants.OriginHttpRequestParameter}, origins)
	require.Equal(t, managed, ManageParameter(ctx, "name", managed), "a managed source is not managed again")
}

// TestVisitStringHiddenGetsUncopiedRanges checks that hidden gets the ranges
// whose sources cannot be copied, so that a collection can mask their bytes.
func TestVisitStringHiddenGetsUncopiedRanges(t *testing.T) {
	manager := NewManager(nil)
	previous := processManager.Swap(manager)
	t.Cleanup(func() { processManager.Store(previous) })
	analysis, ok := manager.Acquire(2)
	require.True(t, ok)
	t.Cleanup(analysis.Finish)
	value, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "name", "hidden-value")
	require.True(t, ok)

	type interval struct{ start, length uint32 }
	var hidden []interval
	record := func(start, length uint32) { hidden = append(hidden, interval{start, length}) }
	visited := 0
	visit := func(ResolvedRange) bool { visited++; return true }
	require.True(t, VisitStringHidden(value, visit, record))
	require.Equal(t, 1, visited)
	require.Empty(t, hidden, "a copied range is not hidden")

	visited = 0
	func() {
		// A contended source table makes the source copy fail.
		analysis.slot.sourceMu.Lock()
		defer analysis.slot.sourceMu.Unlock()
		require.False(t, VisitStringHidden(value, visit, record))
	}()
	require.Zero(t, visited)
	require.Equal(t, []interval{{0, uint32(len(value))}}, hidden)
}

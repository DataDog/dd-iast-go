// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package taint_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

// visitedSources returns "name=value" for each range that ctx visits in
// value.
func visitedSources[T ~string | ~[]byte](ctx context.Context, value T) ([]string, bool) {
	var found []string
	visit := func(got taint.Range) bool {
		found = append(found, got.Source.Name+"="+got.Source.Value)
		return true
	}
	var delivered bool
	switch typed := any(value).(type) {
	case string:
		delivered = taint.VisitString(ctx, typed, visit)
	case []byte:
		delivered = taint.VisitBytes(ctx, typed, visit)
	}
	return found, delivered
}

// The values of the 2 requests have no common byte: the attribution matches
// copies by content, and content cannot tell apart equal bytes of 2 requests
// (plan section 4.5.4).

func TestVisitStringSeesOnlyContextRequest(t *testing.T) {
	requireBits(t)
	alphaCtx, _ := activeScope(t)
	bravoCtx, _ := activeScope(t)
	// Both requests use the same source name, with different values.
	alpha := taint.TaintString(alphaCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "id"}, "alpha")
	bravo := taint.TaintString(bravoCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "id"}, "BRVO")
	shared := asString(heapCopy(view(alpha), []byte("|"), view(bravo)))
	require.True(t, taint.IsTaintedString(shared))

	got, ok := visitedSources(alphaCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"id=alpha"}, got)
	got, ok = visitedSources(bravoCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"id=BRVO"}, got)

	// A window of the shared value that has only bytes of bravo is not
	// tainted for alpha.
	window := shared[len(alpha)+1:]
	got, ok = visitedSources(alphaCtx, window)
	require.False(t, ok)
	require.Empty(t, got)
	got, ok = visitedSources(bravoCtx, window)
	require.True(t, ok)
	require.Equal(t, []string{"id=BRVO"}, got)

	// A context with no request visits nothing.
	got, ok = visitedSources(context.Background(), shared)
	require.False(t, ok)
	require.Empty(t, got)
	require.False(t, taint.VisitString[string](nil, shared, func(taint.Range) bool { return true }))
}

func TestVisitBytesSeesOnlyContextRequest(t *testing.T) {
	requireBits(t)
	alphaCtx, _ := activeScope(t)
	bravoCtx, bravoScope := activeScope(t)
	alpha := taint.TaintBytes(alphaCtx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"}, []byte("alpha"))
	bravo := taint.TaintBytes(bravoCtx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"}, []byte("BRVO"))
	shared := heapCopy(alpha, []byte("+"), bravo)

	got, ok := visitedSources(alphaCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"body=alpha"}, got)
	got, ok = visitedSources(bravoCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"body=BRVO"}, got)
	got, ok = visitedSources(alphaCtx, shared[len(alpha)+1:])
	require.False(t, ok)
	require.Empty(t, got)

	// A finished request visits nothing, also in its old context.
	bravoScope.Finish()
	got, ok = visitedSources(bravoCtx, shared)
	require.False(t, ok)
	require.Empty(t, got)
	got, ok = visitedSources(alphaCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"body=alpha"}, got)
	require.False(t, taint.IsTaintedBytes(shared[len(alpha)+1:]), "bytes of a finished request are not tainted")
}

func TestVisitSharedValueDoesNotAllocate(t *testing.T) {
	requireBits(t)
	alphaCtx, _ := activeScope(t)
	bravoCtx, _ := activeScope(t)
	alpha := taint.TaintString(alphaCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "a"}, "alpha")
	bravo := taint.TaintString(bravoCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "b"}, "BRVO")
	shared := asString(heapCopy(view(alpha), view(bravo)))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.VisitString(alphaCtx, shared, noOpVisitor)
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.VisitString(context.Background(), shared, noOpVisitor)
	}))
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package taint_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
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

func TestVisitStringSeesOnlyContextRequest(t *testing.T) {
	alphaCtx, _ := activeScope(t)
	bravoCtx, _ := activeScope(t)
	// Both requests use the same source name, with different values.
	alpha := taint.TaintString(alphaCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "id"}, "alpha-value")
	bravo := taint.TaintString(bravoCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "id"}, "bravo-value")
	parts := []string{alpha, "|", bravo}
	shared := propagation.JoinString(parts, "", strings.Join(parts, ""))
	owners := map[uint64]bool{}
	request.VisitString(shared, func(resolved request.ResolvedRange) bool {
		owners[resolved.OwnerID] = true
		return true
	})
	require.Len(t, owners, 2, "both requests must adopt the shared value")

	got, ok := visitedSources(alphaCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"id=alpha-value"}, got)
	got, ok = visitedSources(bravoCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"id=bravo-value"}, got)

	// A window of the shared root that has only bytes of bravo is not
	// tainted for alpha.
	window := shared[len(alpha)+1:]
	got, ok = visitedSources(alphaCtx, window)
	require.False(t, ok)
	require.Empty(t, got)
	got, ok = visitedSources(bravoCtx, window)
	require.True(t, ok)
	require.Equal(t, []string{"id=bravo-value"}, got)

	// A context with no request visits nothing.
	got, ok = visitedSources(context.Background(), shared)
	require.False(t, ok)
	require.Empty(t, got)
	require.False(t, taint.VisitString[string](nil, shared, func(taint.Range) bool { return true }))
}

func TestVisitBytesSeesOnlyContextRequest(t *testing.T) {
	alphaCtx, _ := activeScope(t)
	bravoCtx, bravoScope := activeScope(t)
	alpha := taint.TaintBytes(alphaCtx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"}, []byte("alpha-bytes"))
	bravo := taint.TaintBytes(bravoCtx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "body"}, []byte("bravo-bytes"))
	elements := [][]byte{alpha, bravo}
	shared := propagation.JoinBytes(elements, []byte("+"), bytes.Join(elements, []byte("+")))

	got, ok := visitedSources(alphaCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"body=alpha-bytes"}, got)
	got, ok = visitedSources(bravoCtx, shared)
	require.True(t, ok)
	require.Equal(t, []string{"body=bravo-bytes"}, got)
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
	require.Equal(t, []string{"body=alpha-bytes"}, got)
}

func TestVisitSharedValueDoesNotAllocate(t *testing.T) {
	alphaCtx, _ := activeScope(t)
	bravoCtx, _ := activeScope(t)
	alpha := taint.TaintString(alphaCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "a"}, "alpha-value")
	bravo := taint.TaintString(bravoCtx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "b"}, "bravo-value")
	parts := []string{alpha, bravo}
	shared := propagation.JoinString(parts, "", strings.Join(parts, ""))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.VisitString(alphaCtx, shared, noOpVisitor)
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		taint.VisitString(context.Background(), shared, noOpVisitor)
	}))
}

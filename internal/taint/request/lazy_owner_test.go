// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"context"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

type lazyOwner struct {
	ctx      context.Context
	analysis request.Analysis
	id       uint64
}

func beginLazyOwner(t *testing.T) lazyOwner {
	t.Helper()
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	_, id, _, ok := analysis.Identity()
	require.True(t, ok)
	return lazyOwner{ctx: ctx, analysis: analysis, id: id}
}

// ownerSources returns the source names and values of owner in value.
func ownerSources(value string, owner uint64) []string {
	var found []string
	for _, source := range ownerSourceRecords(value, owner) {
		found = append(found, source.Name+"="+source.Value)
	}
	return found
}

// ownerSourceRecords returns the sources of owner in value.
func ownerSourceRecords(value string, owner uint64) []request.Source {
	var found []request.Source
	request.VisitString(value, func(resolved request.ResolvedRange) bool {
		if resolved.OwnerID == owner {
			found = append(found, resolved.Source)
		}
		return true
	})
	return found
}

func configureLazyOwners(t *testing.T) {
	t.Helper()
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
}

func TestLazyParametersIgnoreForeignCompleteSourceRoot(t *testing.T) {
	cases := map[string]struct {
		manage func(context.Context, string, string) string
		origin constants.Origin
	}{
		"parameter":           {request.ManageParameter, constants.OriginHttpRequestParameter},
		"multipart parameter": {request.ManageMultipartParameter, constants.OriginHttpRequestMultipartParameter},
		"path parameter":      {request.ManagePathParameter, constants.OriginHttpRequestPathParameter},
		"cookie value": {func(ctx context.Context, name, value string) string {
			request.ManageCookie(ctx, &name, &value)
			return value
		}, constants.OriginHttpRequestCookieValue},
		// The name of a cookie is its value: "shared" is not used.
		"cookie name": {func(ctx context.Context, _, value string) string {
			name, cookieValue := value, "cookie-value"
			request.ManageCookie(ctx, &name, &cookieValue)
			return name
		}, constants.OriginHttpRequestCookieName},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			configureLazyOwners(t)
			alpha := beginLazyOwner(t)
			bravo := beginLazyOwner(t)
			// The source name of a cookie name is the cookie name.
			sourceName := "shared"
			if test.origin == constants.OriginHttpRequestCookieName {
				sourceName = "shared-value"
			}
			want := []request.Source{{Origin: test.origin, Name: sourceName, Value: "shared-value", Kind: request.SourceString}}
			shared := test.manage(bravo.ctx, "shared", "shared-value")
			require.Equal(t, want, ownerSourceRecords(shared, bravo.id))
			bravoSources := bravo.analysis.SourceCount()
			require.NotZero(t, bravoSources)

			// The complete root of bravo is not a source of alpha. Alpha must
			// add its own source for its own parameter.
			got := test.manage(alpha.ctx, "shared", shared)
			require.Equal(t, "shared-value", got)
			require.Equal(t, want, ownerSourceRecords(got, alpha.id))
			require.Empty(t, ownerSourceRecords(got, bravo.id), "the new root of alpha has no range of bravo")
			require.NotZero(t, alpha.analysis.SourceCount())
			require.Equal(t, bravoSources, bravo.analysis.SourceCount())
		})
	}
}

func TestLazyParameterKeepsOwnCompleteSourceRoot(t *testing.T) {
	configureLazyOwners(t)
	alpha := beginLazyOwner(t)
	managed := request.ManageParameter(alpha.ctx, "name", "value")
	require.Equal(t, 1, alpha.analysis.SourceCount())
	again := request.ManageParameter(alpha.ctx, "other", managed)
	require.Equal(t, unsafe.StringData(managed), unsafe.StringData(again))
	require.Equal(t, 1, alpha.analysis.SourceCount(), "an own source root is not managed again")
}

func TestLazyParameterManagesOwnNonSourceRoot(t *testing.T) {
	configureLazyOwners(t)
	alpha := beginLazyOwner(t)
	left := request.ManageParameter(alpha.ctx, "left", "left-value")
	right := request.ManageParameter(alpha.ctx, "right", "right-value")
	parts := []string{left, right}
	joined := propagation.JoinString(parts, "", strings.Join(parts, ""))
	require.Len(t, ownerSources(joined, alpha.id), 2)
	require.Equal(t, 2, alpha.analysis.SourceCount())

	// A propagated root is tainted, but it is not the root of a source. A new
	// parameter with this value is a new source.
	got := request.ManageParameter(alpha.ctx, "joined", joined)
	require.Equal(t, []string{"joined=left-valueright-value"}, ownerSources(got, alpha.id))
	require.Equal(t, 3, alpha.analysis.SourceCount())
}

func TestLazyParameterOwnSourceRootDoesNotAllocate(t *testing.T) {
	configureLazyOwners(t)
	alpha := beginLazyOwner(t)
	bravo := beginLazyOwner(t)
	managed := request.ManageParameter(alpha.ctx, "name", "value")
	// A shared allocation of two owners makes a lookup with two entries.
	parts := []string{managed, request.ManageParameter(bravo.ctx, "other", "other")}
	shared := propagation.JoinString(parts, "", strings.Join(parts, ""))
	require.Len(t, ownerSources(shared, bravo.id), 1)
	require.Zero(t, testing.AllocsPerRun(100, func() {
		request.ManageParameter(alpha.ctx, "other", managed)
	}))
	require.Equal(t, 1, alpha.analysis.SourceCount())
}

func TestVisitStringOwnerDeliversOnlyOwnerRanges(t *testing.T) {
	configureLazyOwners(t)
	alpha := beginLazyOwner(t)
	bravo := beginLazyOwner(t)
	alphaOwner, ok := alpha.analysis.Owner()
	require.True(t, ok)
	bravoOwner, ok := bravo.analysis.Owner()
	require.True(t, ok)
	left := request.ManageParameter(alpha.ctx, "left", "alpha-value")
	right := request.ManageParameter(bravo.ctx, "right", "bravo-value")
	parts := []string{left, "|", right}
	shared := propagation.JoinString(parts, "", strings.Join(parts, ""))

	type interval struct{ start, length uint32 }
	for _, test := range []struct {
		owner   request.Owner
		name    string
		foreign interval
	}{
		{alphaOwner, "left", interval{12, 11}},
		{bravoOwner, "right", interval{0, 11}},
	} {
		var names []string
		var foreign []interval
		delivered := request.VisitStringOwner(shared, test.owner, func(resolved request.ResolvedRange) bool {
			require.Equal(t, test.owner, request.Owner{ID: resolved.OwnerID, Generation: resolved.OwnerGen, Index: resolved.OwnerIndex})
			names = append(names, resolved.Source.Name)
			return true
		}, func(start, length uint32) {
			foreign = append(foreign, interval{start, length})
		})
		require.True(t, delivered)
		require.Equal(t, []string{test.name}, names)
		require.Equal(t, []interval{test.foreign}, foreign)
	}

	// A stop in the visit of the owner still delivers the foreign ranges.
	var foreign int
	require.True(t, request.VisitStringOwner(shared, alphaOwner, func(request.ResolvedRange) bool { return false }, func(uint32, uint32) { foreign++ }))
	require.Equal(t, 1, foreign)
	// An owner with no range in the value gets no range.
	require.False(t, request.VisitStringOwner(shared, request.Owner{ID: 1 << 60, Generation: 1}, func(request.ResolvedRange) bool {
		t.Fatal("unexpected range")
		return true
	}, nil))
	require.False(t, request.VisitStringOwner(shared, request.Owner{}, func(request.ResolvedRange) bool { return true }, nil))
}

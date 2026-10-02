// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

func TestLazyParametersPreserveValuesWhenSourceTableIsFull(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	for index := range request.MaxSources {
		_, ok := analysis.ManageString(constants.OriginHttpRequestHeader, strconv.Itoa(index), "header-value")
		require.True(t, ok)
	}
	for _, manage := range []func(context.Context, string, string) string{
		request.ManageParameter, request.ManageMultipartParameter, request.ManagePathParameter,
	} {
		value := manage(ctx, "missing", "unchanged-value")
		require.Equal(t, "unchanged-value", value)
		require.False(t, request.IsTaintedString(value))
		require.Equal(t, request.MaxSources, analysis.SourceCount())
	}
}

func TestLazyMultipartWithoutScopePreservesMaps(t *testing.T) {
	ctx := context.Background()
	values := map[string][]string{"name": {"value"}}
	got := request.ManageMultipart(ctx, values, nil, nil)
	require.Equal(t, values, got)
	require.Equal(t, "value", request.ManageMultipartParameter(ctx, "name", "value"))
	require.Equal(t, "x", request.ManageMultipartParameter(ctx, "name", "x"))
}

func TestLazyMultipartPreservesNilValuesAndUnmatchedFormSuffixes(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	values := map[string][]string{"empty": nil, "part": {"body-value"}}
	form := map[string][]string{"part": {"query-value", "different-value"}}
	post := map[string][]string{"part": {"body-value"}}
	managed := request.ManageMultipart(ctx, values, form, post)
	require.Nil(t, managed["empty"])
	require.Equal(t, []string{"query-value", "different-value"}, form["part"])
	require.True(t, request.IsTaintedString(managed["part"][0]))
	require.True(t, request.IsTaintedString(post["part"][0]))
	require.False(t, request.IsTaintedString(form["part"][1]))
}

func TestLazyFormDropsExcessValuesWithoutPartialTaint(t *testing.T) {
	restoreConfig(t)
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 1
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	form := map[string][]string{"name": make([]string, 97)}
	for index := range form["name"] {
		form["name"][index] = "value"
	}
	got, post := request.ManageForm(ctx, form, nil)
	require.Equal(t, form, got)
	require.Nil(t, post)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	require.Zero(t, analysis.SourceCount())
	for _, value := range got["name"] {
		require.False(t, request.IsTaintedString(value))
	}
}

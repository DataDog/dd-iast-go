// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPTransformedSQLBoundArgumentDoesNotReport gives a tainted query to
// the SQL driver as a bound argument. A bound argument is not a query, thus
// the request has no finding and no source.
//
// Plan 9.2: PR #39 used only the column parameter. Here the 2 bytes "id" are
// a short copy of "id!" (a weak match, plan 4.5.2), thus the query alone is
// not tainted. The table parameter is also tainted, so that the bound
// argument is a strong tainted value and the control stays meaningful.
func TestHTTPTransformedSQLBoundArgumentDoesNotReport(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		values := r.URL.Query()
		chain := testapp.BuildSQLChain(values.Get("column"), values.Get("table"))
		assert.Equal(t, "SELECT id FROM customers", chain.Query)
		assertChainRanges(t, ctx, chain.Query, []taint.Range{
			{Start: 7, Length: 2, Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "column"},
				Value:  "id!",
			}},
			{Start: 15, Length: 9, Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "table"},
				Value:  "  customers  ",
			}},
		})
		_, err := db.ExecContext(ctx, "SELECT ?", chain.Query)
		assert.NoError(t, err)
	}, url.Values{"column": {"id!"}, "table": {"  customers  "}})
	require.Empty(t, event.Vulnerabilities)
	require.Empty(t, event.Sources)
}

// TestHTTPShortCopyOnlyDoesNotReport checks the strong-match rule of plan
// 4.5.2 (deviation of plan 9.2). A copy of 1 byte of a longer source can be
// a chance match of the bytes of a different request. Thus a query that has
// only such a copy is not tainted and does not report. A window of 1 byte at
// the address of the source is a strong match and reports.
func TestHTTPShortCopyOnlyDoesNotReport(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	source := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "value"},
		Value:  "abc'",
	}

	t.Run("copy", func(t *testing.T) {
		event := requestEvent(t, func(ctx context.Context, r *http.Request) {
			value := r.URL.Query().Get("value")
			query := testapp.BuildQuoteQuery(value[3:])
			assert.Equal(t, "SELECT ''';", query)
			assert.False(t, taint.IsTaintedString(query))
			assertChainRanges(t, ctx, query, nil)
			_, err := db.ExecContext(ctx, query)
			assert.NoError(t, err)
		}, url.Values{"value": {source.Value}})
		require.Empty(t, event.Vulnerabilities)
		require.Empty(t, event.Sources)
	})

	t.Run("window", func(t *testing.T) {
		event := requestEvent(t, func(ctx context.Context, r *http.Request) {
			window := r.URL.Query().Get("value")[3:]
			assert.Equal(t, "'", window)
			assert.True(t, taint.IsTaintedString(window))
			assertChainRanges(t, ctx, window, []taint.Range{{Length: 1, Source: source}})
			_, err := db.ExecContext(ctx, window)
			assert.NoError(t, err)
		}, url.Values{"value": {source.Value}})
		require.Len(t, event.Vulnerabilities, 1, "the window at the address of the source reports")
		assert.Equal(t, constants.VulnerabilityTypeSqlInjection, event.Vulnerabilities[0].Type)
		assertLocationsInTestFile(t, event, "sql_controls_test.go")
		assert.Equal(t, []model.Source{
			model.NewSourceString(constants.OriginHttpRequestParameter, "value", source.Value),
		}, event.Sources)
	})
}

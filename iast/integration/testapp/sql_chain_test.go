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

func TestHTTPTransformedQueryToSQL(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	columnSource := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "column"},
		Value:  "id!",
	}
	tableSource := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "table"},
		Value:  "  customers  ",
	}
	const expectedQuery = "SELECT id FROM customers"

	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		values := r.URL.Query()
		chain := testapp.BuildSQLChain(values.Get("column"), values.Get("table"))
		assert.Equal(t, "id", chain.Column)
		assert.Equal(t, "customers", chain.Table)
		assertChainRanges(t, ctx, chain.Column, []taint.Range{{Length: 2, Source: columnSource}})
		assertChainRanges(t, ctx, chain.Table, []taint.Range{{Length: 9, Source: tableSource}})

		assert.Equal(t, expectedQuery, chain.Joined)
		assertChainRanges(t, ctx, chain.Joined, []taint.Range{
			{Start: 7, Length: 2, Source: columnSource},
			{Start: 15, Length: 9, Source: tableSource},
		})

		// Plan 9.2: the fmt hooks copy the bits of %s exactly. PR #39 gave
		// one coarse range of the first source for all the result.
		assert.Equal(t, expectedQuery, chain.Query)
		assertChainRanges(t, ctx, chain.Query, []taint.Range{
			{Start: 7, Length: 2, Source: columnSource},
			{Start: 15, Length: 9, Source: tableSource},
		})
		stmt, err := db.PrepareContext(ctx, chain.Query)
		if !assert.NoError(t, err) {
			return
		}
		defer func() { assert.NoError(t, stmt.Close()) }()
		_, err = stmt.ExecContext(ctx)
		assert.NoError(t, err)
	}, url.Values{"column": {columnSource.Value}, "table": {tableSource.Value}})

	require.Len(t, event.Vulnerabilities, 2)
	assertLocationsInTestFile(t, event, "sql_chain_test.go")
	assert.NotEqual(t, event.Vulnerabilities[0].Location.Line, event.Vulnerabilities[1].Location.Line,
		"prepare and execute must report their separate call sites")
	// The 2 bytes "id" are a short copy of the 3 bytes "id!" (weak match,
	// plan 4.5.2). The report keeps their source, because the "customers"
	// part is a strong match.
	require.Equal(t, []model.Source{
		model.NewSourceString(constants.OriginHttpRequestParameter, "column", "id!"),
		model.NewSourceString(constants.OriginHttpRequestParameter, "table", "  customers  "),
	}, event.Sources)
	for _, finding := range event.Vulnerabilities {
		assert.Equal(t, constants.VulnerabilityTypeSqlInjection, finding.Type)
		assert.Equal(t, model.NewEvidenceTaintedValue([]model.ValuePart{
			model.NewValuePartString("SELECT "),
			model.NewValuePartTaintedString("id", 0, nil),
			model.NewValuePartString(" FROM "),
			model.NewValuePartTaintedString("customers", 1, nil),
		}), finding.Evidence)
	}
}

func assertChainRanges(t *testing.T, ctx context.Context, value string, expected []taint.Range) {
	t.Helper()
	count := 0
	taint.VisitString(ctx, value, func(found taint.Range) bool {
		if count >= len(expected) {
			t.Errorf("unexpected range for %q: %#v", value, found)
			count++
			return false
		}
		assert.Equal(t, expected[count], found, "range %d for %q", count, value)
		count++
		return true
	})
	assert.Equal(t, len(expected), count, "range count for %q", value)
}

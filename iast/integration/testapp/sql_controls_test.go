// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPTransformedSQLBoundArgumentDoesNotReport(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		chain := testapp.BuildSQLChain(r.URL.Query().Get("column"), "customers")
		assert.Equal(t, "SELECT id FROM customers", chain.Query)
		assertChainRanges(t, chain.Query, []taint.Range{{
			Length: 24,
			Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "column"},
				Value:  "id!",
			},
		}})
		_, err := db.ExecContext(ctx, "SELECT ?", chain.Query)
		assert.NoError(t, err)
	}, url.Values{"column": {"id!"}})
	require.Empty(t, event.Vulnerabilities)
	require.Empty(t, event.Sources)
}

func TestSQLChainIntersectsSeededSecureMarks(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	for _, markTable := range []bool{false, true} {
		name := "one marked contributor"
		if markTable {
			name = "all contributors marked"
		}
		t.Run(name, func(t *testing.T) {
			event := requestEvent(t, func(ctx context.Context, r *http.Request) {
				values := r.URL.Query()
				column := markSQLChainString(t, values.Get("column"))
				table := values.Get("table")
				if markTable {
					table = markSQLChainString(t, table)
				}
				chain := testapp.BuildSQLChain(column, table)
				assert.Equal(t, "SELECT id FROM customers", chain.Query)
				count := 0
				taint.VisitString(chain.Query, func(found taint.Range) bool {
					count++
					assert.Zero(t, found.Start)
					assert.Equal(t, uint32(24), found.Length)
					assert.Equal(t, "column", found.Source.Name)
					assert.Equal(t, "id!", found.Source.Value)
					assert.Equal(t, taint.OriginHttpRequestParameter, found.Source.Origin)
					assert.Equal(t, markTable, found.Marks.Has(taint.VulnerabilityTypeSqlInjection))
					assert.False(t, found.Marks.Has(taint.VulnerabilityTypeCommandInjection))
					return true
				})
				assert.Equal(t, 1, count)
				_, err := db.ExecContext(ctx, chain.Query)
				assert.NoError(t, err)
			}, url.Values{"column": {"id!"}, "table": {"  customers  "}})
			if markTable {
				assert.Empty(t, event.Vulnerabilities)
			} else {
				require.Len(t, event.Vulnerabilities, 1)
				assert.Equal(t, taint.VulnerabilityTypeSqlInjection, event.Vulnerabilities[0].Type)
			}
		})
	}
}

func markSQLChainString(t *testing.T, input string) string {
	t.Helper()
	active := request.ActiveStore()
	key, ok := store.StringKey(input)
	if !assert.True(t, ok) {
		return input
	}
	var snapshot store.Snapshot
	if !assert.True(t, active.Lookup(key, &snapshot)) {
		return input
	}
	entry, ok := snapshot.At(0)
	if !assert.True(t, ok) {
		return input
	}
	owner, ok := entry.Handle(active)
	if !assert.True(t, ok) {
		return input
	}
	var marked ranges.Set
	if !assert.True(t, ranges.MarkAll(&marked, &entry.Ranges, taint.VulnerabilityTypeSqlInjection).Valid) {
		return input
	}
	input = strings.Clone(input)
	_, ok = owner.AdoptString(input, &marked)
	assert.True(t, ok)
	return input
}

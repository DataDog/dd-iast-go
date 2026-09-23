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

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	application "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/require"
)

func TestHTTPQuery_SprintfZeroPrecision_reportsCleanSQL(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const cleanQuery = "SELECT 40 + 2 /*  */"
	type observation struct {
		query   string
		tainted bool
		err     error
	}
	observed := make(chan observation, 1)

	// Given
	event := requestEvent(t, func(ctx context.Context, request *http.Request) {
		parameter := request.URL.Query().Get("omitted")

		// When
		query := application.FormatWithOmittedString(parameter)
		_, err := db.ExecContext(ctx, query)
		observed <- observation{query: query, tainted: taint.IsTaintedString(query), err: err}
	}, url.Values{"omitted": {"attacker-controlled"}})

	// Then
	got := <-observed
	t.Logf("query=%q query_tainted=%t clean_control_tainted=%t sql_findings=%d",
		got.query, got.tainted, taint.IsTaintedString(cleanQuery), countType(event, constants.VulnerabilityTypeSqlInjection))
	require.NoError(t, got.err)
	require.Equal(t, cleanQuery, got.query, "the HTTP parameter emitted no bytes")
	require.True(t, got.tainted, "reproducer: a zero-precision parameter taints the clean result")
	require.False(t, taint.IsTaintedString(cleanQuery), "byte-identical literal control remains clean")
	require.Equal(t, 1, countType(event, constants.VulnerabilityTypeSqlInjection), "the SQL sink reports false taint")
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanJSONReaderChainDoesNotReport(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, _ *http.Request) {
		reader := bytes.NewReader([]byte(`{"quoted":"\"customers\""}`))
		chain, err := testapp.BuildJSONChain(reader)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, testapp.JSONName("customers"), chain.Document.Quoted)
		assert.Equal(t, "SELECT id FROM customers", chain.Query)
		assertChainRanges(t, ctx, chain.Query, nil)
		_, err = db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, nil)
	require.Empty(t, event.Vulnerabilities)
	require.Empty(t, event.Sources)
}

func TestUnsupportedJSONValueDoesNotInventSinkProvenance(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, _ *http.Request) {
		document := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody}, []byte(`{"value":"secret"}`))
		var destination struct {
			Value customString `json:"value"`
		}
		if !assert.NoError(t, json.Unmarshal(document, &destination)) {
			return
		}
		assert.Equal(t, customString("sanitized"), destination.Value)
		chain := testapp.BuildSQLChain("id!", string(destination.Value))
		assert.Equal(t, "SELECT id FROM sanitized", chain.Query)
		assertChainRanges(t, ctx, chain.Query, nil)
		_, err := db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, nil)
	require.Empty(t, event.Vulnerabilities)
}

// TestRepeatedJSONLiteralsHaveARequestSource decodes 2 equal literals that
// have 2 different sources of the same request.
//
// Plan 9.2: PR #39 kept the separate source of each literal and a secure
// mark on the first one. This tree has no marks (plan 4.7), and it finds
// the source of a copy by its content (plan 4.5.4). The 2 decoded values are
// copies with equal bytes, thus the tie rule gives the same source (the
// last registered one) to both.
func TestRepeatedJSONLiteralsHaveARequestSource(t *testing.T) {
	requireWoven(t)
	requestEvent(t, func(ctx context.Context, _ *http.Request) {
		first := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "first"}, []byte(`"same"`))
		second := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "second"}, []byte(`"same"`))
		assert.True(t, taint.IsTaintedBytes(first))
		assert.True(t, taint.IsTaintedBytes(second))

		decoded, err := testapp.DecodeRepeatedJSON(first, second)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, testapp.JSONName("same"), decoded.First)
		assert.Equal(t, "same", decoded.Second)
		want := []taint.Range{{
			Length: 4,
			Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "second"},
				Value:  `"same"`,
			},
		}}
		assertChainRanges(t, ctx, string(decoded.First), want)
		assertChainRanges(t, ctx, decoded.Second, want)
	}, nil)
}

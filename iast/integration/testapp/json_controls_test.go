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

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
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
		assertChainRanges(t, chain.Query, nil)
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
		assertChainRanges(t, chain.Query, nil)
		_, err := db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, nil)
	require.Empty(t, event.Vulnerabilities)
}

func TestRepeatedJSONLiteralsKeepSeparateSourcesAndMarks(t *testing.T) {
	requireWoven(t)
	requestEvent(t, func(ctx context.Context, _ *http.Request) {
		first := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "first"}, []byte(`"same"`))
		second := taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "second"}, []byte(`"same"`))
		active := request.ActiveStore()
		key, ok := store.BytesKey(first)
		if !assert.True(t, ok) {
			return
		}
		var snapshot store.Snapshot
		if !assert.True(t, active.Lookup(key, &snapshot)) {
			return
		}
		entry, ok := snapshot.At(0)
		if !assert.True(t, ok) {
			return
		}
		owner, ok := entry.Handle(active)
		if !assert.True(t, ok) {
			return
		}
		var marked ranges.Set
		if !assert.True(t, ranges.MarkAll(&marked, &entry.Ranges, taint.VulnerabilityTypeSqlInjection).Valid) {
			return
		}
		first = bytes.Clone(first)
		_, ok = owner.AdoptBytes(first, &marked)
		if !assert.True(t, ok) {
			return
		}
		var secureMarks taint.Marks
		taint.VisitBytes(first, func(found taint.Range) bool {
			secureMarks = found.Marks
			return false
		})
		assert.True(t, secureMarks.Has(taint.VulnerabilityTypeSqlInjection))

		decoded, err := testapp.DecodeRepeatedJSON(first, second)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, testapp.JSONName("same"), decoded.First)
		assert.Equal(t, "same", decoded.Second)
		assertChainRanges(t, string(decoded.First), []taint.Range{{
			Length: 4,
			Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "first"},
				Value:  `"same"`,
			},
			Marks: secureMarks,
		}})
		assertChainRanges(t, decoded.Second, []taint.Range{{
			Length: 4,
			Source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "second"},
				Value:  `"same"`,
			},
		}})
	}, nil)
}

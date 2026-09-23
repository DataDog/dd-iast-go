// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONDestinationClassesPreserveTheirContracts(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"array":["one","two"],"slice":["slice"],"named":{"key":"mapped"},"any":"dynamic","bytes":"c2VjcmV0","dynamic":{"other":"untyped"}}`
	incoming, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://iast.test/", strings.NewReader(document))
	require.NoError(t, err)
	source := taint.SourceValue{Source: taint.Source{Origin: taint.OriginHttpRequestBody}, Value: document}

	event := captureRequestEvent(t, func(ctx context.Context, r *http.Request) {
		var destination struct {
			Array   [2]testapp.JSONName         `json:"array"`
			Slice   []string                    `json:"slice"`
			Named   map[testapp.JSONName]string `json:"named"`
			Any     any                         `json:"any"`
			Bytes   []byte                      `json:"bytes"`
			Dynamic map[string]any              `json:"dynamic"`
		}
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&destination)) {
			return
		}
		assert.Equal(t, [2]testapp.JSONName{"one", "two"}, destination.Array)
		assert.Equal(t, []string{"slice"}, destination.Slice)
		assert.Equal(t, map[testapp.JSONName]string{"key": "mapped"}, destination.Named)
		for _, value := range []string{
			string(destination.Array[0]), string(destination.Array[1]), destination.Slice[0], destination.Named["key"],
		} {
			assertChainRanges(t, value, []taint.Range{{Length: uint32(len(value)), Source: source}})
		}

		assert.Equal(t, []byte("secret"), destination.Bytes)
		assert.False(t, taint.IsTaintedBytes(destination.Bytes))
		dynamic, ok := destination.Any.(string)
		if !assert.True(t, ok) {
			return
		}
		assert.Equal(t, "dynamic", dynamic)
		unsupported := []string{dynamic, string(destination.Bytes)}
		for key := range destination.Named {
			assert.Equal(t, testapp.JSONName("key"), key)
			unsupported = append(unsupported, string(key))
		}
		assert.Equal(t, map[string]any{"other": "untyped"}, destination.Dynamic)
		for key, value := range destination.Dynamic {
			text, ok := value.(string)
			if !assert.True(t, ok) {
				return
			}
			unsupported = append(unsupported, key, text)
		}
		for _, value := range unsupported {
			assertChainRanges(t, value, nil)
			chain := testapp.BuildSQLChain("id!", value)
			assert.Equal(t, "SELECT id FROM "+value, chain.Query)
			assertChainRanges(t, chain.Query, nil)
			_, err := db.ExecContext(ctx, chain.Query)
			assert.NoError(t, err)
		}
	}, incoming)
	require.Empty(t, event.Vulnerabilities)
	require.Empty(t, event.Sources)
}

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

// TestJSONDestinationClassesPreserveTheirContracts decodes a request body
// into the destination classes of encoding/json.
//
// Plan 9.2: in PR #39, the values of `any`, the map keys and the values of
// map[string]any were not tainted. In this tree, the taint bits follow the
// bytes, thus these values are tainted too. A []byte value (base64) is a
// new encoding of the bytes, and it stays clean in both trees. All the
// tainted values have 4 bytes or more: a shorter copy is a weak match (plan
// 4.5.2).
func TestJSONDestinationClassesPreserveTheirContracts(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"array":["first-item","second-item"],"slice":["slice"],"named":{"named-key":"mapped"},"any":"dynamic","bytes":"c2VjcmV0","dynamic":{"other":"untyped"}}`
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
		assert.Equal(t, [2]testapp.JSONName{"first-item", "second-item"}, destination.Array)
		assert.Equal(t, []string{"slice"}, destination.Slice)
		assert.Equal(t, map[testapp.JSONName]string{"named-key": "mapped"}, destination.Named)
		assert.Equal(t, map[string]any{"other": "untyped"}, destination.Dynamic)
		dynamic, ok := destination.Any.(string)
		if !assert.True(t, ok) {
			return
		}
		assert.Equal(t, "dynamic", dynamic)

		tainted := []string{
			string(destination.Array[0]), string(destination.Array[1]), destination.Slice[0], dynamic,
		}
		for key, value := range destination.Named {
			tainted = append(tainted, string(key), value)
		}
		for key, value := range destination.Dynamic {
			text, ok := value.(string)
			if !assert.True(t, ok) {
				return
			}
			tainted = append(tainted, key, text)
		}
		for _, value := range tainted {
			assertChainRanges(t, ctx, value, []taint.Range{{Length: uint32(len(value)), Source: source}})
		}

		assert.Equal(t, []byte("secret"), destination.Bytes)
		assert.False(t, taint.IsTaintedBytes(destination.Bytes))
		unsupported := string(destination.Bytes)
		assertChainRanges(t, ctx, unsupported, nil)
		chain := testapp.BuildSQLChain("id!", unsupported)
		assert.Equal(t, "SELECT id FROM "+unsupported, chain.Query)
		assertChainRanges(t, ctx, chain.Query, nil)
		_, err := db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, incoming)
	require.Empty(t, event.Vulnerabilities)
	require.Empty(t, event.Sources)
}

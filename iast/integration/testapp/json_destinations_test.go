// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
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
			assertChainRanges(t, ctx, value, []taint.Range{{Length: uint32(len(value)), Source: source}})
		}

		assert.Equal(t, []byte("secret"), destination.Bytes)
		assert.False(t, taint.IsTaintedBytes(destination.Bytes))
		dynamic, ok := destination.Any.(string)
		if !assert.True(t, ok) {
			return
		}
		assert.Equal(t, "dynamic", dynamic)
		// Map keys and interface{} strings: tainted with the body source on the
		// v2 variant, clean on the v1 variant (see "JSON decoding" in the
		// README). The v1 decoder decodes its clean buffer, thus the runtime
		// hooks do not taint its verbatim keys.
		keysAndAny := []string{dynamic}
		for key := range destination.Named {
			assert.Equal(t, testapp.JSONName("key"), key)
			keysAndAny = append(keysAndAny, string(key))
		}
		assert.Equal(t, map[string]any{"other": "untyped"}, destination.Dynamic)
		for key, value := range destination.Dynamic {
			text, ok := value.(string)
			if !assert.True(t, ok) {
				return
			}
			keysAndAny = append(keysAndAny, key, text)
		}
		for _, value := range keysAndAny {
			chain := testapp.BuildSQLChain("id!", value)
			assert.Equal(t, "SELECT id FROM "+value, chain.Query)
			if jsonTaintsKeysAndAny {
				assertChainRanges(t, ctx, value, []taint.Range{{Length: uint32(len(value)), Source: source}})
				// fmt.Sprintf is coarse: the source owns all the query.
				assertChainRanges(t, ctx, chain.Query, []taint.Range{{Length: uint32(len(chain.Query)), Source: source}})
			} else {
				assertChainRanges(t, ctx, value, nil)
				assertChainRanges(t, ctx, chain.Query, nil)
			}
			_, err := db.ExecContext(ctx, chain.Query)
			assert.NoError(t, err)
		}
		// []byte is never tainted.
		chain := testapp.BuildSQLChain("id!", string(destination.Bytes))
		assertChainRanges(t, ctx, chain.Query, nil)
		_, err := db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, incoming)
	if !jsonTaintsKeysAndAny {
		require.Empty(t, event.Vulnerabilities)
		require.Empty(t, event.Sources)
		return
	}
	// The named key, the interface{} string, and the key and value of the
	// map[string]any.
	requireSQLFindings(t, event, 4, document)
}

// TestJSONKeysAndInterfaceStringsUseTheirOwnToken checks the v2 coverage of map
// keys and interface{} strings with one request parameter in each token of a
// json.Unmarshal document. On the v2 variant, each map key and interface{}
// string gets the taint of its own token only. On the v1 variant, only the
// typed map value (the control) gets taint. Each token has an escape: the
// runtime hooks of the v1 variant would taint a verbatim key or interface{}
// string (a conversion of the tainted input bytes), but not an unquoted copy.
func TestJSONKeysAndInterfaceStringsUseTheirOwnToken(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	tokens := []struct {
		parameter, raw, decoded string
		// typedValue is true for the typed map value: it gets taint on all
		// variants.
		typedValue bool
	}{
		{parameter: "typedkey", raw: `k\u005ftyped`, decoded: "k_typed"},
		{parameter: "typedvalue", raw: `v\u005ftyped`, decoded: "v_typed", typedValue: true},
		{parameter: "anykey", raw: `k\u005fany`, decoded: "k_any"},
		{parameter: "anyvalue", raw: `v\u005fany`, decoded: "v_any"},
		{parameter: "single", raw: `s\u005fsingle`, decoded: "s_single"},
	}
	values := url.Values{}
	for _, token := range tokens {
		values.Set(token.parameter, token.raw)
	}
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query()
		// String concatenation keeps the exact range of each parameter, and
		// the conversion to []byte keeps the ranges.
		document := []byte(`{"typed":{"` + query.Get("typedkey") + `":"` + query.Get("typedvalue") + `"},` +
			`"any":{"` + query.Get("anykey") + `":"` + query.Get("anyvalue") + `"},` +
			`"single":"` + query.Get("single") + `"}`)
		var destination struct {
			Typed  map[string]string `json:"typed"`
			Any    map[string]any    `json:"any"`
			Single any               `json:"single"`
		}
		if !assert.NoError(t, json.Unmarshal(document, &destination)) {
			return
		}
		decoded := map[string]string{}
		for key, value := range destination.Typed {
			decoded[key], decoded[value] = key, value
		}
		for key, value := range destination.Any {
			text, _ := value.(string)
			decoded[key], decoded[text] = key, text
		}
		single, _ := destination.Single.(string)
		decoded[single] = single
		if !assert.Len(t, decoded, len(tokens)) {
			return
		}
		for _, token := range tokens {
			value, ok := decoded[token.decoded]
			if !assert.True(t, ok, "no decoded string %q", token.decoded) {
				continue
			}
			if token.typedValue || jsonTaintsKeysAndAny {
				assertChainRanges(t, ctx, value, []taint.Range{{
					Length: uint32(len(value)),
					Source: taint.SourceValue{
						Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: token.parameter},
						Value:  token.raw,
					},
				}})
			} else {
				assertChainRanges(t, ctx, value, nil)
			}
			_, err := db.ExecContext(ctx, testapp.BuildTableQuery(value))
			assert.NoError(t, err)
		}
	}, values)

	want := []model.Source{model.NewSourceString(constants.OriginHttpRequestParameter, "typedvalue", `v\u005ftyped`)}
	if jsonTaintsKeysAndAny {
		want = nil
		for _, token := range tokens {
			want = append(want, model.NewSourceString(constants.OriginHttpRequestParameter, token.parameter, token.raw))
		}
	}
	require.Len(t, event.Vulnerabilities, len(want))
	require.Equal(t, len(want), countType(event, constants.VulnerabilityTypeSqlInjection))
	require.ElementsMatch(t, want, event.Sources)
	assertSourcesReferenced(t, event)
}

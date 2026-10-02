// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build go1.27 && goexperiment.jsonv2

package json

import (
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

// The direct encoding/json/v2 modes of the string cache tests. With the
// default options of encoding/json/v2 (no AllowDuplicateNames), an any value
// uses the fast path unmarshalValueAny: it calls makeString with no string
// arshaler, thus with no wrapper. The string cache guard (in makeString)
// must cover it too. Direct encoding/json/v2 is out of scope for provenance
// (decision Q3); these tests check only that no request gets a false source.

// v2Any decodes an object into an any value.
var v2Any = cacheMode{document: objectDocument, decode: func(t *testing.T, document []byte) (string, string) {
	t.Helper()
	var destination any
	require.NoError(t, jsonv2.Unmarshal(document, &destination))
	object, ok := destination.(map[string]any)
	require.True(t, ok, "%T", destination)
	return object["probe"].(string), object["value"].(string)
}}

// v2Map decodes an object into a map[string]any.
var v2Map = cacheMode{document: objectDocument, decode: func(t *testing.T, document []byte) (string, string) {
	t.Helper()
	var destination map[string]any
	require.NoError(t, jsonv2.Unmarshal(document, &destination))
	return destination["probe"].(string), destination["value"].(string)
}}

// v2Slice decodes an array into a []any.
var v2Slice = cacheMode{
	document: func(probe, value string) string { return `["` + probe + `","` + value + `"]` },
	decode: func(t *testing.T, document []byte) (string, string) {
		t.Helper()
		var destination []any
		require.NoError(t, jsonv2.Unmarshal(document, &destination))
		require.Len(t, destination, 2)
		return destination[0].(string), destination[1].(string)
	},
}

// v2Typed decodes a struct with encoding/json/v2: the wrapped string
// arshaler, with the default options of encoding/json/v2.
var v2Typed = cacheMode{document: objectDocument, decode: func(t *testing.T, document []byte) (string, string) {
	t.Helper()
	var destination struct {
		Probe string `json:"probe"`
		Value string `json:"value"`
	}
	require.NoError(t, jsonv2.Unmarshal(document, &destination))
	return destination.Probe, destination.Value
}}

// TestUnmarshalV2StringCacheKeepsRequestsApart checks the string cache guard
// for each direct encoding/json/v2 mode of request A, and for a direct
// encoding/json/v2 decode and a json.Unmarshal of request B. All the modes
// use the decoders of one pool, thus one string cache.
func TestUnmarshalV2StringCacheKeepsRequestsApart(t *testing.T) {
	requireWoven(t)
	for taintedName, tainted := range map[string]cacheMode{
		"any": v2Any, "map[string]any": v2Map, "[]any": v2Slice, "typed": v2Typed, "legacy typed": legacyTyped,
	} {
		for cleanName, clean := range map[string]cacheMode{"v2 any": v2Any, "legacy typed": legacyTyped} {
			t.Run(taintedName+" then "+cleanName, func(t *testing.T) {
				requireCacheKeepsRequestsApart(t, tainted, clean)
			})
		}
	}
}

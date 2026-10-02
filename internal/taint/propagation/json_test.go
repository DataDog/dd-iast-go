// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestJSONStringPropagatesLiteralProvenance(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	document, _ := taintBytes(t, owner, []byte(`{"value":"attack"}`), []ranges.Range{{Start: 10, Length: 6, SourceID: 7}})
	literal := document[9:17]
	decoded := strings.Clone("attack")

	result, propagated := propagation.JSONString(document, literal, decoded)

	require.True(t, propagated)
	require.Equal(t, decoded, result)
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 7}}, lookupRanges(s, result))
}

func TestJSONStringUsesExactRepeatedLiteral(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	raw := []byte(`{"a":"\"same\"","b":"\"same\""}`)
	second := strings.LastIndex(string(raw), `"\"same\""`)
	require.NotEqual(t, -1, second)
	document, _ := taintBytes(t, owner, raw, []ranges.Range{{Start: uint32(second + 3), Length: 4, SourceID: 9}})
	first := strings.Index(string(document), `"\"same\""`)

	result, propagated := propagation.JSONString(document, document[second:second+len(`"\"same\""`)], "same")
	require.True(t, propagated)
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 9}}, lookupRanges(s, result))

	result, propagated = propagation.JSONString(document, document[first:first+len(`"\"same\""`)], "same")
	require.False(t, propagated, "the first equal token has no provenance")
	require.Empty(t, lookupRanges(s, result))

	copied := append([]byte(nil), document[second:second+len(`"\"same\""`)]...)
	result, propagated = propagation.JSONString(document, copied, "same")
	require.False(t, propagated, "equal bytes from another allocation must not acquire provenance")
	require.Empty(t, lookupRanges(s, result))
}

func TestJSONStringRejectsIneligibleInputs(t *testing.T) {
	document := []byte(`{"value":"clean"}`)
	literal := document[9:16]
	for name, test := range map[string]struct {
		document []byte
		literal  []byte
		result   string
	}{
		"short result":     {document: document, literal: literal, result: "x"},
		"oversized result": {document: document, literal: literal, result: strings.Repeat("x", store.MaxRootBytes+1)},
		"short document":   {document: []byte("x"), literal: []byte("x"), result: "clean"},
		"empty literal":    {document: document, result: "clean"},
	} {
		t.Run(name, func(t *testing.T) {
			result, propagated := propagation.JSONString(test.document, test.literal, test.result)
			require.False(t, propagated)
			require.Equal(t, test.result, result)
		})
	}
}

func TestJSONStringRequiresAliasedTaintedLiteral(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	document, _ := taintBytes(t, owner, []byte(`{"value":"attack"}`), []ranges.Range{{Start: 2, Length: 5, SourceID: 3}})
	literal := document[9:17]

	result, propagated := propagation.JSONString(document, literal, "attack")
	require.False(t, propagated, "taint outside the decoded literal must not propagate")
	require.Equal(t, "attack", result)

	copiedLiteral := append([]byte(nil), literal...)
	result, propagated = propagation.JSONString(document, copiedLiteral, "attack")
	require.False(t, propagated, "a literal from another allocation must not be mapped onto the document")
	require.Equal(t, "attack", result)

	cleanDocument := []byte(`{"value":"clean"}`)
	result, propagated = propagation.JSONString(cleanDocument, cleanDocument[9:16], "clean")
	require.False(t, propagated)
	require.Equal(t, "clean", result)
}

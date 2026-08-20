// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
)

// originProtocol lives in model because colocating tests with constants
// prevents Orchestrion from resolving covered synthetic dependencies. It is
// the exhaustive, intentionally-duplicated protocol mapping for
// [constants.Origin]. Every entry pins the constant's name (without the
// "Origin" prefix), its wire representation, and its numeric value. Adding a
// new enum value without adding an explicit entry here must fail the
// cardinality checks below.
var originProtocol = []struct {
	name  string
	value constants.Origin
	wire  string
}{
	{"HttpRequestParameter", constants.OriginHttpRequestParameter, "http.request.parameter"},
	{"HttpRequestParameterName", constants.OriginHttpRequestParameterName, "http.request.parameter.name"},
	{"HttpRequestHeader", constants.OriginHttpRequestHeader, "http.request.header"},
	{"HttpRequestHeaderName", constants.OriginHttpRequestHeaderName, "http.request.header.name"},
	{"HttpRequestPath", constants.OriginHttpRequestPath, "http.request.path"},
	{"HttpRequestBody", constants.OriginHttpRequestBody, "http.request.body"},
	{"HttpRequestQuery", constants.OriginHttpRequestQuery, "http.request.query"},
	{"HttpRequestPathParameter", constants.OriginHttpRequestPathParameter, "http.request.path.parameter"},
	{"HttpRequestMatrixParameter", constants.OriginHttpRequestMatrixParameter, "http.request.matrix.parameter"},
	{"HttpRequestCookieName", constants.OriginHttpRequestCookieName, "http.request.cookie.name"},
	{"HttpRequestCookieValue", constants.OriginHttpRequestCookieValue, "http.request.cookie.value"},
	{"HttpRequestUri", constants.OriginHttpRequestUri, "http.request.uri"},
	{"GrpcRequestBody", constants.OriginGrpcRequestBody, "grpc.request.body"},
	{"HttpRequestMultipartParameter", constants.OriginHttpRequestMultipartParameter, "http.request.multipart.parameter"},
	{"KafkaMessageKey", constants.OriginKafkaMessageKey, "kafka.message.key"},
	{"KafkaMessageValue", constants.OriginKafkaMessageValue, "kafka.message.value"},
	{"GraphqlResolverArgument", constants.OriginGraphqlResolverArgument, "graphql.resolver.argument"},
	{"SqlRowValue", constants.OriginSqlRowValue, "sql.row.value"},
}

func TestOriginProtocolCardinality(t *testing.T) {
	require.Equal(t, uint(18), constants.OriginCount, "the protocol origin count must stay at the agreed literal")
	require.Len(t, originProtocol, 18, "the exhaustive protocol table must cover every origin exactly once")
	require.Equal(t, int(constants.OriginCount), len(originProtocol))
}

func TestAllOrigins(t *testing.T) {
	all := constants.AllOrigins()
	require.Len(t, all, len(originProtocol))

	seen := make(map[constants.Origin]bool, len(originProtocol))
	for _, row := range originProtocol {
		got, ok := all[row.name]
		require.True(t, ok, "AllOrigins is missing entry %q", row.name)
		require.Equal(t, row.value, got, "AllOrigins()[%q] has an unexpected value", row.name)
		require.False(t, seen[row.value], "value %d appears more than once in the protocol table", row.value)
		seen[row.value] = true
	}
}

func TestOriginString(t *testing.T) {
	for _, row := range originProtocol {
		t.Run(row.name, func(t *testing.T) {
			require.Equal(t, row.wire, row.value.String())
		})
	}
}

func TestOriginJSONRoundTrip(t *testing.T) {
	for _, row := range originProtocol {
		t.Run(row.name, func(t *testing.T) {
			data, err := json.Marshal(row.value)
			require.NoError(t, err)
			require.JSONEq(t, `"`+row.wire+`"`, string(data))

			var decoded constants.Origin
			require.NoError(t, json.Unmarshal(data, &decoded))
			require.Equal(t, row.value, decoded)
		})
	}
}

func TestOriginMessagePackRoundTrip(t *testing.T) {
	prefix := []byte{0xde, 0xad, 0xbe, 0xef}
	suffix := []byte{0xf0, 0x0d}

	for _, row := range originProtocol {
		t.Run(row.name, func(t *testing.T) {
			encoded, err := row.value.MarshalMsg(append([]byte(nil), prefix...))
			require.NoError(t, err)
			require.Equal(t, prefix, encoded[:len(prefix)])

			payload := encoded[len(prefix):]
			require.LessOrEqual(t, len(payload), row.value.Msgsize(), "Msgsize must be an upper bound on the encoded size")

			withSuffix := append(append([]byte(nil), payload...), suffix...)
			var decoded constants.Origin
			remainder, err := decoded.UnmarshalMsg(withSuffix)
			require.NoError(t, err)
			require.Equal(t, row.value, decoded)
			require.Equal(t, suffix, remainder)
		})
	}
}

func TestOriginRejectsInvalidJSON(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"unknown value", `"not.a.real.origin"`},
		{"null", `null`},
		{"wrong type (number)", `42`},
		{"wrong type (object)", `{}`},
		{"malformed syntax", `"unterminated`},
		{"empty document", ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o constants.Origin
			err := o.UnmarshalJSON([]byte(tt.data))
			require.Error(t, err)
		})
	}
}

func TestOriginRejectsInvalidMessagePack(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"unknown value", encodeMsgpString("not.a.real.origin")},
		{"wrong type (int instead of string)", []byte{0x01}},
		{"truncated string header", []byte{0xdb, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o constants.Origin
			_, err := o.UnmarshalMsg(tt.data)
			require.Error(t, err)
		})
	}
}

func TestOriginInvalidValueFallbackFormatting(t *testing.T) {
	invalid := constants.Origin(255)
	require.Equal(t, "Origin(255)", invalid.String())

	data, err := invalid.MarshalJSON()
	require.NoError(t, err, "MarshalJSON never fails because String always returns a fallback")
	require.JSONEq(t, `"Origin(255)"`, string(data))

	var decoded constants.Origin
	require.Error(t, decoded.UnmarshalJSON(data), "the fallback string must not parse back into a valid constants.Origin")

	encoded, err := invalid.MarshalMsg(nil)
	require.NoError(t, err)
	var decodedMsg constants.Origin
	_, err = decodedMsg.UnmarshalMsg(encoded)
	require.Error(t, err, "the fallback string must not round-trip through MessagePack either")
}

func TestOriginUint8SweepNeverPanics(t *testing.T) {
	for i := 0; i <= 255; i++ {
		o := constants.Origin(i)
		require.NotPanics(t, func() {
			_ = o.String()
		}, "String must not panic for value %d", i)
		require.NotPanics(t, func() {
			_, _ = o.MarshalJSON()
		}, "MarshalJSON must not panic for value %d", i)
		require.NotPanics(t, func() {
			_, _ = o.MarshalMsg(nil)
		}, "MarshalMsg must not panic for value %d", i)
		require.NotPanics(t, func() {
			_ = o.Msgsize()
		}, "Msgsize must not panic for value %d", i)
	}
}

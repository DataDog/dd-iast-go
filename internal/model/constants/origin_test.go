// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package constants_test

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

// originProtocol is the exhaustive, intentionally duplicated protocol mapping
// for [constants.Origin]. Every entry pins the constant name without the
// "Origin" prefix and its wire representation. Adding an enum value without an
// explicit entry here must fail the cardinality checks below.
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
	if got, want := constants.OriginCount, uint(18); got != want {
		t.Errorf("OriginCount = %d, want %d", got, want)
	}
	if got, want := len(originProtocol), 18; got != want {
		t.Errorf("len(originProtocol) = %d, want %d", got, want)
	}
	if got, want := uint(len(originProtocol)), constants.OriginCount; got != want {
		t.Errorf("protocol table length = %d, OriginCount = %d", got, want)
	}
}

func TestAllOrigins(t *testing.T) {
	all := constants.AllOrigins()
	if got, want := len(all), len(originProtocol); got != want {
		t.Errorf("len(AllOrigins()) = %d, want %d", got, want)
	}

	seen := make(map[constants.Origin]bool, len(originProtocol))
	for _, row := range originProtocol {
		got, ok := all[row.name]
		if !ok {
			t.Errorf("AllOrigins() is missing entry %q", row.name)
			continue
		}
		if got != row.value {
			t.Errorf("AllOrigins()[%q] = %d, want %d", row.name, got, row.value)
		}
		if seen[row.value] {
			t.Errorf("origin value %d appears more than once", row.value)
		}
		seen[row.value] = true
	}
}

func TestOriginString(t *testing.T) {
	for _, row := range originProtocol {
		t.Run(row.name, func(t *testing.T) {
			if got := row.value.String(); got != row.wire {
				t.Errorf("String() = %q, want %q", got, row.wire)
			}
		})
	}
}

func TestOriginJSONRoundTrip(t *testing.T) {
	for _, row := range originProtocol {
		t.Run(row.name, func(t *testing.T) {
			data, err := json.Marshal(row.value)
			if err != nil {
				t.Fatalf("MarshalJSON() error: %v", err)
			}
			if got, want := string(data), strconv.Quote(row.wire); got != want {
				t.Errorf("MarshalJSON() = %s, want %s", got, want)
			}

			var decoded constants.Origin
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("UnmarshalJSON() error: %v", err)
			}
			if decoded != row.value {
				t.Errorf("JSON round trip = %d, want %d", decoded, row.value)
			}
		})
	}
}

func TestOriginMessagePackRoundTrip(t *testing.T) {
	prefix := []byte{0xde, 0xad, 0xbe, 0xef}
	suffix := []byte{0xf0, 0x0d}

	for _, row := range originProtocol {
		t.Run(row.name, func(t *testing.T) {
			encoded, err := row.value.MarshalMsg(append([]byte(nil), prefix...))
			if err != nil {
				t.Fatalf("MarshalMsg() error: %v", err)
			}
			if len(encoded) < len(prefix) {
				t.Fatalf("MarshalMsg() returned %d bytes, shorter than the %d-byte prefix", len(encoded), len(prefix))
			}
			if got := encoded[:len(prefix)]; !bytes.Equal(got, prefix) {
				t.Errorf("MarshalMsg() prefix = %x, want %x", got, prefix)
			}

			payload := encoded[len(prefix):]
			if got, max := len(payload), row.value.Msgsize(); got > max {
				t.Errorf("MarshalMsg() length = %d, exceeds Msgsize() = %d", got, max)
			}

			withSuffix := append(append([]byte(nil), payload...), suffix...)
			var decoded constants.Origin
			remainder, err := decoded.UnmarshalMsg(withSuffix)
			if err != nil {
				t.Fatalf("UnmarshalMsg() error: %v", err)
			}
			if decoded != row.value {
				t.Errorf("MessagePack round trip = %d, want %d", decoded, row.value)
			}
			if !bytes.Equal(remainder, suffix) {
				t.Errorf("UnmarshalMsg() remainder = %x, want %x", remainder, suffix)
			}
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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var origin constants.Origin
			if err := origin.UnmarshalJSON([]byte(test.data)); err == nil {
				t.Errorf("UnmarshalJSON(%q) succeeded, want an error", test.data)
			}
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
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var origin constants.Origin
			if _, err := origin.UnmarshalMsg(test.data); err == nil {
				t.Errorf("UnmarshalMsg(%x) succeeded, want an error", test.data)
			}
		})
	}
}

func TestOriginInvalidValueFallbackFormatting(t *testing.T) {
	invalid := constants.Origin(255)
	if got, want := invalid.String(), "Origin(255)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	data, err := invalid.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error: %v", err)
	}
	if got, want := string(data), `"Origin(255)"`; got != want {
		t.Errorf("MarshalJSON() = %s, want %s", got, want)
	}

	var decoded constants.Origin
	if err := decoded.UnmarshalJSON(data); err == nil {
		t.Error("fallback JSON string parsed as a valid Origin")
	}

	encoded, err := invalid.MarshalMsg(nil)
	if err != nil {
		t.Fatalf("MarshalMsg() error: %v", err)
	}
	var decodedMsg constants.Origin
	if _, err := decodedMsg.UnmarshalMsg(encoded); err == nil {
		t.Error("fallback MessagePack string parsed as a valid Origin")
	}
}

func TestOriginUint8SweepNeverPanics(t *testing.T) {
	for i := range 256 {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			origin := constants.Origin(i)
			assertNotPanics(t, "String", func() { _ = origin.String() })
			assertNotPanics(t, "MarshalJSON", func() { _, _ = origin.MarshalJSON() })
			assertNotPanics(t, "MarshalMsg", func() { _, _ = origin.MarshalMsg(nil) })
			assertNotPanics(t, "Msgsize", func() { _ = origin.Msgsize() })
		})
	}
}

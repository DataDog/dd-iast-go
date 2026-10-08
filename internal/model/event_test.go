// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"
)

func TestEventMarshalMsg(t *testing.T) {
	event := model.Event{
		Sources: []model.Source{
			model.NewSourceString(constants.OriginHttpRequestParameter, "query", "shady"),
			model.NewSourceRedactedString(constants.OriginHttpRequestHeader, "Authorization", "<redacted-pattern>"),
		},
		Vulnerabilities: []model.Vulnerability{
			model.NewVulnerability(
				constants.VulnerabilityTypeWeakHash,
				model.NewEvidenceEmpty(),
				&model.Location{
					SpanID:  123,
					Path:    "hash.go",
					Class:   "Hasher",
					Line:    12,
					Method:  "Hash",
					StackID: "stack-1",
				},
			),
			model.NewVulnerability(constants.VulnerabilityTypeWeakCipher, model.NewEvidenceString("DES"), nil),
			model.NewVulnerability(
				constants.VulnerabilityTypeSqlInjection,
				model.NewEvidenceTaintedValue([]model.ValuePart{
					model.NewValuePartString("SELECT "),
					model.NewValuePartRedactedString("***"),
					model.NewValuePartTaintedString("shady", 0, []constants.VulnerabilityType{constants.VulnerabilityTypeXss}),
					model.NewValuePartTaintedRedactedString("<redacted-pattern>", 1, []constants.VulnerabilityType{constants.VulnerabilityTypeSqlInjection}),
				}),
				nil,
			),
			model.NewVulnerability(constants.VulnerabilityTypeHardcodedSecret, model.NewEvidenceRedactedString("pattern"), nil),
		},
	}

	prefix := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded, err := event.MarshalMsg(append([]byte(nil), prefix...))
	require.NoError(t, err)
	require.Equal(t, prefix, encoded[:len(prefix)])

	var decoded bytes.Buffer
	remainder, err := msgp.UnmarshalAsJSON(&decoded, encoded[len(prefix):])
	require.NoError(t, err)
	require.Empty(t, remainder)
	require.JSONEq(t, fmt.Sprintf(`{
		"sources": [
			{"origin":"http.request.parameter","name":"query","value":"shady"},
			{"origin":"http.request.header","name":"Authorization","pattern":"<redacted-pattern>","redacted":true}
		],
		"vulnerabilities": [
			{"type":"WEAK_HASH","hash":%d,"evidence":{},"location":{"spanId":123,"path":"hash.go","class":"Hasher","line":12,"method":"Hash","stackId":"stack-1"}},
			{"type":"WEAK_CIPHER","hash":%d,"evidence":{"value":"DES"}},
			{"type":"SQL_INJECTION","hash":%d,"evidence":{"valueParts":[
				{"value":"SELECT "},
				{"pattern":"***","redacted":true},
				{"value":"shady","source":0,"secure_marks":["XSS"]},
				{"pattern":"<redacted-pattern>","redacted":true,"source":1,"secure_marks":["SQL_INJECTION"]}
			]}},
			{"type":"HARDCODED_SECRET","hash":%d,"evidence":{"pattern":"pattern","redacted":true}}
		]
	}`,
		event.Vulnerabilities[0].Hash,
		event.Vulnerabilities[1].Hash,
		event.Vulnerabilities[2].Hash,
		event.Vulnerabilities[3].Hash,
	), decoded.String())
}

func TestEventMarshalMsgRoundTrip(t *testing.T) {
	sourceIndex := 3
	event := model.Event{
		Sources: []model.Source{{
			Origin:    constants.OriginHttpRequestHeader,
			Name:      "Authorization",
			Value:     "Bearer token",
			Pattern:   "Bearer ***",
			Redacted:  true,
			Truncated: model.TruncatedSideRight,
		}},
		Vulnerabilities: []model.Vulnerability{{
			Type: constants.VulnerabilityTypeSqlInjection,
			Hash: 42,
			Evidence: &model.Evidence{
				Value:     "SELECT attack",
				Pattern:   "SELECT ***",
				Redacted:  true,
				Truncated: model.TruncatedSideRight,
				ValueParts: []model.ValuePart{{
					Value:       "attack",
					Pattern:     "***",
					Redacted:    true,
					Truncated:   model.TruncatedSideRight,
					SourceIndex: &sourceIndex,
					SecureMarks: []constants.VulnerabilityType{
						constants.VulnerabilityTypeXss,
						constants.VulnerabilityTypeSqlInjection,
					},
				}},
			},
			Location: &model.Location{
				SpanID:  123,
				Path:    "query.go",
				Class:   "Repository",
				Line:    17,
				Method:  "Lookup",
				StackID: "stack-1",
			},
		}},
	}
	trailing := []byte{0xde, 0xad, 0xbe, 0xef}
	encoded, err := event.MarshalMsg(nil)
	require.NoError(t, err)
	encoded = append(encoded, trailing...)

	var decoded model.Event
	remainder, err := decoded.UnmarshalMsg(encoded)
	require.NoError(t, err)
	require.Equal(t, trailing, remainder)
	require.Equal(t, event, decoded)

	// Decode again to exercise bounded slice reuse instead of allocating new
	// source and vulnerability arrays for every payload.
	remainder, err = decoded.UnmarshalMsg(encoded)
	require.NoError(t, err)
	require.Equal(t, trailing, remainder)
	require.Equal(t, event, decoded)
}

func TestEventUnmarshalMsgSkipsUnknownFields(t *testing.T) {
	encoded := msgp.AppendMapHeader(nil, 1)
	encoded = msgp.AppendString(encoded, "unknown")
	encoded = msgp.AppendString(encoded, "ignored")

	var event model.Event
	remainder, err := event.UnmarshalMsg(encoded)
	require.NoError(t, err)
	require.Empty(t, remainder)
}

func TestGeneratedUnmarshalMsgRejectsMalformedPayloads(t *testing.T) {
	decodeEvent := func(data []byte) error { _, err := new(model.Event).UnmarshalMsg(data); return err }
	decodeSource := func(data []byte) error { _, err := new(model.Source).UnmarshalMsg(data); return err }
	decodeVulnerability := func(data []byte) error { _, err := new(model.Vulnerability).UnmarshalMsg(data); return err }
	decodeEvidence := func(data []byte) error { _, err := new(model.Evidence).UnmarshalMsg(data); return err }
	decodeValuePart := func(data []byte) error { _, err := new(model.ValuePart).UnmarshalMsg(data); return err }
	decodeLocation := func(data []byte) error { _, err := new(model.Location).UnmarshalMsg(data); return err }
	decoders := []struct {
		name   string
		decode func([]byte) error
	}{
		{"event", decodeEvent},
		{"source", decodeSource},
		{"vulnerability", decodeVulnerability},
		{"evidence", decodeEvidence},
		{"value part", decodeValuePart},
		{"location", decodeLocation},
	}
	for _, decoder := range decoders {
		t.Run(decoder.name+" header", func(t *testing.T) {
			require.Error(t, decoder.decode(nil))
		})
		t.Run(decoder.name+" key", func(t *testing.T) {
			require.Error(t, decoder.decode(msgp.AppendMapHeader(nil, 1)))
		})
		t.Run(decoder.name+" unknown value", func(t *testing.T) {
			payload := msgp.AppendMapHeader(nil, 1)
			payload = msgp.AppendString(payload, "unknown")
			payload = append(payload, 0xc1) // Reserved MessagePack prefix.
			require.Error(t, decoder.decode(payload))
		})
	}

	nilValue := msgp.AppendNil(nil)
	stringValue := msgp.AppendString(nil, "wrong type")
	fieldCases := []struct {
		name   string
		field  string
		value  []byte
		decode func([]byte) error
	}{
		{"event sources", "sources", nilValue, decodeEvent},
		{"event vulnerabilities", "vulnerabilities", nilValue, decodeEvent},
		{"source origin", "origin", nilValue, decodeSource},
		{"source name", "name", nilValue, decodeSource},
		{"source value", "value", nilValue, decodeSource},
		{"source pattern", "pattern", nilValue, decodeSource},
		{"source redacted", "redacted", nilValue, decodeSource},
		{"source truncated", "truncated", nilValue, decodeSource},
		{"vulnerability type", "type", nilValue, decodeVulnerability},
		{"vulnerability hash", "hash", nilValue, decodeVulnerability},
		{"vulnerability evidence", "evidence", stringValue, decodeVulnerability},
		{"vulnerability location", "location", stringValue, decodeVulnerability},
		{"evidence value", "value", nilValue, decodeEvidence},
		{"evidence pattern", "pattern", nilValue, decodeEvidence},
		{"evidence redacted", "redacted", nilValue, decodeEvidence},
		{"evidence truncated", "truncated", nilValue, decodeEvidence},
		{"evidence value parts", "valueParts", nilValue, decodeEvidence},
		{"value part value", "value", nilValue, decodeValuePart},
		{"value part pattern", "pattern", nilValue, decodeValuePart},
		{"value part redacted", "redacted", nilValue, decodeValuePart},
		{"value part truncated", "truncated", nilValue, decodeValuePart},
		{"value part source", "source", stringValue, decodeValuePart},
		{"value part secure marks", "secure_marks", nilValue, decodeValuePart},
		{"location span ID", "spanId", nilValue, decodeLocation},
		{"location path", "path", nilValue, decodeLocation},
		{"location class", "class", nilValue, decodeLocation},
		{"location line", "line", nilValue, decodeLocation},
		{"location method", "method", nilValue, decodeLocation},
		{"location stack ID", "stackId", nilValue, decodeLocation},
	}
	for _, test := range fieldCases {
		t.Run(test.name, func(t *testing.T) {
			payload := msgp.AppendMapHeader(nil, 1)
			payload = msgp.AppendString(payload, test.field)
			payload = append(payload, test.value...)
			require.Error(t, test.decode(payload))
		})
	}
}

func TestEventMarshalMsgOmitsEmptyFields(t *testing.T) {
	event := model.Event{Vulnerabilities: []model.Vulnerability{model.NewVulnerability(
		constants.VulnerabilityTypeWeakHash,
		model.NewEvidenceString("SHA-1"),
		nil,
	)}}

	encoded, err := event.MarshalMsg(nil)
	require.NoError(t, err)
	require.NotZero(t, event.Vulnerabilities[0].Hash)

	var decoded bytes.Buffer
	remainder, err := msgp.UnmarshalAsJSON(&decoded, encoded)
	require.NoError(t, err)
	require.Empty(t, remainder)
	require.JSONEq(t, `{
		"vulnerabilities":[{
			"type":"WEAK_HASH",
			"hash":`+string(mustJSONMarshal(t, event.Vulnerabilities[0].Hash))+`,
			"evidence":{"value":"SHA-1"}
		}]
	}`, decoded.String())
}

func withConfig(t *testing.T, vulnerabilitiesPerRequest int, deduplicationEnabled bool) {
	t.Helper()
	previousLimit := config.VulnerabilitiesPerRequest
	previousDeduplication := config.DeduplicationEnabled
	config.VulnerabilitiesPerRequest = vulnerabilitiesPerRequest
	config.DeduplicationEnabled = deduplicationEnabled
	t.Cleanup(func() {
		config.VulnerabilitiesPerRequest = previousLimit
		config.DeduplicationEnabled = previousDeduplication
	})
}

func TestAddVulnerabilityEnforcesHardCap(t *testing.T) {
	withConfig(t, model.MaxVulnerabilities+100, false)
	event := model.NewEvent()
	for index := 0; index < model.MaxVulnerabilities; index++ {
		require.True(t, event.AddVulnerability(model.Vulnerability{Hash: int32(index)}))
	}
	require.False(t, event.AddVulnerability(model.Vulnerability{Hash: 999}))
	require.Len(t, event.Vulnerabilities, model.MaxVulnerabilities)
}

func TestAddVulnerabilityDeduplicationEnabledRejectsDuplicateHash(t *testing.T) {
	withConfig(t, 10, true)

	event := model.NewEvent()
	first := model.Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 7}
	second := model.Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 7}

	require.True(t, event.AddVulnerability(first), "the first vulnerability must be admitted")
	require.False(t, event.AddVulnerability(second), "a vulnerability with a duplicate hash must be rejected when deduplication is enabled")
	require.Equal(t, []model.Vulnerability{first}, event.Vulnerabilities)
}

func TestAddVulnerabilityDeduplicationDisabledAdmitsDuplicateHash(t *testing.T) {
	withConfig(t, 10, false)

	event := model.NewEvent()
	first := model.Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 7}
	second := model.Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 7}

	require.True(t, event.AddVulnerability(first), "the first vulnerability must be admitted")
	require.True(t, event.AddVulnerability(second), "a vulnerability with a duplicate hash must be admitted when deduplication is disabled")
	require.Equal(t, []model.Vulnerability{first, second}, event.Vulnerabilities)
}

func TestAddVulnerabilityRejectsAtLimitWithoutMutatingEvent(t *testing.T) {
	withConfig(t, 1, true)

	event := model.NewEvent()
	first := model.Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 1}
	require.True(t, event.AddVulnerability(first))

	capacityBefore := cap(event.Vulnerabilities)
	valuesBefore := append([]model.Vulnerability(nil), event.Vulnerabilities...)
	second := model.Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 2}
	require.False(t, event.AddVulnerability(second), "adding beyond the configured limit must be rejected")
	require.Equal(t, capacityBefore, cap(event.Vulnerabilities), "rejecting an admission must not grow the backing array")
	require.Equal(t, valuesBefore, event.Vulnerabilities, "rejecting an admission must not modify stored vulnerabilities")
}

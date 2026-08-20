// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"
)

func TestEventMarshalMsg(t *testing.T) {
	event := Event{
		Sources: []Source{
			NewSourceString(
				constants.OriginHttpRequestParameter,
				"query",
				"shady",
			),
			NewSourceRedactedString(
				constants.OriginHttpRequestHeader,
				"Authorization",
				"<redacted-pattern>",
			),
		},
		Vulnerabilities: []Vulnerability{
			NewVulnerability(
				constants.VulnerabilityTypeWeakHash,
				NewEvidenceEmpty(),
				&Location{
					SpanID:  123,
					Path:    "hash.go",
					Class:   "Hasher",
					Line:    12,
					Method:  "Hash",
					StackID: "stack-1",
				},
			),
			NewVulnerability(
				constants.VulnerabilityTypeWeakCipher,
				NewEvidenceString("DES"),
				nil,
			),
			NewVulnerability(
				constants.VulnerabilityTypeSqlInjection,
				NewEvidenceTaintedValue([]ValuePart{
					NewValuePartString("SELECT "),
					NewValuePartRedactedString("***"),
					NewValuePartTaintedString("shady", 0, []constants.VulnerabilityType{constants.VulnerabilityTypeXss}),
					NewValuePartTaintedRedactedString("<redacted-pattern>", 1, []constants.VulnerabilityType{constants.VulnerabilityTypeSqlInjection}),
				}),
				nil,
			),
			NewVulnerability(
				constants.VulnerabilityTypeHardcodedSecret,
				NewEvidenceRedactedString("pattern"),
				nil,
			),
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

func TestEventMarshalMsgOmitsEmptyFields(t *testing.T) {
	event := Event{Vulnerabilities: []Vulnerability{NewVulnerability(
		constants.VulnerabilityTypeWeakHash,
		NewEvidenceString("SHA-1"),
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

func mustJSONMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return data
}

// withConfig temporarily overrides the given config globals for the duration
// of the test and restores their original values on cleanup. This keeps
// package-global configuration state from leaking between tests.
func withConfig(t *testing.T, vulnerabilitiesPerRequest int, deduplicationEnabled bool) {
	t.Helper()

	prevLimit := config.VulnerabilitiesPerRequest
	prevDedup := config.DeduplicationEnabled
	t.Cleanup(func() {
		config.VulnerabilitiesPerRequest = prevLimit
		config.DeduplicationEnabled = prevDedup
	})

	config.VulnerabilitiesPerRequest = vulnerabilitiesPerRequest
	config.DeduplicationEnabled = deduplicationEnabled
}

func TestAddVulnerabilityDeduplicationEnabledRejectsDuplicateHash(t *testing.T) {
	withConfig(t, 10, true)

	event := NewEvent()
	first := Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 7}
	second := Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 7}

	require.True(t, event.AddVulnerability(first), "the first vulnerability must be admitted")
	require.False(t, event.AddVulnerability(second), "a vulnerability with a duplicate hash must be rejected when deduplication is enabled")

	require.Len(t, event.Vulnerabilities, 1, "the duplicate must not be appended")
	require.Equal(t, first, event.Vulnerabilities[0], "the first duplicate must remain stored unchanged")
}

func TestAddVulnerabilityDeduplicationDisabledAdmitsDuplicateHash(t *testing.T) {
	withConfig(t, 10, false)

	event := NewEvent()
	first := Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 7}
	second := Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 7}

	require.True(t, event.AddVulnerability(first), "the first vulnerability must be admitted")
	require.True(t, event.AddVulnerability(second), "a vulnerability with a duplicate hash must be admitted when deduplication is disabled")

	require.Len(t, event.Vulnerabilities, 2)
	require.Equal(t, []Vulnerability{first, second}, event.Vulnerabilities)
}

func TestAddVulnerabilityRejectsAtLimitWithoutMutatingEvent(t *testing.T) {
	withConfig(t, 1, true)

	event := NewEvent()
	first := Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 1}
	require.True(t, event.AddVulnerability(first))

	capBefore := cap(event.Vulnerabilities)
	snapshotBefore := append([]Vulnerability(nil), event.Vulnerabilities...)

	second := Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 2}
	require.False(t, event.AddVulnerability(second), "adding beyond the configured limit must be rejected")

	require.Len(t, event.Vulnerabilities, 1, "the event must not grow beyond the configured limit")
	require.Equal(t, capBefore, cap(event.Vulnerabilities), "rejecting an admission must not grow the backing array")
	require.Equal(t, snapshotBefore, event.Vulnerabilities, "rejecting an admission must not modify the stored vulnerabilities")
}

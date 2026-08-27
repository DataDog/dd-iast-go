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

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model_test

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
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
	if err != nil {
		t.Fatalf("MarshalMsg(): %v", err)
	}
	if len(encoded) < len(prefix) {
		t.Fatalf("MarshalMsg() returned %d bytes, shorter than the %d-byte prefix", len(encoded), len(prefix))
	}
	if got := encoded[:len(prefix)]; !bytes.Equal(got, prefix) {
		t.Errorf("MarshalMsg() prefix = %x, want %x", got, prefix)
	}

	var decoded bytes.Buffer
	remainder, err := msgp.UnmarshalAsJSON(&decoded, encoded[len(prefix):])
	if err != nil {
		t.Fatalf("UnmarshalAsJSON(): %v", err)
	}
	if len(remainder) != 0 {
		t.Errorf("UnmarshalAsJSON() remainder = %x, want empty", remainder)
	}
	assertJSONEqual(t, fmt.Sprintf(`{
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
	if err != nil {
		t.Fatalf("MarshalMsg(): %v", err)
	}
	if event.Vulnerabilities[0].Hash == 0 {
		t.Error("vulnerability hash = 0, want non-zero")
	}

	var decoded bytes.Buffer
	remainder, err := msgp.UnmarshalAsJSON(&decoded, encoded)
	if err != nil {
		t.Fatalf("UnmarshalAsJSON(): %v", err)
	}
	if len(remainder) != 0 {
		t.Errorf("UnmarshalAsJSON() remainder = %x, want empty", remainder)
	}
	assertJSONEqual(t, `{
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

func TestAddVulnerabilityDeduplicationEnabledRejectsDuplicateHash(t *testing.T) {
	withConfig(t, 10, true)

	event := model.NewEvent()
	first := model.Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 7}
	second := model.Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 7}

	if !event.AddVulnerability(first) {
		t.Error("first vulnerability was rejected")
	}
	if event.AddVulnerability(second) {
		t.Error("duplicate vulnerability was admitted")
	}
	if got := len(event.Vulnerabilities); got != 1 {
		t.Fatalf("vulnerability count = %d, want 1", got)
	}
	if got := event.Vulnerabilities[0]; !reflect.DeepEqual(got, first) {
		t.Errorf("stored vulnerability = %#v, want %#v", got, first)
	}
}

func TestAddVulnerabilityDeduplicationDisabledAdmitsDuplicateHash(t *testing.T) {
	withConfig(t, 10, false)

	event := model.NewEvent()
	first := model.Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 7}
	second := model.Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 7}

	if !event.AddVulnerability(first) {
		t.Error("first vulnerability was rejected")
	}
	if !event.AddVulnerability(second) {
		t.Error("duplicate vulnerability was rejected with deduplication disabled")
	}
	want := []model.Vulnerability{first, second}
	if !reflect.DeepEqual(event.Vulnerabilities, want) {
		t.Errorf("stored vulnerabilities = %#v, want %#v", event.Vulnerabilities, want)
	}
}

func TestAddVulnerabilityRejectsAtLimitWithoutMutatingEvent(t *testing.T) {
	withConfig(t, 1, true)

	event := model.NewEvent()
	first := model.Vulnerability{Type: constants.VulnerabilityTypeXss, Hash: 1}
	if !event.AddVulnerability(first) {
		t.Fatal("first vulnerability was rejected")
	}

	capacityBefore := cap(event.Vulnerabilities)
	valuesBefore := append([]model.Vulnerability(nil), event.Vulnerabilities...)
	second := model.Vulnerability{Type: constants.VulnerabilityTypeSsrf, Hash: 2}
	if event.AddVulnerability(second) {
		t.Error("vulnerability beyond the configured limit was admitted")
	}
	if got := cap(event.Vulnerabilities); got != capacityBefore {
		t.Errorf("capacity after rejection = %d, want %d", got, capacityBefore)
	}
	if !reflect.DeepEqual(event.Vulnerabilities, valuesBefore) {
		t.Errorf("stored vulnerabilities after rejection = %#v, want %#v", event.Vulnerabilities, valuesBefore)
	}
}

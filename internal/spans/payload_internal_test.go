// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestBuildLimitedPayloadBoundaries(t *testing.T) {
	for _, encoding := range []PayloadEncoding{PayloadEncodingMsgpack, PayloadEncodingJSON} {
		for _, size := range []int{MaxEventPayloadBytes - 1, MaxEventPayloadBytes, MaxEventPayloadBytes + 1} {
			t.Run(payloadEncodingName(encoding)+"/"+strconv.Itoa(size), func(t *testing.T) {
				event := eventWithEncodedSize(t, encoding, size)
				originalEvidence := event.Vulnerabilities[0].Evidence.Value
				payload, err := BuildLimitedPayload(event, encoding)
				if err != nil {
					t.Fatal(err)
				}
				wantTruncated := size > MaxEventPayloadBytes
				if payload.Truncated != wantTruncated {
					t.Fatalf("truncated = %t, want %t", payload.Truncated, wantTruncated)
				}
				if len(payload.Encoded) > MaxEventPayloadBytes {
					t.Fatalf("encoded size = %d", len(payload.Encoded))
				}
				if event.Vulnerabilities[0].Evidence.Value != originalEvidence {
					t.Fatal("input event was mutated")
				}
				if wantTruncated {
					if payload.Event == event || len(payload.Event.Sources) != 0 || payload.Event.Vulnerabilities[0].Evidence.Value != MaxSizeExceededEvidence {
						t.Fatalf("invalid fallback: %#v", payload.Event)
					}
				} else if payload.Event != event || len(payload.Encoded) != size {
					t.Fatalf("unmodified payload = event:%p size:%d", payload.Event, len(payload.Encoded))
				}
			})
		}
	}
}

func TestBuildLimitedPayloadFirstFallbackPreservesLocation(t *testing.T) {
	location := &model.Location{SpanID: 42, Path: "app/main.go", Class: "handler", Line: 7, Method: "ServeHTTP", StackID: "stack"}
	event := &model.Event{Vulnerabilities: []model.Vulnerability{{
		Type:     constants.VulnerabilityTypeSqlInjection,
		Hash:     123,
		Evidence: &model.Evidence{Value: strings.Repeat("x", 30_000)},
		Location: location,
	}}}
	for _, encoding := range []PayloadEncoding{PayloadEncodingMsgpack, PayloadEncodingJSON} {
		payload, err := BuildLimitedPayload(event, encoding)
		if err != nil {
			t.Fatal(err)
		}
		got := payload.Event.Vulnerabilities[0].Location
		if got == nil || got.Path != location.Path || got.Class != location.Class || got.Method != location.Method || got.StackID != location.StackID {
			t.Fatalf("first fallback location = %#v, want %#v", got, location)
		}
	}
}

func TestBuildLimitedPayloadSentinelIgnoresValueTruncation(t *testing.T) {
	old := config.TruncationMaxValue
	config.TruncationMaxValue = 1
	defer func() { config.TruncationMaxValue = old }()
	event := &model.Event{Vulnerabilities: []model.Vulnerability{{Evidence: &model.Evidence{Value: strings.Repeat("x", 30_000)}}}}
	for _, encoding := range []PayloadEncoding{PayloadEncodingMsgpack, PayloadEncodingJSON} {
		payload, err := BuildLimitedPayload(event, encoding)
		if err != nil {
			t.Fatal(err)
		}
		evidence := payload.Event.Vulnerabilities[0].Evidence
		if evidence.Value != MaxSizeExceededEvidence || evidence.Truncated != model.TruncatedSideNone {
			t.Fatalf("sentinel evidence = %#v", evidence)
		}
	}
}

func TestBuildLimitedPayloadPreservesRequiredFields(t *testing.T) {
	location := &model.Location{SpanID: 42, Path: strings.Repeat("p", 30_000), Class: "class", Line: 7, Method: "method", StackID: "stack"}
	event := &model.Event{
		Sources: []model.Source{{Name: "parameter", Value: "secret"}},
		Vulnerabilities: []model.Vulnerability{{
			Type:     constants.VulnerabilityTypeSqlInjection,
			Hash:     123,
			Evidence: &model.Evidence{Value: strings.Repeat("x", 30_000)},
			Location: location,
		}},
	}
	for _, encoding := range []PayloadEncoding{PayloadEncodingMsgpack, PayloadEncodingJSON} {
		payload, err := BuildLimitedPayload(event, encoding)
		if err != nil {
			t.Fatal(err)
		}
		if !payload.Truncated || len(payload.Event.Sources) != 0 {
			t.Fatalf("payload was not degraded: %#v", payload)
		}
		vulnerability := payload.Event.Vulnerabilities[0]
		if vulnerability.Type != event.Vulnerabilities[0].Type || vulnerability.Hash != 123 || vulnerability.Evidence.Value != MaxSizeExceededEvidence {
			t.Fatalf("required vulnerability fields changed: %#v", vulnerability)
		}
		if vulnerability.Location == nil || vulnerability.Location.SpanID != 42 || vulnerability.Location.Line != 7 || vulnerability.Location.StackID != "stack" {
			t.Fatalf("required location fields changed: %#v", vulnerability.Location)
		}
		if vulnerability.Location.Path != "" || vulnerability.Location.Class != "" || vulnerability.Location.Method != "" {
			t.Fatalf("optional location fields were retained: %#v", vulnerability.Location)
		}
		if len(payload.Encoded) > MaxEventPayloadBytes || location.Path == "" {
			t.Fatal("fallback limit or input immutability failed")
		}
	}
}

func TestBuildLimitedPayloadDropsOversizedStackIDsLast(t *testing.T) {
	event := &model.Event{Vulnerabilities: []model.Vulnerability{{
		Type:     constants.VulnerabilityTypeSqlInjection,
		Hash:     123,
		Evidence: &model.Evidence{Value: strings.Repeat("x", 30_000)},
		Location: &model.Location{SpanID: 42, Line: 7, StackID: strings.Repeat("s", 30_000)},
	}}}
	for _, encoding := range []PayloadEncoding{PayloadEncodingMsgpack, PayloadEncodingJSON} {
		payload, err := BuildLimitedPayload(event, encoding)
		if err != nil {
			t.Fatal(err)
		}
		location := payload.Event.Vulnerabilities[0].Location
		if location == nil || location.SpanID != 42 || location.Line != 7 || location.StackID != "" {
			t.Fatalf("final location = %#v", location)
		}
	}
}

func TestBuildLimitedPayloadMaximumFallbackShapeFits(t *testing.T) {
	event := &model.Event{Vulnerabilities: make([]model.Vulnerability, model.MaxVulnerabilities)}
	for index := range event.Vulnerabilities {
		event.Vulnerabilities[index] = model.Vulnerability{
			Type:     constants.VulnerabilityTypeSqlInjection,
			Hash:     int32(index),
			Evidence: &model.Evidence{Value: strings.Repeat("x", 1_000)},
			Location: &model.Location{SpanID: uint64(index + 1), Path: strings.Repeat("p", 1_000), Class: strings.Repeat("c", 1_000), Line: uint32(index + 1), Method: strings.Repeat("m", 1_000), StackID: strings.Repeat("s", 36)},
		}
	}
	for _, encoding := range []PayloadEncoding{PayloadEncodingMsgpack, PayloadEncodingJSON} {
		payload, err := BuildLimitedPayload(event, encoding)
		if err != nil {
			t.Fatal(err)
		}
		if !payload.Truncated || len(payload.Event.Vulnerabilities) != model.MaxVulnerabilities || len(payload.Encoded) > MaxEventPayloadBytes {
			t.Fatalf("maximum fallback = truncated:%t vulnerabilities:%d bytes:%d", payload.Truncated, len(payload.Event.Vulnerabilities), len(payload.Encoded))
		}
	}
}

func TestBuildLimitedPayloadRejectsInvalidInput(t *testing.T) {
	if _, err := BuildLimitedPayload(nil, PayloadEncodingJSON); err == nil {
		t.Fatal("nil event accepted")
	}
	event := &model.Event{Vulnerabilities: make([]model.Vulnerability, model.MaxVulnerabilities+1)}
	if _, err := BuildLimitedPayload(event, PayloadEncodingJSON); err == nil {
		t.Fatal("oversized vulnerability set accepted")
	}
	if _, err := BuildLimitedPayload(&model.Event{}, PayloadEncoding(255)); err == nil {
		t.Fatal("invalid encoding accepted")
	}
}

func eventWithEncodedSize(t *testing.T, encoding PayloadEncoding, target int) *model.Event {
	t.Helper()
	event := &model.Event{Vulnerabilities: []model.Vulnerability{{
		Type:     constants.VulnerabilityTypeSqlInjection,
		Hash:     1,
		Evidence: &model.Evidence{},
	}}}
	length := 0
	for range 8 {
		event.Vulnerabilities[0].Evidence.Value = strings.Repeat("x", length)
		encoded, err := encodePayloadEvent(event, encoding)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) == target {
			return event
		}
		length += target - len(encoded)
		if length < 0 {
			t.Fatalf("cannot construct %d-byte payload", target)
		}
	}
	t.Fatalf("cannot construct %d-byte payload", target)
	return nil
}

func payloadEncodingName(encoding PayloadEncoding) string {
	if encoding == PayloadEncodingMsgpack {
		return "msgpack"
	}
	return "json"
}

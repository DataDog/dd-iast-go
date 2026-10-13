// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package constants_test

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/tinylib/msgp/msgp"
)

func TestOriginJSONRoundTrip(t *testing.T) {
	for name, origin := range constants.AllOrigins() {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(origin)
			if err != nil {
				t.Fatalf("json.Marshal(): %v", err)
			}
			var decoded constants.Origin
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("json.Unmarshal(): %v", err)
			}
			if decoded != origin {
				t.Errorf("JSON round trip = %v, want %v", decoded, origin)
			}
		})
	}
}

func TestOriginMsgpackRoundTripAndErrors(t *testing.T) {
	for name, origin := range constants.AllOrigins() {
		t.Run(name, func(t *testing.T) {
			encoded, err := origin.MarshalMsg(nil)
			if err != nil {
				t.Fatalf("MarshalMsg(): %v", err)
			}
			trailing := []byte{0xde, 0xad}
			encoded = append(encoded, trailing...)
			var decoded constants.Origin
			remainder, err := decoded.UnmarshalMsg(encoded)
			if err != nil {
				t.Fatalf("UnmarshalMsg(): %v", err)
			}
			if decoded != origin {
				t.Errorf("MessagePack round trip = %v, want %v", decoded, origin)
			}
			if string(remainder) != string(trailing) {
				t.Errorf("UnmarshalMsg() remainder = %x, want %x", remainder, trailing)
			}
		})
	}

	var decoded constants.Origin
	if _, err := decoded.UnmarshalMsg(nil); err == nil {
		t.Error("UnmarshalMsg(nil) succeeded")
	}
	unknown := msgp.AppendString(nil, "unknown")
	if _, err := decoded.UnmarshalMsg(unknown); err == nil {
		t.Error("UnmarshalMsg() accepted an unknown origin")
	}
}

func TestVulnerabilityTypeMsgpackRoundTripAndErrors(t *testing.T) {
	for name, vulnerabilityType := range constants.AllVulnerabilityTypes() {
		t.Run(name, func(t *testing.T) {
			encoded, err := vulnerabilityType.MarshalMsg(nil)
			if err != nil {
				t.Fatalf("MarshalMsg(): %v", err)
			}
			trailing := []byte{0xbe, 0xef}
			encoded = append(encoded, trailing...)
			var decoded constants.VulnerabilityType
			remainder, err := decoded.UnmarshalMsg(encoded)
			if err != nil {
				t.Fatalf("UnmarshalMsg(): %v", err)
			}
			if decoded != vulnerabilityType {
				t.Errorf("MessagePack round trip = %v, want %v", decoded, vulnerabilityType)
			}
			if string(remainder) != string(trailing) {
				t.Errorf("UnmarshalMsg() remainder = %x, want %x", remainder, trailing)
			}
		})
	}

	var decoded constants.VulnerabilityType
	if _, err := decoded.UnmarshalMsg(nil); err == nil {
		t.Error("UnmarshalMsg(nil) succeeded")
	}
	unknown := msgp.AppendString(nil, "unknown")
	if _, err := decoded.UnmarshalMsg(unknown); err == nil {
		t.Error("UnmarshalMsg() accepted an unknown vulnerability type")
	}
}

func TestVulnerabilityTypeJSONRoundTrip(t *testing.T) {
	for name, vulnerabilityType := range constants.AllVulnerabilityTypes() {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(vulnerabilityType)
			if err != nil {
				t.Fatalf("json.Marshal(): %v", err)
			}
			var decoded constants.VulnerabilityType
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("json.Unmarshal(): %v", err)
			}
			if decoded != vulnerabilityType {
				t.Errorf("JSON round trip = %v, want %v", decoded, vulnerabilityType)
			}
		})
	}
}

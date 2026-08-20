// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package constants_test

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
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

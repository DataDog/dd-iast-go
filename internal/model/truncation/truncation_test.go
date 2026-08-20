// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package truncation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/truncation"
)

func TestString(t *testing.T) {
	tests := []struct {
		name          string
		maxCharacters uint64
		input         string
		wantValue     string
		wantTruncated bool
	}{
		{name: "empty", maxCharacters: 3, input: "", wantValue: ""},
		{name: "empty at zero limit", maxCharacters: 0, input: "", wantValue: ""},
		{name: "non-empty at zero limit", maxCharacters: 0, input: "a", wantValue: "", wantTruncated: true},
		{name: "below limit", maxCharacters: 3, input: "ab", wantValue: "ab"},
		{name: "at limit", maxCharacters: 3, input: "abc", wantValue: "abc"},
		{name: "above limit", maxCharacters: 3, input: "abcd", wantValue: "abc", wantTruncated: true},
		{name: "multibyte below limit", maxCharacters: 3, input: "éé", wantValue: "éé"},
		{name: "multibyte at limit", maxCharacters: 3, input: "ééé", wantValue: "ééé"},
		{name: "multibyte above limit", maxCharacters: 2, input: "ééé", wantValue: "éé", wantTruncated: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotValue, gotTruncated := truncation.String(test.input, test.maxCharacters)
			if gotValue != test.wantValue {
				t.Errorf("String() value = %q, want %q", gotValue, test.wantValue)
			}
			if gotTruncated != test.wantTruncated {
				t.Errorf("String() truncated = %t, want %t", gotTruncated, test.wantTruncated)
			}
		})
	}
}

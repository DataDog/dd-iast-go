// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"encoding/json"
	"fmt"
)

type StringValue interface {
	Evidence
	ValuePart
	isStringValue() // marker method
}

var (
	_ StringValue = (*UnredactedStringValue)(nil)
	_ StringValue = (*RedactedStringValue)(nil)
)

func unmarshalStringValue(raw map[string]json.RawMessage) (StringValue, error) {
	if redacted, ok := raw["redacted"]; ok {
		var val bool
		if err := json.Unmarshal(redacted, &val); err != nil {
			return nil, fmt.Errorf("cannot unmarshal StringValue.redacted: %w", err)
		}
		if !val {
			return nil, fmt.Errorf("StringValue.redacted can only be present when true")
		}
		res := RedactedStringValue{
			Redacted: true,
		}
		if pattern, ok := raw["pattern"]; ok {
			if err := json.Unmarshal(pattern, &res.Pattern); err != nil {
				return nil, fmt.Errorf("cannot unmarshal StringValue.pattern: %w", err)
			}
		}
		if truncated, ok := raw["truncated"]; ok {
			if err := json.Unmarshal(truncated, &res.Truncated); err != nil {
				return nil, fmt.Errorf("cannot unmarshal StringValue.truncated: %w", err)
			}
		}
		return &res, nil
	}

	var res UnredactedStringValue
	if err := json.Unmarshal(raw["value"], &res.Value); err != nil {
		return nil, fmt.Errorf("cannot unmarshal StringValue.value: %w", err)
	}
	if truncated, ok := raw["truncated"]; ok {
		if err := json.Unmarshal(truncated, &res.Truncated); err != nil {
			return nil, fmt.Errorf("cannot unmarshal StringValue.truncated: %w", err)
		}
	}

	return &res, nil
}

type UnredactedStringValue struct {
	// Value is the string value part of the evidence.
	Value string `json:"value"`
	// Truncated indicates whether the value has been truncated or not.
	Truncated Truncation `json:"truncated,omitzero"`
}

func (*UnredactedStringValue) isEvidence()    {}
func (*UnredactedStringValue) isValuePart()   {}
func (*UnredactedStringValue) isStringValue() {}

type RedactedStringValue struct {
	// Pattern is the pattern characterizing the redacted value.
	Pattern string `json:"pattern,omitempty"`
	// Redacted indicates whether the value has been redacted or not.
	Redacted bool `json:"redacted"`
	// Truncated indicates whether the value has been truncated or not.
	Truncated Truncation `json:"truncated,omitzero"`
}

func (*RedactedStringValue) isEvidence()    {}
func (*RedactedStringValue) isValuePart()   {}
func (*RedactedStringValue) isStringValue() {}

type TaintedValue interface {
	ValuePart
	isTaintedValue() // marker method
}

var (
	_ TaintedValue = (*UnredactedTaintedValue)(nil)
	_ TaintedValue = (*RedactedTaintedValue)(nil)
)

func unmarshalTaintedValue(raw map[string]json.RawMessage, srcIndex int) (TaintedValue, error) {
	if redacted, ok := raw["redacted"]; ok {
		var val bool
		if err := json.Unmarshal(redacted, &val); err != nil {
			return nil, fmt.Errorf("cannot unmarshal TaintedValue.redacted: %w", err)
		}
		if !val {
			return nil, fmt.Errorf("TaintedValue.redacted can only be present when true")
		}
		res := RedactedTaintedValue{SourceIndex: srcIndex, Redacted: true}
		if pattern, ok := raw["pattern"]; ok {
			if err := json.Unmarshal(pattern, &res.Pattern); err != nil {
				return nil, fmt.Errorf("cannot unmarshal TaintedValue.pattern: %w", err)
			}
		}
		if secureMarks, ok := raw["secure_marks"]; ok {
			if err := json.Unmarshal(secureMarks, &res.SecureMarks); err != nil {
				return nil, fmt.Errorf("cannot unmarshal TaintedValue.secure_marks: %w", err)
			}
		}
		if truncated, ok := raw["truncated"]; ok {
			if err := json.Unmarshal(truncated, &res.Truncated); err != nil {
				return nil, fmt.Errorf("cannot unmarshal TaintedValue.truncated: %w", err)
			}
		}
		return &res, nil
	}

	res := UnredactedTaintedValue{SourceIndex: srcIndex}
	if err := json.Unmarshal(raw["value"], &res.Value); err != nil {
		return nil, fmt.Errorf("cannot unmarshal TaintedValue.value: %w", err)
	}
	if secureMarks, ok := raw["secure_marks"]; ok {
		if err := json.Unmarshal(secureMarks, &res.SecureMarks); err != nil {
			return nil, fmt.Errorf("cannot unmarshal TaintedValue.secure_marks: %w", err)
		}
	}
	if truncated, ok := raw["truncated"]; ok {
		if err := json.Unmarshal(truncated, &res.Truncated); err != nil {
			return nil, fmt.Errorf("cannot unmarshal TaintedValue.truncated: %w", err)
		}
	}

	return &res, nil
}

type UnredactedTaintedValue struct {
	// Value is the string value that is tainted.
	Value string `json:"value"`
	// SourceIndex is the index of the source in the sources array.
	SourceIndex int `json:"source"`
	// SecureMarks is the secure marks for the evidence part.
	SecureMarks []VulnerabilityType `json:"secure_marks,omitempty"`
	// Truncated indicates whether the value has been truncated or not.
	Truncated Truncation `json:"truncated,omitzero"`
}

func (*UnredactedTaintedValue) isValuePart()    {}
func (*UnredactedTaintedValue) isTaintedValue() {}

type RedactedTaintedValue struct {
	// Pattern is the pattern characterizing the redacted value.
	Pattern string `json:"pattern,omitempty"`
	// Redacted indicates whether the value has been redacted or not.
	Redacted bool `json:"redacted"`
	// SourceIndex is the index of the source in the sources array.
	SourceIndex int `json:"source"`
	// SecureMarks is the secure marks for the evidence part.
	SecureMarks []VulnerabilityType `json:"secure_marks,omitempty"`
	// Truncated indicates whether the value has been truncated or not.
	Truncated Truncation `json:"truncated,omitzero"`
}

func (*RedactedTaintedValue) isValuePart()    {}
func (*RedactedTaintedValue) isTaintedValue() {}

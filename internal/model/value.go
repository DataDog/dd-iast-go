// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

type StringValue interface {
	Evidence
	ValuePart
	isStringValue() // marker method
}

var (
	_ StringValue = (*UnredactedStringValue)(nil)
	_ StringValue = (*RedactedStringValue)(nil)
)

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

type UnredactedTaintedValue struct {
	// Value is the string value that is tainted.
	Value string `json:"value"`
	// Source is the index of the source in the sources array.
	Source int `json:"source"`
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
	// Source is the index of the source in the sources array.
	Source int `json:"source"`
	// SecureMarks is the secure marks for the evidence part.
	SecureMarks []VulnerabilityType `json:"secure_marks,omitempty"`
	// Truncated indicates whether the value has been truncated or not.
	Truncated Truncation `json:"truncated,omitzero"`
}

func (*RedactedTaintedValue) isValuePart()    {}
func (*RedactedTaintedValue) isTaintedValue() {}

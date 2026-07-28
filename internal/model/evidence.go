// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import "github.com/DataDog/dd-iast-go/internal/model/constants"

//go:generate go tool msgp -io=false -tests=false

type Evidence struct {
	Value     string        `json:"value,omitempty" msg:"value,omitempty"`
	Pattern   string        `json:"pattern,omitempty" msg:"pattern,omitempty"`
	Redacted  bool          `json:"redacted,omitempty" msg:"redacted,omitempty"`
	Truncated TruncatedSide `json:"truncated,omitempty" msg:"truncated,omitzero"`

	ValueParts []ValuePart `json:"valueParts,omitempty" msg:"valueParts,omitempty"`
}

// NewEvidenceString creates a new evidence with string value.
func NewEvidenceString(value string) *Evidence {
	//TODO: Truncate if too long?
	return &Evidence{
		Value: value,
	}
}

// NewEvidenceRedactedString creates a new evidence with redacted string.
func NewEvidenceRedactedString(pattern string) *Evidence {
	//TODO: Truncate if too long?
	return &Evidence{
		Pattern:  pattern,
		Redacted: true,
	}
}

// NewEvidenceTaintedValue creates a new evidence with tainted value parts.
func NewEvidenceTaintedValue(parts []ValuePart) *Evidence {
	return &Evidence{
		ValueParts: parts,
	}
}

// NewEvidenceEmpty creates a new empty evidence.
func NewEvidenceEmpty() *Evidence {
	return new(Evidence)
}

type ValuePart struct {
	Value       string                        `json:"value,omitempty" msg:"value,omitempty"`
	Pattern     string                        `json:"pattern,omitempty" msg:"pattern,omitempty"`
	Redacted    bool                          `json:"redacted,omitempty" msg:"redacted,omitempty"`
	Truncated   TruncatedSide                 `json:"truncated,omitempty" msg:"truncated,omitzero"`
	SourceIndex *int                          `json:"source,omitempty" msg:"source,omitempty"`
	SecureMarks []constants.VulnerabilityType `json:"secure_marks,omitempty" msg:"secure_marks,omitempty"`
}

func NewValuePartString(value string) ValuePart {
	//TODO: Truncate if too long?
	return ValuePart{
		Value: value,
	}
}

func NewValuePartRedactedString(pattern string) ValuePart {
	//TODO: Truncate if too long?
	return ValuePart{
		Pattern:  pattern,
		Redacted: true,
	}
}

func NewValuePartTaintedString(value string, sourceIndex int, secureMarks []constants.VulnerabilityType) ValuePart {
	//TODO: Truncate if too long?
	return ValuePart{
		Value:       value,
		SourceIndex: &sourceIndex,
		SecureMarks: secureMarks,
	}
}

func NewValuePartTaintedRedactedString(pattern string, sourceIndex int, secureMarks []constants.VulnerabilityType) ValuePart {
	return ValuePart{
		Pattern:     pattern,
		Redacted:    true,
		SourceIndex: &sourceIndex,
		SecureMarks: secureMarks,
	}
}

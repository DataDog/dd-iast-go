// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"encoding/json"
	"fmt"
)

type Evidence interface {
	isEvidence() // marker method
}

var (
	_ Evidence = EmptyEvidence{}
	_ Evidence = (StringEvidence)(nil)
	_ Evidence = (*TaintedEvidence)(nil)
)

// EmptyEvidence is empty evidence.
type EmptyEvidence struct{}

func (EmptyEvidence) isEvidence() {}

// StringEvidence is the value that triggered a vulnerability. For example, the
// crypto algorithm for weak hash.
type StringEvidence = StringValue

// TaintedEvidence is the value that triggered a vulnerability, including the
// string value and tainted ranges.
type TaintedEvidence struct {
	ValueParts []ValuePart `json:"valueParts"`
}

func (*TaintedEvidence) isEvidence() {}

type ValuePart interface {
	isValuePart() // marker method
}

var (
	_ ValuePart = (TaintedValue)(nil)
	_ ValuePart = (StringValue)(nil)
)

func unmarshalValuePart(raw json.RawMessage) (ValuePart, error) {
	var partial map[string]json.RawMessage
	if err := json.Unmarshal(raw, &partial); err != nil {
		return nil, err
	}

	if src, ok := partial["source"]; ok {
		var srcIndex int
		if err := json.Unmarshal(src, &srcIndex); err != nil {
			return nil, fmt.Errorf("cannot unmarshal ValuePart.source: %w", err)
		}
		return unmarshalTaintedValue(partial, srcIndex)
	}

	value, err := unmarshalStringValue(partial)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal ValuePart: %w", err)
	}
	return value, nil
}

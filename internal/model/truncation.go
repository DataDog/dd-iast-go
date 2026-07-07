// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import "encoding/json"

// Truncation indicates whether the value has been truncated or not.
type Truncation bool

const (
	// TruncationNone indicates that the value has not been truncated.
	TruncationNone Truncation = false
	// TruncationRight indicates that the value has been truncated on the right.
	TruncationRight Truncation = true
)

var _ json.Marshaler = Truncation(false)

func (t Truncation) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t Truncation) String() string {
	if t {
		return "right"
	}
	return "none"
}

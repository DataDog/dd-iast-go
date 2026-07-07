// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

type Source struct {
	// Origin of the source (where the source comes from).
	Origin Origin
	// Name of the source. For example, the name of the request parameter.
	Name string `json:"name,omitempty"`
	// Value of the source. For example, the value of the request parameter
	Value string `json:"value,omitempty"`
	// Pattern characterizing the redacted value
	Pattern string `json:"pattern,omitempty"`
	// Redacted informs whether the value has been redacted or not
	Redacted bool `json:"redacted,omitzero"`
	// Truncated informs whether the value has been truncated (on the right)
	Truncated Truncation `json:"truncated,omitzero"`
}

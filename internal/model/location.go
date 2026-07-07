// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

type Location struct {
	// SpanID is the ID of the active span when the vulnerability was triggered,
	// for later use in correlation APIs.
	SpanID string `json:"spanId"`
	// Path is the name of the file containing the vulnerability.
	Path string `json:"path,omitempty"`
	// Type is the name of the type containing the vulnerability.
	Type string `json:"class,omitempty"`
	// Line is the zero based line number in the source code file where the
	// vulnerability is located (-1 may be used as missing line)
	Line *int `json:"line,omitempty"`
	// Method is the name or descriptor of the method where this location points
	// to.
	Method string `json:"method,omitempty"`
	// StackID is the ID of the stack in the vulnerability category under the
	// `_dd.stack` tag in metastruct.
	StackID string `json:"stackId,omitempty"`
}

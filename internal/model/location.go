// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

//go:generate go tool msgp -io=false -tests=false

type Location struct {
	// SpanID is the ID of the span where the vulnerability was detected.
	SpanID uint64 `json:"spanId,string" msg:"spanId"`
	// Path is the path to the file containing the vulnerable code.
	Path string `json:"path,omitempty" msg:"path,omitempty"`
	// Class is the name of the type that hosts the vulnerable method.
	Class string `json:"class,omitempty" msg:"class,omitempty"`
	// Line is the line number in [Location.Path] where the vulnerability is. If
	// not available or unknown, the value is 0 or -1.
	Line int `json:"line,omitzero" msg:"line,omitempty"`
	// Method is the name of the function of method that is vulnerable.
	Method string `json:"method,omitempty" msg:"method,omitempty"`
	// StackID is the identifier of the stack trace in the `_dd.stack` tag in
	// `meta_struct`.
	StackID string `json:"stackId,omitempty" msg:"stackId,omitempty"`
}

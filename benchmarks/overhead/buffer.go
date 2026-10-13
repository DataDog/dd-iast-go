// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

import "bytes"

// NewTrackedBuffer exercises an ordinary wrapped write before benchmarking.
func NewTrackedBuffer(input string) *bytes.Buffer {
	var buffer bytes.Buffer
	buffer.Grow(64)
	buffer.WriteString(input)
	return &buffer
}

// ReadBufferCopy publishes an ordinary pass-by-value copy.
func ReadBufferCopy(buffer bytes.Buffer) string { return buffer.String() }

// WriteBufferCopy appends through a copy, then restores the source writer.
func WriteBufferCopy(buffer *bytes.Buffer, input string) string {
	copied := *buffer
	copied.WriteString("clean")
	result := copied.String()
	copied.Reset()
	buffer.Reset()
	buffer.WriteString(input)
	return result
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp

import (
	"bytes"
	"strings"
)

func BuilderString(input string) string {
	var builder strings.Builder
	builder.WriteString("prefix:")
	builder.WriteString(input)
	builder.Grow(128)
	builder.WriteByte('!')
	return builder.String()
}

func BuilderBytes(input []byte) string {
	var builder strings.Builder
	builder.Write(input)
	builder.WriteRune('!')
	return builder.String()
}

func BuilderReset(input string) string {
	var builder strings.Builder
	builder.WriteString(input)
	builder.Reset()
	builder.WriteString("plain")
	return builder.String()
}

func BufferString(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString("prefix:")
	buffer.WriteString(input)
	buffer.Grow(128)
	buffer.WriteByte('!')
	return buffer.String()
}

func BufferBytes(input []byte) string {
	var buffer bytes.Buffer
	buffer.Write(input)
	buffer.WriteRune('!')
	return buffer.String()
}

func BufferTruncate(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	buffer.Truncate(2)
	return buffer.String()
}

func BufferReset(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	buffer.Reset()
	buffer.WriteString("plain")
	return buffer.String()
}

func BufferIndirectRead(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	read := buffer.Read
	_, _ = read(make([]byte, 1))
	return buffer.String()
}

func BufferBytesMutation(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	value := buffer.Bytes()
	copy(value, "plain!")
	return buffer.String()
}

func BufferGrow(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	buffer.Grow(1024)
	return buffer.String()
}

func NilBufferString() string {
	var buffer *bytes.Buffer
	return buffer.String()
}

func BufferInvalidTruncate() {
	var buffer bytes.Buffer
	buffer.WriteString("value")
	buffer.Truncate(10)
}

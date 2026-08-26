// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"bytes"
	"strings"
	"unsafe"

	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
)

// BuilderWrite wraps strings.Builder.Write.
func BuilderWrite(builder *strings.Builder, value []byte) (int, error) {
	if !internal.WriterActive() {
		return builder.Write(value)
	}
	before := builderView(builder)
	written, err := builder.Write(value)
	internal.UpdateBytesWriter(builder, store.WriterStringBuilder, before, builderView(builder), value, written)
	return written, err
}

// BuilderWriteString wraps strings.Builder.WriteString.
func BuilderWriteString(builder *strings.Builder, value string) (int, error) {
	if !internal.WriterActive() {
		return builder.WriteString(value)
	}
	before := builderView(builder)
	written, err := builder.WriteString(value)
	internal.UpdateStringWriter(builder, store.WriterStringBuilder, before, builderView(builder), value, written)
	return written, err
}

// BuilderWriteByte wraps strings.Builder.WriteByte.
func BuilderWriteByte(builder *strings.Builder, value byte) error {
	if !internal.WriterActive() {
		return builder.WriteByte(value)
	}
	before := builderView(builder)
	err := builder.WriteByte(value)
	internal.UpdateUntaintedWriter(builder, store.WriterStringBuilder, before, builderView(builder), 1)
	return err
}

// BuilderWriteRune wraps strings.Builder.WriteRune.
func BuilderWriteRune(builder *strings.Builder, value rune) (int, error) {
	if !internal.WriterActive() {
		return builder.WriteRune(value)
	}
	before := builderView(builder)
	written, err := builder.WriteRune(value)
	internal.UpdateUntaintedWriter(builder, store.WriterStringBuilder, before, builderView(builder), written)
	return written, err
}

// BuilderGrow wraps strings.Builder.Grow.
func BuilderGrow(builder *strings.Builder, capacity int) {
	if !internal.WriterActive() {
		builder.Grow(capacity)
		return
	}
	before := builderView(builder)
	builder.Grow(capacity)
	internal.UpdateUntaintedWriter(builder, store.WriterStringBuilder, before, builderView(builder), 0)
}

// BuilderReset wraps strings.Builder.Reset.
func BuilderReset(builder *strings.Builder) {
	if !internal.WriterActive() {
		builder.Reset()
		return
	}
	builder.Reset()
	internal.ResetWriter(builder, store.WriterStringBuilder)
}

// BuilderString wraps strings.Builder.String.
func BuilderString(builder *strings.Builder) string {
	if !internal.WriterActive() {
		return builder.String()
	}
	result := builder.String()
	return internal.BuilderString(builder, builderView(builder), result)
}

// BufferWrite wraps bytes.Buffer.Write.
func BufferWrite(buffer *bytes.Buffer, value []byte) (int, error) {
	if !internal.WriterActive() {
		return buffer.Write(value)
	}
	before := bufferView(buffer)
	pointer, marked := expectBufferMutation(buffer)
	defer writerbridge.Cancel(pointer, marked)
	written, err := buffer.Write(value)
	internal.UpdateBytesWriter(buffer, store.WriterBytesBuffer, before, bufferView(buffer), value, written)
	return written, err
}

// BufferWriteString wraps bytes.Buffer.WriteString.
func BufferWriteString(buffer *bytes.Buffer, value string) (int, error) {
	if !internal.WriterActive() {
		return buffer.WriteString(value)
	}
	before := bufferView(buffer)
	pointer, marked := expectBufferMutation(buffer)
	defer writerbridge.Cancel(pointer, marked)
	written, err := buffer.WriteString(value)
	internal.UpdateStringWriter(buffer, store.WriterBytesBuffer, before, bufferView(buffer), value, written)
	return written, err
}

// BufferWriteByte wraps bytes.Buffer.WriteByte.
func BufferWriteByte(buffer *bytes.Buffer, value byte) error {
	if !internal.WriterActive() {
		return buffer.WriteByte(value)
	}
	before := bufferView(buffer)
	pointer, marked := expectBufferMutation(buffer)
	defer writerbridge.Cancel(pointer, marked)
	err := buffer.WriteByte(value)
	internal.UpdateUntaintedWriter(buffer, store.WriterBytesBuffer, before, bufferView(buffer), 1)
	return err
}

// BufferWriteRune wraps bytes.Buffer.WriteRune.
func BufferWriteRune(buffer *bytes.Buffer, value rune) (int, error) {
	if !internal.WriterActive() {
		return buffer.WriteRune(value)
	}
	before := bufferView(buffer)
	pointer, marked := expectBufferMutation(buffer)
	nested := writerbridge.Expect(pointer) // ASCII WriteRune delegates to WriteByte.
	defer writerbridge.Cancel(pointer, nested)
	defer writerbridge.Cancel(pointer, marked)
	written, err := buffer.WriteRune(value)
	internal.UpdateUntaintedWriter(buffer, store.WriterBytesBuffer, before, bufferView(buffer), written)
	return written, err
}

// BufferGrow wraps bytes.Buffer.Grow.
func BufferGrow(buffer *bytes.Buffer, capacity int) {
	if !internal.WriterActive() {
		buffer.Grow(capacity)
		return
	}
	before := bufferView(buffer)
	pointer, marked := expectBufferMutation(buffer)
	defer writerbridge.Cancel(pointer, marked)
	buffer.Grow(capacity)
	internal.UpdateUntaintedWriter(buffer, store.WriterBytesBuffer, before, bufferView(buffer), 0)
}

// BufferReset wraps bytes.Buffer.Reset.
func BufferReset(buffer *bytes.Buffer) {
	if !internal.WriterActive() {
		buffer.Reset()
		return
	}
	pointer, marked := expectBufferMutation(buffer)
	defer writerbridge.Cancel(pointer, marked)
	buffer.Reset()
	internal.ResetWriter(buffer, store.WriterBytesBuffer)
}

// BufferTruncate wraps bytes.Buffer.Truncate.
func BufferTruncate(buffer *bytes.Buffer, length int) {
	if !internal.WriterActive() {
		buffer.Truncate(length)
		return
	}
	before := bufferView(buffer)
	pointer, marked := expectBufferMutation(buffer)
	defer writerbridge.Cancel(pointer, marked)
	buffer.Truncate(length)
	internal.TruncateWriter(buffer, store.WriterBytesBuffer, before, bufferView(buffer))
}

// BufferString wraps bytes.Buffer.String.
func BufferString(buffer *bytes.Buffer) string {
	if buffer == nil {
		return buffer.String()
	}
	if !internal.WriterActive() {
		return buffer.String()
	}
	result := buffer.String()
	return internal.BufferString(buffer, bufferView(buffer), result)
}

func builderView(builder *strings.Builder) store.WriterView {
	value := builder.String()
	return writerView(stringPointer(value), builder.Len(), builder.Cap())
}

func bufferView(buffer *bytes.Buffer) store.WriterView {
	pointer, marked := expectBufferMutation(buffer)
	defer writerbridge.Cancel(pointer, marked)
	value := buffer.Bytes()
	return writerView(bytesPointer(value), buffer.Len(), buffer.Cap())
}

func writerView(pointer uintptr, length, capacity int) store.WriterView {
	if length < 0 || capacity < 0 || length > store.MaxRootBytes || capacity > store.MaxRootBytes {
		return store.WriterView{Pointer: pointer, Length: store.MaxRootBytes + 1, Capacity: store.MaxRootBytes + 1}
	}
	return store.WriterView{Pointer: pointer, Length: uint32(length), Capacity: uint32(capacity)}
}

func expectBufferMutation(buffer *bytes.Buffer) (uintptr, bool) {
	pointer := uintptr(unsafe.Pointer(buffer))
	return pointer, writerbridge.Expect(pointer)
}

func stringPointer(value string) uintptr {
	if len(value) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.StringData(value)))
}

func bytesPointer(value []byte) uintptr {
	if len(value) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(value)))
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp

import (
	"bytes"
	"io"
	"strings"
	"unsafe"
)

// BufferCopyRead exercises ordinary value copies rather than wrapper calls.
func BufferCopyRead(input, mode string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	switch mode {
	case "value":
		return bufferValueString(buffer)
	case "return":
		buffer = returnedBuffer(input)
	case "struct":
		original := struct{ Buffer bytes.Buffer }{Buffer: buffer}
		copied := original
		return copied.Buffer.String()
	}
	copied := buffer
	return copied.String()
}

func bufferValueString(buffer bytes.Buffer) string { return buffer.String() }

func returnedBuffer(input string) bytes.Buffer {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	return buffer
}

// BufferPeekOverwrite returns the host result after mutating a Peek alias.
func BufferPeekOverwrite(input, mode string) (string, error) {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	var value []byte
	var err error
	switch mode {
	case "method":
		peek := buffer.Peek
		value, err = peek(len(input))
	case "copy":
		copied := buffer
		value, err = copied.Peek(len(input))
	case "interface":
		var peeker interface{ Peek(int) ([]byte, error) } = &buffer
		value, err = peeker.Peek(len(input))
	case "eof":
		value, err = buffer.Peek(len(input) + 1)
	case "zero":
		value, err = buffer.Peek(0)
		value = value[:len(input)]
	default:
		value, err = buffer.Peek(len(input))
	}
	copy(value, "plain!")
	return buffer.String(), err
}

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

// BufferCopyAppend exercises direct writes through an exact value copy.
func BufferCopyAppend(input, suffix, mode string) (string, int, error) {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	copied := buffer
	var n int
	var err error
	switch mode {
	case "grow":
		copied.Grow(1024)
		n, err = copied.WriteString(suffix)
	case "bytes":
		n, err = copied.Write([]byte(suffix))
	case "byte":
		err = copied.WriteByte('!')
		n = 1
	case "rune":
		n, err = copied.WriteRune('!')
	case "wide-rune":
		n, err = copied.WriteRune('界')
	default:
		n, err = copied.WriteString(suffix)
	}
	return copied.String(), n, err
}

// BufferCopyReset distinguishes a header change from the later backing write.
func BufferCopyReset(input string, indirect bool) (string, string, [4]uintptr, [4]uintptr) {
	buffer := bytes.NewBuffer(make([]byte, 0, 64))
	backing := buffer.Bytes() // Observe before tracking, not before publication.
	buffer.WriteString(input)
	copied := *buffer
	before := [4]uintptr{uintptr(unsafe.Pointer(unsafe.SliceData(backing))), uintptr(buffer.Len()), uintptr(buffer.Cap()), uintptr(buffer.Available())}
	if indirect {
		reset := copied.Reset
		reset()
	} else {
		copied.Reset()
	}
	unchanged := buffer.String()
	if indirect {
		write := copied.WriteString
		write("plain!")
	} else {
		copied.WriteString("plain!")
	}
	result := buffer.String()
	backing = buffer.Bytes() // Publication must precede this exposure hook.
	after := [4]uintptr{uintptr(unsafe.Pointer(unsafe.SliceData(backing))), uintptr(buffer.Len()), uintptr(buffer.Cap()), uintptr(buffer.Available())}
	return unchanged, result, before, after
}

// BufferCopyCompaction starts with an interior backing and a nonzero offset.
func BufferCopyCompaction(input string) (string, int, int) {
	backing := make([]byte, 160)
	buffer := bytes.NewBuffer(backing[13:113:141])
	buffer.Next(96)
	buffer.WriteString(input)
	copied := *buffer
	before := copied.Available()
	copied.Grow(30)
	return copied.String(), before, copied.Available()
}

// BufferCopyExhausted mutates through a zero-capacity unread view.
func BufferCopyExhausted(input string) string {
	buffer := bytes.NewBuffer(make([]byte, 0, len(input)))
	buffer.WriteString(input)
	copied := *buffer
	copied.Next(len(input))
	buffer.Reset()
	buffer.WriteString(input)
	copied.WriteString("plain!")
	return buffer.String()
}

// BufferOldAllocation writes through the copy left behind by a reallocation.
func BufferOldAllocation(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	copied := buffer
	buffer.Grow(1024)
	copied.Reset()
	copied.WriteString("plain!")
	return buffer.String()
}

// BufferAssignedReceiver retains the old allocation only through a value copy.
func BufferAssignedReceiver(input string) (string, string) {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	copied := buffer
	buffer = *bytes.NewBufferString("clean!")
	return copied.String(), buffer.String()
}

// BufferIndependent checks that equal content is not used as alias identity.
func BufferIndependent(first, second string) (string, string, string) {
	var buffer, independent bytes.Buffer
	buffer.WriteString(first)
	independent.WriteString(second)
	clean := bytes.NewBufferString("attack")
	cleanResult := clean.String()
	buffer.Reset()
	buffer.WriteString("plain!")
	return buffer.String(), independent.String(), cleanResult
}

// BufferExpectedPeerWrite overwrites a peer even though its own call is wrapped.
func BufferExpectedPeerWrite(input string) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	copied := buffer
	copied.WriteString("suffix")
	buffer.WriteString("plain!")
	return copied.String()
}

// BufferCopyTruncate retains the copied prefix, including nested Reset at zero.
func BufferCopyTruncate(input string, length int) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	copied := buffer
	copied.Truncate(length)
	return copied.String()
}

// BufferHostPanic exposes the original negative-argument and nil behavior.
func BufferHostPanic(mode string) {
	var buffer bytes.Buffer
	switch mode {
	case "peek":
		buffer.Peek(-1)
	case "truncate":
		buffer.Truncate(-1)
	case "grow":
		buffer.Grow(-1)
	case "nil-grow":
		var nilBuffer *bytes.Buffer
		nilBuffer.Grow(-1)
	case "nil-write":
		var nilBuffer *bytes.Buffer
		nilBuffer.WriteString("hello")
	}
}

// BufferReadFrom preserves host errors while invalidating unsupported input.
func BufferReadFrom(input string, reader io.Reader) (string, int64, error) {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	n, err := buffer.ReadFrom(reader)
	return buffer.String(), n, err
}

// BufferDivergentCopy shows the deliberate exact-view historical-view miss.
func BufferDivergentCopy(input string, truncate bool) string {
	var buffer bytes.Buffer
	buffer.WriteString(input)
	copied := buffer
	if truncate {
		copied.Truncate(2)
		return buffer.String()
	}
	buffer.WriteString("clean")
	return copied.String()
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/stretchr/testify/require"
)

func testBuilderView(builder *strings.Builder) store.WriterView {
	value := builder.String()
	var pointer uintptr
	if len(value) != 0 {
		pointer = uintptr(unsafe.Pointer(unsafe.StringData(value)))
	}
	return store.WriterView{Pointer: pointer, Length: uint32(len(value)), Capacity: uint32(builder.Cap())}
}

func testBufferView(buffer *bytes.Buffer) store.WriterView {
	var value []byte
	testExpectedBufferMutation(buffer, func() { value = buffer.Bytes() })
	view := store.WriterView{Length: uint32(len(value)), Capacity: uint32(buffer.Cap())}
	if len(value) != 0 {
		view.Pointer = uintptr(unsafe.Pointer(unsafe.SliceData(value)))
	}
	if cap(value) != 0 {
		view.Anchor = unsafe.SliceData(value)
		view.Backing = uintptr(unsafe.Pointer(view.Anchor)) - uintptr(buffer.Cap()-cap(value))
	}
	return view
}

// Internal packages do not receive call-site advice. Exercise the native
// operations and their callbacks explicitly in both build modes.
func testExpectedBufferMutation(buffer *bytes.Buffer, mutation func()) {
	pointer := uintptr(unsafe.Pointer(buffer))
	marked := writerbridge.Expect(pointer)
	defer writerbridge.Cancel(pointer, marked)
	mutation()
}

func testBuilderWriteString(t *testing.T, builder *strings.Builder, value string) {
	t.Helper()
	before := testBuilderView(builder)
	written, err := builder.WriteString(value)
	require.NoError(t, err)
	propagation.UpdateStringWriter(builder, store.WriterStringBuilder, before, testBuilderView(builder), value, written)
}

func testBufferWriteString(t *testing.T, buffer *bytes.Buffer, value string) {
	t.Helper()
	before := testBufferView(buffer)
	propagation.PrepareBufferWriter(buffer, before)
	var written int
	var err error
	testExpectedBufferMutation(buffer, func() { written, err = buffer.WriteString(value) })
	require.NoError(t, err)
	propagation.UpdateStringWriter(buffer, store.WriterBytesBuffer, before, testBufferView(buffer), value, written)
}

func TestWriterResultsPreserveContributorsMarksAndNativeIdentity(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	stringInput, _ := taintString(t, owner, "attack", []ranges.Range{{Start: 1, Length: 4, SourceID: 3, Marks: 0xe}})
	byteInput, _ := taintBytes(t, owner, []byte("bytes"), []ranges.Range{{Length: 3, SourceID: 7, Marks: 0x4}})
	var builder strings.Builder
	testBuilderWriteString(t, &builder, "prefix:")
	require.False(t, propagation.WriterInvalidationActive())
	testBuilderWriteString(t, &builder, stringInput)
	before := testBuilderView(&builder)
	written, err := builder.Write(byteInput)
	require.NoError(t, err)
	propagation.UpdateBytesWriter(&builder, store.WriterStringBuilder, before, testBuilderView(&builder), byteInput, written)
	before = testBuilderView(&builder)
	require.NoError(t, builder.WriteByte('!'))
	propagation.UpdateUntaintedWriter(&builder, store.WriterStringBuilder, before, testBuilderView(&builder), 1)
	require.True(t, propagation.WriterInvalidationActive())
	nativeBuilder := builder.String()
	built := propagation.BuilderString(&builder, testBuilderView(&builder), nativeBuilder)
	require.Equal(t, "prefix:attackbytes!", built)
	require.True(t, unsafe.StringData(built) != unsafe.StringData(nativeBuilder))
	require.Equal(t, []ranges.Range{{Start: 8, Length: 4, SourceID: 3, Marks: 0xe}, {Start: 13, Length: 3, SourceID: 7, Marks: 0x4}}, lookupRanges(s, built))

	var buffer bytes.Buffer
	buffer.Grow(32)
	testBufferWriteString(t, &buffer, "clean:")
	testBufferWriteString(t, &buffer, stringInput)
	nativeBuffer := buffer.String()
	bufferResult := propagation.BufferString(&buffer, testBufferView(&buffer), nativeBuffer)
	require.Equal(t, "clean:attack", bufferResult)
	require.True(t, unsafe.StringData(bufferResult) == unsafe.StringData(nativeBuffer))
	require.Equal(t, []ranges.Range{{Start: 7, Length: 4, SourceID: 3, Marks: 0xe}}, lookupRanges(s, bufferResult))
}

func TestWriterTruncateResetAndAnchoredCopyLifetime(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintString(t, owner, "attack", []ranges.Range{{Length: 6, SourceID: 9, Marks: 0x2}})
	var buffer bytes.Buffer
	buffer.Grow(32)
	testBufferWriteString(t, &buffer, input)
	copied := buffer
	before := testBufferView(&copied)
	propagation.PrepareBufferWriter(&copied, before)
	testExpectedBufferMutation(&copied, func() { require.NoError(t, copied.WriteByte('!')) })
	propagation.UpdateUntaintedWriter(&copied, store.WriterBytesBuffer, before, testBufferView(&copied), 1)
	result := propagation.BufferString(&copied, testBufferView(&copied), copied.String())
	require.Equal(t, "attack!", result)
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 9, Marks: 0x2}}, lookupRanges(s, result))

	before = testBufferView(&copied)
	propagation.PrepareBufferWriter(&copied, before)
	testExpectedBufferMutation(&copied, func() { copied.Truncate(3) })
	propagation.TruncateWriter(&copied, store.WriterBytesBuffer, before, testBufferView(&copied))
	truncated := propagation.BufferString(&copied, testBufferView(&copied), copied.String())
	require.Equal(t, "att", truncated)
	require.Equal(t, []ranges.Range{{Length: 3, SourceID: 9, Marks: 0x2}}, lookupRanges(s, truncated))
	testExpectedBufferMutation(&copied, copied.Reset)
	propagation.ResetWriter(&copied, store.WriterBytesBuffer)
	require.False(t, s.HasWriterStates())
	require.False(t, propagation.WriterInvalidationActive())
}

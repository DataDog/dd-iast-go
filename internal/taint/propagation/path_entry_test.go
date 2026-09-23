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
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestPathEngineNoActiveStoreEntryPoints(t *testing.T) {
	require.Nil(t, request.ActiveStore())

	byteInput := []byte{'a', 0xff}
	byteReplacement := []byte("?")
	validUTF8 := bytes.ToValidUTF8(byteInput, byteReplacement)
	validUTF8Data := unsafe.SliceData(validUTF8)
	require.Equal(t, validUTF8, propagation.ValidUTF8Bytes(byteInput, byteReplacement, validUTF8))
	require.True(t, unsafe.SliceData(validUTF8) == validUTF8Data)

	convertedNative := strings.Clone("clean")
	converted := propagation.BytesToString([]byte("clean"), convertedNative)
	require.True(t, unsafe.StringData(converted) == unsafe.StringData(convertedNative))

	caseNative := strings.ToUpper("clean")
	cased := propagation.CaseString("clean", caseNative)
	require.True(t, unsafe.StringData(cased) == unsafe.StringData(caseNative))

	document := []byte(`{"value":"clean"}`)
	literal := document[9:16]
	decodedNative := strings.Clone("clean")
	decoded, propagated := propagation.JSONString(document, literal, decodedNative)
	require.False(t, propagated)
	require.True(t, unsafe.StringData(decoded) == unsafe.StringData(decodedNative))

	byteWindows := [][]byte{byteInput[:1], byteInput[1:]}
	propagation.ByteWindows(byteInput, byteWindows)

	object := &struct{ value int }{value: 1}
	before := store.WriterView{Pointer: 1, Length: 2, Capacity: 8}
	after := store.WriterView{Pointer: 1, Length: 4, Capacity: 8}
	propagation.PrepareBufferWriter(object, before)
	propagation.UpdateStringWriter(object, store.WriterStringBuilder, before, after, "xy", 2)
	propagation.UpdateBytesWriter(object, store.WriterBytesBuffer, before, after, []byte("xy"), 2)
	propagation.UpdateUntaintedWriter(object, store.WriterStringBuilder, before, after, 2)
	propagation.ResetWriter(object, store.WriterStringBuilder)
	propagation.TruncateWriter(object, store.WriterBytesBuffer, after, before)

	builderNative := strings.Clone("builder")
	builder := propagation.BuilderString(object, after, builderNative)
	require.True(t, unsafe.StringData(builder) == unsafe.StringData(builderNative))
	bufferNative := strings.Clone("buffer")
	buffer := propagation.BufferString(object, after, bufferNative)
	require.True(t, unsafe.StringData(buffer) == unsafe.StringData(bufferNative))
}

func TestPathIneligibleResultsPreserveNativeValues(t *testing.T) {
	_, _ = beginScope(t)

	oversizedString := strings.Repeat("x", store.MaxRootBytes+1)
	oversizedBytes := bytes.Repeat([]byte{'x'}, store.MaxRootBytes+1)

	for name, test := range map[string]struct {
		input  []byte
		result string
	}{
		"one byte":  {input: []byte("x"), result: "x"},
		"mismatch":  {input: []byte("ab"), result: "abc"},
		"oversized": {input: oversizedBytes, result: oversizedString},
	} {
		t.Run("bytes to string/"+name, func(t *testing.T) {
			result := propagation.BytesToString(test.input, test.result)
			require.Equal(t, test.result, result)
			if len(result) != 0 {
				require.True(t, unsafe.StringData(result) == unsafe.StringData(test.result))
			}
		})
	}

	for name, result := range map[string][]byte{
		"empty":           nil,
		"one byte":        {'x'},
		"oversized len":   oversizedBytes,
		"oversized cap":   make([]byte, 2, store.MaxRootBytes+1),
		"zero length cap": make([]byte, 0, 8),
	} {
		t.Run("valid UTF-8/"+name, func(t *testing.T) {
			got := propagation.ValidUTF8Bytes([]byte{'a', 0xff}, []byte("?"), result)
			require.Equal(t, result, got)
			if len(result) != 0 {
				require.True(t, unsafe.SliceData(got) == unsafe.SliceData(result))
			}
		})
	}

	for name, result := range map[string]string{
		"empty":     "",
		"oversized": oversizedString,
	} {
		t.Run("string transforms/"+name, func(t *testing.T) {
			require.Equal(t, result, propagation.CaseString("input", result))
			require.Equal(t, result, propagation.JoinString([]string{"input"}, "", result))
			require.Equal(t, result, propagation.ReplaceString("input", "input", "", result, -1))
			require.Equal(t, result, propagation.CoarseFormattedString(result, "%s", []any{"input"}))
		})
	}

	native := strings.Clone("native-result")
	got := propagation.CoarseString(native, "", "clean")
	require.True(t, unsafe.StringData(got) == unsafe.StringData(native), "an empty operand must not change the native result")
}

func TestPathActiveUntaintedInputsRemainUnpublished(t *testing.T) {
	s, _ := beginScope(t)

	cleanString := strings.Clone("clean-input")
	stringWindow := cleanString[1:5]
	propagation.StringWindow(cleanString, stringWindow)
	require.Nil(t, lookupRanges(s, stringWindow))

	casedNative := strings.ToUpper(cleanString)
	cased := propagation.CaseString(cleanString, casedNative)
	require.True(t, unsafe.StringData(cased) == unsafe.StringData(casedNative))
	require.Nil(t, lookupRanges(s, cased))

	cleanBytes := bytes.Clone([]byte("clean-input"))
	byteWindows := [][]byte{cleanBytes[:3], cleanBytes[3:]}
	propagation.ByteWindows(cleanBytes, byteWindows)
	require.Nil(t, lookupByteRanges(s, byteWindows[0]))

	byteCopyNative := bytes.Clone(cleanBytes)
	byteCopy := propagation.CopyBytes(cleanBytes, byteCopyNative)
	require.True(t, unsafe.SliceData(byteCopy) == unsafe.SliceData(byteCopyNative))
	require.Nil(t, lookupByteRanges(s, byteCopy))

	convertedNative := strings.Clone(string(cleanBytes))
	converted := propagation.BytesToString(cleanBytes, convertedNative)
	require.True(t, unsafe.StringData(converted) == unsafe.StringData(convertedNative))
	require.Nil(t, lookupRanges(s, converted))

	invalid := []byte{'a', 0xff}
	validNative := bytes.ToValidUTF8(invalid, []byte("?"))
	valid := propagation.ValidUTF8Bytes(invalid, []byte("?"), validNative)
	require.True(t, unsafe.SliceData(valid) == unsafe.SliceData(validNative))
	require.Nil(t, lookupByteRanges(s, valid))
}

func TestPathOneByteBuilderResultIsRejected(t *testing.T) {
	s, _ := beginScope(t)
	native := strings.Clone("x")
	result := propagation.BuilderString(&struct{}{}, store.WriterView{Pointer: 1, Length: 1, Capacity: 8}, native)
	require.True(t, unsafe.StringData(result) == unsafe.StringData(native))
	require.Nil(t, lookupRanges(s, result))
	require.Zero(t, s.ProcessCharged())
}

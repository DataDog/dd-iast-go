// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestExactNativeTransformsPreserveRangesAndMarks(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	want := []ranges.Range{{Length: 1, SourceID: 3, Marks: 0xe}, {Start: 2, Length: 1, SourceID: 5, Marks: 0x6}}
	input, _ := taintString(t, owner, "abc", want)
	nativeRepeat := strings.Repeat(input, 3)
	repeated := propagation.RepeatString(input, nativeRepeat, 3)
	require.True(t, unsafe.StringData(repeated) != unsafe.StringData(nativeRepeat))
	require.Equal(t, []ranges.Range{
		{Length: 1, SourceID: 3, Marks: 0xe}, {Start: 2, Length: 1, SourceID: 5, Marks: 0x6},
		{Start: 3, Length: 1, SourceID: 3, Marks: 0xe}, {Start: 5, Length: 1, SourceID: 5, Marks: 0x6},
		{Start: 6, Length: 1, SourceID: 3, Marks: 0xe}, {Start: 8, Length: 1, SourceID: 5, Marks: 0x6},
	}, lookupRanges(s, repeated))

	window := input[1:3]
	propagation.StringWindow(input, window)
	require.Equal(t, []ranges.Range{{Start: 1, Length: 1, SourceID: 5, Marks: 0x6}}, lookupRanges(s, window))
	joinedNative := strings.Join([]string{input}, "")
	require.True(t, unsafe.StringData(joinedNative) == unsafe.StringData(input))
	joined := propagation.JoinString([]string{input}, "", joinedNative)
	require.True(t, unsafe.StringData(joined) == unsafe.StringData(input))
	require.Equal(t, want, lookupRanges(s, joined))
	adoptedNative := string([]byte(input))
	adopted := propagation.AdoptStringCopy(input, adoptedNative)
	require.True(t, unsafe.StringData(adopted) == unsafe.StringData(adoptedNative))
	require.Equal(t, want, lookupRanges(s, adopted))

	byteInput, _ := taintBytes(t, owner, []byte("wxyz"), []ranges.Range{{Start: 1, Length: 2, SourceID: 8, Marks: 0xa}})
	nativeBytes := bytes.Repeat(byteInput, 2)
	data := unsafe.SliceData(nativeBytes)
	byteRepeat := propagation.RepeatBytes(byteInput, nativeBytes, 2)
	require.True(t, unsafe.SliceData(byteRepeat) == data)
	require.Equal(t, []ranges.Range{{Start: 1, Length: 2, SourceID: 8, Marks: 0xa}, {Start: 5, Length: 2, SourceID: 8, Marks: 0xa}}, lookupByteRanges(s, byteRepeat))
	convertedNative := string(byteInput)
	converted := propagation.BytesToString(byteInput, convertedNative)
	require.True(t, unsafe.StringData(converted) == unsafe.StringData(convertedNative))
	require.Equal(t, []ranges.Range{{Start: 1, Length: 2, SourceID: 8, Marks: 0xa}}, lookupRanges(s, converted))
}

func TestWindowFanoutClipsRangesAndDropsExcessSafely(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintBytes(t, owner, []byte(strings.Repeat("abcd|", 34)+"abcd"), []ranges.Range{
		{Start: 2, Length: 5, SourceID: 2, Marks: 0xc}, {Start: 160, Length: 4, SourceID: 4, Marks: 0x4},
	})
	outputs := bytes.Split(input, []byte("|"))
	propagation.ByteWindows(input, outputs)
	require.Equal(t, []ranges.Range{{Start: 2, Length: 2, SourceID: 2, Marks: 0xc}}, lookupByteRanges(s, outputs[0]))
	require.Equal(t, []ranges.Range{{Length: 2, SourceID: 2, Marks: 0xc}}, lookupByteRanges(s, outputs[1]))
	require.Empty(t, lookupByteRanges(s, outputs[2]))
	require.Nil(t, lookupByteRanges(s, outputs[32]))
}

func TestCoarseOperationsIntersectSecureMarksPerOwner(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	first, _ := taintString(t, owner, "first", []ranges.Range{{Length: 5, SourceID: 11, Marks: 0xe}})
	second, _ := taintString(t, owner, "second", []ranges.Range{{Length: 6, SourceID: 12, Marks: 0x6}})
	native := fmt.Sprintf("%s/%s", first, second)
	coarse := propagation.CoarseString(native, first, second)
	require.True(t, unsafe.StringData(coarse) != unsafe.StringData(native))
	require.Equal(t, []ranges.Range{{Length: uint32(len(coarse)), SourceID: 11, Marks: 0x6}}, lookupRanges(s, coarse))
	format, _ := taintString(t, owner, "%s %d %v", []ranges.Range{{Length: 2, SourceID: 13, Marks: 0xe}})
	arguments := []any{second, 42, nil}
	formatted := propagation.CoarseFormattedString(fmt.Sprintf(format, arguments...), format, arguments)
	require.Equal(t, []ranges.Range{{Length: uint32(len(formatted)), SourceID: 13, Marks: 0x6}}, lookupRanges(s, formatted))

	firstBytes, _ := taintBytes(t, owner, []byte("alpha"), []ranges.Range{{Length: 5, SourceID: 21, Marks: 0xa}})
	secondBytes, _ := taintBytes(t, owner, []byte("beta"), []ranges.Range{{Length: 4, SourceID: 22, Marks: 0x2}})
	byteNative := bytes.Join([][]byte{firstBytes, secondBytes}, []byte("/"))
	data := unsafe.SliceData(byteNative)
	coarseBytes := propagation.CoarseBytes(byteNative, firstBytes, secondBytes)
	require.True(t, unsafe.SliceData(coarseBytes) == data)
	require.Equal(t, []ranges.Range{{Length: uint32(len(coarseBytes)), SourceID: 21, Marks: 0x2}}, lookupByteRanges(s, coarseBytes))
	cleanArguments := []any{42, nil, []byte(nil)}
	clean := fmt.Sprint(cleanArguments...)
	require.Equal(t, clean, propagation.CoarseFormatString(clean, cleanArguments))
	require.Nil(t, lookupRanges(s, clean))
}

func TestByteReplacementFallsBackBeyondExactSegmentBudget(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	raw := bytes.Repeat([]byte{'x', 0xff}, 33)
	input, _ := taintBytes(t, owner, raw, []ranges.Range{{Length: uint32(len(raw)), SourceID: 31, Marks: 0xc}})
	replacement, _ := taintBytes(t, owner, []byte("??"), []ranges.Range{{Length: 2, SourceID: 32, Marks: 0x6}})
	for _, operation := range []struct {
		name   string
		native func() []byte
		apply  func([]byte) []byte
	}{
		{
			"invalid UTF-8 runs",
			func() []byte { return bytes.ToValidUTF8(input, replacement) },
			func(result []byte) []byte { return propagation.ValidUTF8Bytes(input, replacement, result) },
		},
		{
			"empty old value",
			func() []byte { return bytes.ReplaceAll(input, nil, replacement) },
			func(result []byte) []byte { return propagation.ReplaceBytes(input, nil, replacement, result, -1) },
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			native := operation.native()
			want := bytes.Clone(native)
			result := operation.apply(native)
			require.True(t, unsafe.SliceData(result) == unsafe.SliceData(native))
			require.Equal(t, want, result)
			require.Equal(t, []ranges.Range{{Length: uint32(len(result)), SourceID: 31, Marks: 0x4}}, lookupByteRanges(s, result))
		})
	}
	unchanged := bytes.Replace(input, []byte("x"), replacement, 0)
	result := propagation.ReplaceBytes(input, []byte("x"), replacement, unchanged, 0)
	require.Equal(t, input, result)
	require.Equal(t, []ranges.Range{{Length: uint32(len(input)), SourceID: 31, Marks: 0xc}}, lookupByteRanges(s, result))

	unicodeInput, _ := taintBytes(t, owner, []byte("\u00e9\xff\u00e9"), []ranges.Range{{Length: 5, SourceID: 33}})
	valid := bytes.ToValidUTF8(unicodeInput, []byte("?"))
	propagation.ValidUTF8Bytes(unicodeInput, []byte("?"), valid)
	require.Equal(t, []byte("\u00e9?\u00e9"), valid)
	require.Equal(t, []ranges.Range{{Length: 2, SourceID: 33}, {Start: 3, Length: 2, SourceID: 33}}, lookupByteRanges(s, valid))
}

func TestCoarseByteAliasesKeepExactWindows(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintBytes(t, owner, []byte(" preattackpost "), []ranges.Range{{Start: 4, Length: 6, SourceID: 41, Marks: 0xa}})
	window := bytes.TrimSpace(input)
	result := propagation.CoarseBytes(window, input, window)
	require.True(t, unsafe.SliceData(result) == unsafe.SliceData(window))
	require.Equal(t, []ranges.Range{{Start: 3, Length: 6, SourceID: 41, Marks: 0xa}}, lookupByteRanges(s, result))
	inputs := make([][]byte, 17)
	for index := range inputs {
		inputs[index] = input
	}
	joined := bytes.Join(inputs, nil)
	propagation.CoarseBytes(joined, inputs...)
	require.Equal(t, []ranges.Range{{Length: uint32(len(joined)), SourceID: 41, Marks: 0xa}}, lookupByteRanges(s, joined))
}

func TestSplitEmptyAndSingleByteWindowsPreserveProvenance(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	text, _ := taintString(t, owner, ",a", []ranges.Range{{Length: 2, SourceID: 51}})
	textParts := strings.Split(text, ",")
	propagation.StringWindows(text, textParts)
	propagation.StringWindow(text, textParts[1])
	require.Nil(t, lookupRanges(s, textParts[0]))
	require.Equal(t, []ranges.Range{{Length: 1, SourceID: 51}}, lookupRanges(s, textParts[1]))
	data, _ := taintBytes(t, owner, []byte(",a"), []ranges.Range{{Length: 2, SourceID: 52}})
	parts := bytes.Split(data, []byte(","))
	propagation.ByteWindows(data, parts)
	propagation.ByteWindow(data, parts[1])
	require.Nil(t, lookupByteRanges(s, parts[0]))
	require.Equal(t, []ranges.Range{{Length: 1, SourceID: 52}}, lookupByteRanges(s, parts[1]))
}

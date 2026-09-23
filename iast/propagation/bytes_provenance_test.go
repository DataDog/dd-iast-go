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

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestAllocatingByteOperationsUseBoundedCoarseProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	sqlAndCommand := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	sqlOnly := []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection}

	t.Run("join uses first contributor and mark intersection", func(t *testing.T) {
		firstSource := nativeByteSource(t, ctx, "first", []byte("first-source"))
		secondSource := nativeByteSource(t, ctx, "second", []byte("second-source"))
		separatorSource := nativeByteSource(t, ctx, "separator", []byte("separator-source"))
		first := nativeBytesWithRanges(t, []byte("aa"),
			nativeByteRangeSeed{source: firstSource, length: 2, marks: sqlAndCommand},
		)
		second := nativeBytesWithRanges(t, []byte("bb"),
			nativeByteRangeSeed{source: secondSource, length: 2, marks: sqlOnly},
		)
		separator := nativeBytesWithRanges(t, []byte("::"),
			nativeByteRangeSeed{source: separatorSource, length: 2, marks: sqlOnly},
		)
		elements := make([][]byte, 17)
		for index := range elements {
			elements[index] = []byte("x")
		}
		elements[0] = first
		elements[14] = second

		got := testapp.BytesJoin(elements, separator)
		require.Equal(t, bytes.Join(elements, []byte("::")), got)
		requireNativeByteRanges(t, got, nativeExpectedRange{
			length: uint32(len(got)),
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "first"},
				Value:  "first-source",
			},
			marks: sqlOnly,
		})
	})

	t.Run("replace uses input source and contributor intersection", func(t *testing.T) {
		inputValue := []byte(strings.Repeat("a", 33))
		inputSource := nativeByteSource(t, ctx, "replace-input", inputValue)
		replacementSource := nativeByteSource(t, ctx, "replace-value", []byte("bb"))
		input := nativeBytesWithRanges(t, inputValue,
			nativeByteRangeSeed{
				source: inputSource,
				length: uint32(len(inputValue)),
				marks:  sqlAndCommand,
			},
		)
		replacement := nativeBytesWithRanges(t, []byte("bb"),
			nativeByteRangeSeed{source: replacementSource, length: 2, marks: sqlOnly},
		)

		got := testapp.BytesReplaceAll(input, []byte("a"), replacement)
		require.Equal(t, []byte(strings.Repeat("bb", 33)), got)
		requireNativeByteRanges(t, got, nativeExpectedRange{
			length: uint32(len(got)),
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "replace-input"},
				Value:  string(inputValue),
			},
			marks: sqlOnly,
		})
	})

	t.Run("valid UTF-8 uses input source and contributor intersection", func(t *testing.T) {
		inputValue := bytes.Repeat([]byte{'x', 0xff}, 33)
		inputSource := nativeByteSource(t, ctx, "invalid-input", inputValue)
		replacementSource := nativeByteSource(t, ctx, "repair", []byte("??"))
		input := nativeBytesWithRanges(t, inputValue,
			nativeByteRangeSeed{
				source: inputSource,
				length: uint32(len(inputValue)),
				marks:  sqlAndCommand,
			},
		)
		replacement := nativeBytesWithRanges(t, []byte("??"),
			nativeByteRangeSeed{source: replacementSource, length: 2, marks: sqlOnly},
		)

		got := testapp.BytesToValidUTF8(input, replacement)
		require.Equal(t, bytes.ToValidUTF8(inputValue, []byte("??")), got)
		requireNativeByteRanges(t, got, nativeExpectedRange{
			length: uint32(len(got)),
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "invalid-input"},
				Value:  string(inputValue),
			},
			marks: sqlOnly,
		})
	})
}

func TestByteWindowOperationsPreservePartialRangesAndMarks(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	source := nativeByteSource(t, ctx, "window", []byte("\xffattack"))
	marks := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	value := nativeBytesWithRanges(t, []byte("  \xffattack  "),
		nativeByteRangeSeed{source: source, start: 2, length: 7, marks: marks},
	)
	wantSource := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "window"},
		Value:  "\xffattack",
	}

	clone := testapp.BytesClone(value)
	require.Equal(t, value, clone)
	require.NotEqual(
		t,
		uintptr(unsafe.Pointer(unsafe.SliceData(value))),
		uintptr(unsafe.Pointer(unsafe.SliceData(clone))),
	)
	requireNativeByteRanges(t, clone,
		nativeExpectedRange{start: 2, length: 7, source: wantSource, marks: marks},
	)
	trimmed := testapp.BytesTrimSpace(value)
	require.Equal(t, []byte("\xffattack"), trimmed)
	require.NotEqual(
		t,
		uintptr(unsafe.Pointer(unsafe.SliceData(value))),
		uintptr(unsafe.Pointer(unsafe.SliceData(trimmed))),
	)
	require.Equal(t, 9, cap(trimmed))
	requireNativeByteRanges(t, trimmed,
		nativeExpectedRange{length: 7, source: wantSource, marks: marks},
	)

	unicodeSource := nativeByteSource(t, ctx, "unicode-window", []byte("évil"))
	unicode := nativeBytesWithRanges(t, []byte("  évil  "),
		nativeByteRangeSeed{source: unicodeSource, start: 2, length: 5, marks: marks},
	)
	unicodeTrimmed := testapp.BytesTrimSpace(unicode)
	require.Equal(t, []byte("évil"), unicodeTrimmed)
	requireNativeByteRanges(t, unicodeTrimmed, nativeExpectedRange{
		length: 5,
		source: taint.SourceValue{
			Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "unicode-window"},
			Value:  "évil",
		},
		marks: marks,
	})
}

func TestByteCaseAndValidUTF8BranchesPreserveProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	sqlAndCommand := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	sqlOnly := []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection}

	unicodeSource := nativeByteSource(t, ctx, "unicode", []byte("İ"))
	unicode := nativeBytesWithRanges(t, []byte("AİZ"),
		nativeByteRangeSeed{source: unicodeSource, start: 1, length: 2, marks: sqlAndCommand},
	)
	lowered := testapp.BytesToLower(unicode)
	require.Equal(t, bytes.ToLower([]byte("AİZ")), lowered)
	requireNativeByteRanges(t, lowered, nativeExpectedRange{
		length: uint32(len(lowered)),
		source: taint.SourceValue{
			Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "unicode"},
			Value:  "İ",
		},
		marks: sqlAndCommand,
	})

	inputSource := nativeByteSource(t, ctx, "invalid", []byte("a\xffb"))
	repairSource := nativeByteSource(t, ctx, "repair-exact", []byte("RR"))
	input := nativeBytesWithRanges(t, []byte("a\xffb"),
		nativeByteRangeSeed{source: inputSource, length: 3, marks: sqlAndCommand},
	)
	repair := nativeBytesWithRanges(t, []byte("RR"),
		nativeByteRangeSeed{source: repairSource, length: 2, marks: sqlOnly},
	)
	got := testapp.BytesToValidUTF8(input, repair)
	require.Equal(t, []byte("aRRb"), got)
	inputWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "invalid"},
		Value:  "a\xffb",
	}
	repairWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "repair-exact"},
		Value:  "RR",
	}
	requireNativeByteRanges(t, got,
		nativeExpectedRange{length: 1, source: inputWant, marks: sqlAndCommand},
		nativeExpectedRange{start: 1, length: 2, source: repairWant, marks: sqlOnly},
		nativeExpectedRange{start: 3, length: 1, source: inputWant, marks: sqlAndCommand},
	)
}

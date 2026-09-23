// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestAllocatingStringOperations(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	inputSource := nativeStringSource(t, ctx, "input", "input-source")
	separatorSource := nativeStringSource(t, ctx, "separator", "::")
	replacementSource := nativeStringSource(t, ctx, "replacement", "XY")
	sqlAndCommand := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	sqlOnly := []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection}
	input := nativeStringWithRanges(t, "pre-OLD-post",
		nativeStringRangeSeed{source: inputSource, length: 4, marks: sqlAndCommand},
		nativeStringRangeSeed{source: inputSource, start: 8, length: 4, marks: sqlAndCommand},
	)
	separator := nativeStringWithRanges(t, "::",
		nativeStringRangeSeed{source: separatorSource, length: 2, marks: sqlOnly},
	)
	replacement := nativeStringWithRanges(t, "XY",
		nativeStringRangeSeed{source: replacementSource, length: 2, marks: sqlOnly},
	)
	inputWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "input"},
		Value:  "input-source",
	}
	separatorWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "separator"},
		Value:  "::",
	}
	replacementWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "replacement"},
		Value:  "XY",
	}

	t.Run("join maps elements and separator", func(t *testing.T) {
		got := testapp.Join([]string{"plain", input, "tail"}, separator)
		require.Equal(t, "plain::pre-OLD-post::tail", got)
		requireNativeStringRanges(t, got,
			nativeExpectedRange{start: 5, length: 2, source: separatorWant, marks: sqlOnly},
			nativeExpectedRange{start: 7, length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 15, length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 19, length: 2, source: separatorWant, marks: sqlOnly},
		)
	})

	t.Run("repeat preserves aliases and fresh copies", func(t *testing.T) {
		aliased := testapp.Repeat(input, 1)
		require.Equal(
			t,
			uintptr(unsafe.Pointer(unsafe.StringData(input))),
			uintptr(unsafe.Pointer(unsafe.StringData(aliased))),
		)
		requireNativeStringRanges(t, aliased,
			nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 8, length: 4, source: inputWant, marks: sqlAndCommand},
		)

		got := testapp.Repeat(input, 2)
		require.Equal(t, "pre-OLD-postpre-OLD-post", got)
		require.NotEqual(
			t,
			uintptr(unsafe.Pointer(unsafe.StringData(input))),
			uintptr(unsafe.Pointer(unsafe.StringData(got))),
		)
		requireNativeStringRanges(t, got,
			nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 8, length: 8, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 20, length: 4, source: inputWant, marks: sqlAndCommand},
		)
	})

	for _, test := range []struct {
		name string
		call func() string
	}{
		{name: "replace", call: func() string { return testapp.Replace(input, "OLD", replacement, 1) }},
		{name: "replace all", call: func() string { return testapp.ReplaceAll(input, "OLD", replacement) }},
	} {
		t.Run(test.name+" maps copied and replacement ranges", func(t *testing.T) {
			got := test.call()
			require.Equal(t, "pre-XY-post", got)
			requireNativeStringRanges(t, got,
				nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
				nativeExpectedRange{start: 4, length: 2, source: replacementWant, marks: sqlOnly},
				nativeExpectedRange{start: 7, length: 4, source: inputWant, marks: sqlAndCommand},
			)
		})
	}

	t.Run("unused replacement does not contribute", func(t *testing.T) {
		got := testapp.Replace(input, "missing", replacement, -1)
		require.Equal(
			t,
			uintptr(unsafe.Pointer(unsafe.StringData(input))),
			uintptr(unsafe.Pointer(unsafe.StringData(got))),
		)
		requireNativeStringRanges(t, got,
			nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 8, length: 4, source: inputWant, marks: sqlAndCommand},
		)
	})
}

func TestAllocatingStringOperationsUseBoundedCoarseProvenance(t *testing.T) {
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
		firstSource := nativeStringSource(t, ctx, "first", "first-source")
		secondSource := nativeStringSource(t, ctx, "second", "second-source")
		separatorSource := nativeStringSource(t, ctx, "separator", "separator-source")
		first := nativeStringWithRanges(t, "aa",
			nativeStringRangeSeed{source: firstSource, length: 2, marks: sqlAndCommand},
		)
		second := nativeStringWithRanges(t, "bb",
			nativeStringRangeSeed{source: secondSource, length: 2, marks: sqlOnly},
		)
		separator := nativeStringWithRanges(t, "::",
			nativeStringRangeSeed{source: separatorSource, length: 2, marks: sqlOnly},
		)
		elements := make([]string, 17)
		for index := range elements {
			elements[index] = "x"
		}
		elements[0] = first
		elements[14] = second

		got := testapp.Join(elements, separator)
		require.Equal(t, strings.Join(elements, "::"), got)
		requireNativeStringRanges(t, got, nativeExpectedRange{
			length: uint32(len(got)),
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "first"},
				Value:  "first-source",
			},
			marks: sqlOnly,
		})
	})

	t.Run("replace uses input source and contributor intersection", func(t *testing.T) {
		inputValue := strings.Repeat("a", 33)
		inputSource := nativeStringSource(t, ctx, "replace-input", inputValue)
		replacementSource := nativeStringSource(t, ctx, "replace-value", "bb")
		input := nativeStringWithRanges(t, inputValue,
			nativeStringRangeSeed{
				source: inputSource,
				length: uint32(len(inputValue)),
				marks:  sqlAndCommand,
			},
		)
		replacement := nativeStringWithRanges(t, "bb",
			nativeStringRangeSeed{source: replacementSource, length: 2, marks: sqlOnly},
		)

		got := testapp.ReplaceAll(input, "a", replacement)
		require.Equal(t, strings.Repeat("bb", 33), got)
		requireNativeStringRanges(t, got, nativeExpectedRange{
			length: uint32(len(got)),
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "replace-input"},
				Value:  inputValue,
			},
			marks: sqlOnly,
		})
	})
}

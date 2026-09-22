// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"slices"
	"strings"
	"testing"
	"unicode"
	"unsafe"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestStringWindowOperationsPreservePartialRangesAndMarks(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	source := nativeStringSource(t, ctx, "window", "\xffattack")
	marks := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	value := nativeStringWithRanges(t, "  \xffattack  ",
		nativeStringRangeSeed{source: source, start: 2, length: 7, marks: marks},
	)
	wantSource := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "window"},
		Value:  "\xffattack",
	}

	clone := testapp.Clone(value)
	require.Equal(t, value, clone)
	require.NotEqual(
		t,
		uintptr(unsafe.Pointer(unsafe.StringData(value))),
		uintptr(unsafe.Pointer(unsafe.StringData(clone))),
	)
	requireNativeStringRanges(t, clone,
		nativeExpectedRange{start: 2, length: 7, source: wantSource, marks: marks},
	)
	trimmed := testapp.TrimSpace(value)
	require.Equal(t, "\xffattack", trimmed)
	requireNativeStringRanges(t, trimmed,
		nativeExpectedRange{length: 7, source: wantSource, marks: marks},
	)

	unicodeSource := nativeStringSource(t, ctx, "unicode-window", "évil")
	unicode := nativeStringWithRanges(t, "  évil  ",
		nativeStringRangeSeed{source: unicodeSource, start: 2, length: 5, marks: marks},
	)
	unicodeTrimmed := testapp.TrimSpace(unicode)
	require.Equal(t, "évil", unicodeTrimmed)
	requireNativeStringRanges(t, unicodeTrimmed, nativeExpectedRange{
		length: 5,
		source: taint.SourceValue{
			Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "unicode-window"},
			Value:  "évil",
		},
		marks: marks,
	})
}

func TestStringWindowSequencesInspectOnlyFirstThirtyTwoResults(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	source := nativeStringSource(t, ctx, "sequence", "token")
	marks := []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection}
	delimited := strings.Repeat("aa,", 33) + "aa"
	lines := strings.Repeat("aa\n", 33) + "aa"
	fields := strings.Repeat("aa ", 33) + "aa"
	seed := func(value string) string {
		return nativeStringWithRanges(t, value,
			nativeStringRangeSeed{source: source, start: 31 * 3, length: 2, marks: marks},
			nativeStringRangeSeed{source: source, start: 32 * 3, length: 2, marks: marks},
		)
	}
	wantSource := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "sequence"},
		Value:  "token",
	}
	tests := []struct {
		name string
		call func() []string
		want string
	}{
		{
			name: "SplitSeq",
			call: func() []string { return slices.Collect(strings.SplitSeq(seed(delimited), ",")) },
			want: "aa",
		},
		{
			name: "SplitAfterSeq",
			call: func() []string { return slices.Collect(strings.SplitAfterSeq(seed(delimited), ",")) },
			want: "aa,",
		},
		{
			name: "Lines",
			call: func() []string { return slices.Collect(strings.Lines(seed(lines))) },
			want: "aa\n",
		},
		{
			name: "FieldsSeq",
			call: func() []string { return slices.Collect(strings.FieldsSeq(seed(fields))) },
			want: "aa",
		},
		{
			name: "FieldsFuncSeq",
			call: func() []string {
				return slices.Collect(strings.FieldsFuncSeq(seed(fields), unicode.IsSpace))
			},
			want: "aa",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.call()
			require.Len(t, got, 34)
			require.Equal(t, test.want, got[31])
			requireNativeStringRanges(t, got[31],
				nativeExpectedRange{length: 2, source: wantSource, marks: marks},
			)
			requireNativeStringRanges(t, got[32])
		})
	}
}

func TestStringCaseAndCoarseOperationsPreserveProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	sqlAndCommand := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	sqlOnly := []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection}
	asciiSource := nativeStringSource(t, ctx, "ascii", "ATTACK")
	ascii := nativeStringWithRanges(t, "xATTACKy",
		nativeStringRangeSeed{source: asciiSource, start: 1, length: 6, marks: sqlAndCommand},
	)
	asciiWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "ascii"},
		Value:  "ATTACK",
	}
	for _, test := range []struct {
		name string
		call func(string) string
	}{
		{name: "lower", call: testapp.ToLower},
		{name: "upper", call: testapp.ToUpper},
		{name: "title", call: testapp.ToTitle},
	} {
		t.Run("ASCII "+test.name+" stays exact", func(t *testing.T) {
			got := test.call(ascii)
			requireNativeStringRanges(t, got,
				nativeExpectedRange{start: 1, length: 6, source: asciiWant, marks: sqlAndCommand},
			)
		})
	}

	unicodeSource := nativeStringSource(t, ctx, "unicode", "İ")
	unicode := nativeStringWithRanges(t, "AİZ",
		nativeStringRangeSeed{source: unicodeSource, start: 1, length: 2, marks: sqlAndCommand},
	)
	lowered := testapp.ToLower(unicode)
	require.Equal(t, strings.ToLower("AİZ"), lowered)
	requireNativeStringRanges(t, lowered, nativeExpectedRange{
		length: uint32(len(lowered)),
		source: taint.SourceValue{
			Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "unicode"},
			Value:  "İ",
		},
		marks: sqlAndCommand,
	})

	mapped := testapp.Map(func(r rune) rune { return r + 1 }, ascii)
	require.Equal(t, strings.Map(func(r rune) rune { return r + 1 }, "xATTACKy"), mapped)
	requireNativeStringRanges(t, mapped,
		nativeExpectedRange{length: uint32(len(mapped)), source: asciiWant, marks: sqlAndCommand},
	)

	replacer := *strings.NewReplacer("ATTACK", "changed")
	replaced := replacer.Replace(ascii)
	require.Equal(t, "xchangedy", replaced)
	requireNativeStringRanges(t, replaced,
		nativeExpectedRange{length: uint32(len(replaced)), source: asciiWant, marks: sqlAndCommand},
	)

	invalidSource := nativeStringSource(t, ctx, "invalid", "a\xffb")
	repairSource := nativeStringSource(t, ctx, "repair", "RR")
	invalid := nativeStringWithRanges(t, "a\xffb",
		nativeStringRangeSeed{source: invalidSource, length: 3, marks: sqlAndCommand},
	)
	repair := nativeStringWithRanges(t, "RR",
		nativeStringRangeSeed{source: repairSource, length: 2, marks: sqlOnly},
	)
	valid := testapp.ToValidUTF8(invalid, repair)
	require.Equal(t, "aRRb", valid)
	requireNativeStringRanges(t, valid, nativeExpectedRange{
		length: uint32(len(valid)),
		source: taint.SourceValue{
			Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "invalid"},
			Value:  "a\xffb",
		},
		marks: sqlOnly,
	})

	require.False(t, taint.IsTaintedString(testapp.Join([]string{"clean", "values"}, ":")))
	require.False(t, taint.IsTaintedString(testapp.ToLower("CLEAN")))
}

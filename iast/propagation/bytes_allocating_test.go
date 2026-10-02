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

func TestAllocatingByteOperations(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx := beginNativePropagation(t)
	inputSource := nativeByteSource(t, ctx, "input", []byte("input-source"))
	separatorSource := nativeByteSource(t, ctx, "separator", []byte("::"))
	replacementSource := nativeByteSource(t, ctx, "replacement", []byte("XY"))
	sqlAndCommand := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	sqlOnly := []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection}
	input := nativeBytesWithRanges(t, []byte("pre-OLD-post"),
		nativeByteRangeSeed{source: inputSource, length: 4, marks: sqlAndCommand},
		nativeByteRangeSeed{source: inputSource, start: 8, length: 4, marks: sqlAndCommand},
	)
	separator := nativeBytesWithRanges(t, []byte("::"),
		nativeByteRangeSeed{source: separatorSource, length: 2, marks: sqlOnly},
	)
	replacement := nativeBytesWithRanges(t, []byte("XY"),
		nativeByteRangeSeed{source: replacementSource, length: 2, marks: sqlOnly},
	)
	inputWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "input"},
		Value:  "input-source",
	}
	separatorWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "separator"},
		Value:  "::",
	}
	replacementWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "replacement"},
		Value:  "XY",
	}

	t.Run("join maps elements and separator", func(t *testing.T) {
		got := testapp.BytesJoin([][]byte{[]byte("plain"), input, []byte("tail")}, separator)
		require.Equal(t, []byte("plain::pre-OLD-post::tail"), got)
		require.NotEqual(
			t,
			uintptr(unsafe.Pointer(unsafe.SliceData(input))),
			uintptr(unsafe.Pointer(unsafe.SliceData(got))),
		)
		requireNativeByteRanges(t, got,
			nativeExpectedRange{start: 5, length: 2, source: separatorWant, marks: sqlOnly},
			nativeExpectedRange{start: 7, length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 15, length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 19, length: 2, source: separatorWant, marks: sqlOnly},
		)
	})

	t.Run("repeat preserves fresh-copy ranges", func(t *testing.T) {
		once := testapp.BytesRepeat(input, 1)
		require.Equal(t, input, once)
		require.NotEqual(
			t,
			uintptr(unsafe.Pointer(unsafe.SliceData(input))),
			uintptr(unsafe.Pointer(unsafe.SliceData(once))),
		)
		requireNativeByteRanges(t, once,
			nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 8, length: 4, source: inputWant, marks: sqlAndCommand},
		)

		got := testapp.BytesRepeat(input, 2)
		require.Equal(t, []byte("pre-OLD-postpre-OLD-post"), got)
		require.NotEqual(
			t,
			uintptr(unsafe.Pointer(unsafe.SliceData(input))),
			uintptr(unsafe.Pointer(unsafe.SliceData(got))),
		)
		requireNativeByteRanges(t, got,
			nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 8, length: 8, source: inputWant, marks: sqlAndCommand},
			nativeExpectedRange{start: 20, length: 4, source: inputWant, marks: sqlAndCommand},
		)
	})

	for _, test := range []struct {
		name string
		call func() []byte
	}{
		{
			name: "replace",
			call: func() []byte {
				return testapp.BytesReplace(input, []byte("OLD"), replacement, 1)
			},
		},
		{
			name: "replace all",
			call: func() []byte {
				return testapp.BytesReplaceAll(input, []byte("OLD"), replacement)
			},
		},
	} {
		t.Run(test.name+" maps copied and replacement ranges", func(t *testing.T) {
			got := test.call()
			require.Equal(t, []byte("pre-XY-post"), got)
			require.NotEqual(
				t,
				uintptr(unsafe.Pointer(unsafe.SliceData(input))),
				uintptr(unsafe.Pointer(unsafe.SliceData(got))),
			)
			requireNativeByteRanges(t, got,
				nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
				nativeExpectedRange{start: 4, length: 2, source: replacementWant, marks: sqlOnly},
				nativeExpectedRange{start: 7, length: 4, source: inputWant, marks: sqlAndCommand},
			)
		})
	}

	for _, test := range []struct {
		name string
		call func([]byte) []byte
		want []byte
	}{
		{name: "lower", call: testapp.BytesToLower, want: []byte("pre-old-post")},
		{name: "upper", call: testapp.BytesToUpper, want: []byte("PRE-OLD-POST")},
		{name: "title", call: testapp.BytesToTitle, want: []byte("PRE-OLD-POST")},
	} {
		t.Run("ASCII "+test.name+" stays exact", func(t *testing.T) {
			got := test.call(input)
			require.Equal(t, test.want, got)
			requireNativeByteRanges(t, got,
				nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
				nativeExpectedRange{start: 8, length: 4, source: inputWant, marks: sqlAndCommand},
			)
		})
	}

	mapped := testapp.BytesMap(func(r rune) rune { return r + 1 }, input)
	require.Equal(t, bytes.Map(func(r rune) rune { return r + 1 }, []byte("pre-OLD-post")), mapped)
	requireNativeByteRanges(t, mapped,
		nativeExpectedRange{length: uint32(len(mapped)), source: inputWant, marks: sqlAndCommand},
	)

	valid := testapp.BytesToValidUTF8(input, []byte("?"))
	require.Equal(t, input, valid)
	requireNativeByteRanges(t, valid,
		nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
		nativeExpectedRange{start: 8, length: 4, source: inputWant, marks: sqlAndCommand},
	)

	unused := testapp.BytesReplace(input, []byte("missing"), replacement, -1)
	require.Equal(t, input, unused)
	require.NotEqual(
		t,
		uintptr(unsafe.Pointer(unsafe.SliceData(input))),
		uintptr(unsafe.Pointer(unsafe.SliceData(unused))),
	)
	requireNativeByteRanges(t, unused,
		nativeExpectedRange{length: 4, source: inputWant, marks: sqlAndCommand},
		nativeExpectedRange{start: 8, length: 4, source: inputWant, marks: sqlAndCommand},
	)

	require.False(t, taint.IsTaintedBytes(testapp.BytesJoin(
		[][]byte{[]byte("clean"), []byte("values")},
		[]byte(":"),
	)))
	require.False(t, taint.IsTaintedBytes([]byte(strings.ToLower("CLEAN"))))
}

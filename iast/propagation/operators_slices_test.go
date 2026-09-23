// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestOperatorConcatAndSlices(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("run with Orchestrion")
	}
	ctx := beginNativePropagation(t)
	marks := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	stringSource := nativeStringSource(t, ctx, "string", "attack")
	source := nativeStringWithRanges(t, "attack",
		nativeStringRangeSeed{source: stringSource, length: 6, marks: marks},
	)
	stringWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "string"},
		Value:  "attack",
	}
	joined := "before:" + source + ":after"
	require.Equal(t, "before:attack:after", joined)
	requireNativeStringRanges(t, joined,
		nativeExpectedRange{start: 7, length: 6, source: stringWant, marks: marks},
	)
	requireNativeStringRanges(t, joined[7:13],
		nativeExpectedRange{length: 6, source: stringWant, marks: marks},
	)
	aliased := source + ""
	require.Equal(
		t,
		uintptr(unsafe.Pointer(unsafe.StringData(source))),
		uintptr(unsafe.Pointer(unsafe.StringData(aliased))),
	)
	requireNativeStringRanges(t, aliased,
		nativeExpectedRange{length: 6, source: stringWant, marks: marks},
	)

	stringValue := nativeStringWithRanges(t, "00attack99",
		nativeStringRangeSeed{source: stringSource, start: 2, length: 6, marks: marks},
	)
	defined := definedString(stringValue)
	for _, test := range []struct {
		name  string
		got   definedString
		want  definedString
		start uint32
	}{
		{name: "all", got: defined[:], want: "00attack99", start: 2},
		{name: "low", got: defined[1:], want: "0attack99", start: 1},
		{name: "high", got: defined[:9], want: "00attack9", start: 2},
		{name: "bounds", got: defined[1:9], want: "0attack9", start: 1},
	} {
		t.Run("native string slice "+test.name, func(t *testing.T) {
			require.Equal(t, test.want, test.got)
			requireNativeStringRanges(t, string(test.got),
				nativeExpectedRange{start: test.start, length: 6, source: stringWant, marks: marks},
			)
		})
	}
	genericStringWindow := genericSlice(defined, uint8(1), uint8(9))
	require.Equal(t, definedString("0attack9"), genericStringWindow)
	requireNativeStringRanges(t, string(genericStringWindow),
		nativeExpectedRange{start: 1, length: 6, source: stringWant, marks: marks},
	)

	byteSource := nativeByteSource(t, ctx, "bytes", []byte("attack"))
	byteValue := nativeBytesWithRanges(t, []byte("00attack99"),
		nativeByteRangeSeed{source: byteSource, start: 2, length: 6, marks: marks},
	)
	byteWant := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "bytes"},
		Value:  "attack",
	}
	definedByteValue := definedBytes(byteValue)
	for _, test := range []struct {
		name    string
		got     definedBytes
		want    definedBytes
		start   uint32
		wantCap int
	}{
		{name: "all", got: definedByteValue[:], want: definedBytes("00attack99"), start: 2, wantCap: 10},
		{name: "low", got: definedByteValue[1:], want: definedBytes("0attack99"), start: 1, wantCap: 9},
		{name: "high", got: definedByteValue[:9], want: definedBytes("00attack9"), start: 2, wantCap: 10},
		{name: "bounds", got: definedByteValue[1:9], want: definedBytes("0attack9"), start: 1, wantCap: 9},
		{name: "full", got: definedByteValue[1:9:9], want: definedBytes("0attack9"), start: 1, wantCap: 8},
		{name: "full zero", got: definedByteValue[:9:9], want: definedBytes("00attack9"), start: 2, wantCap: 9},
	} {
		t.Run("native byte slice "+test.name, func(t *testing.T) {
			require.Equal(t, test.want, test.got)
			require.Equal(t, test.wantCap, cap(test.got))
			requireNativeByteRanges(t, []byte(test.got),
				nativeExpectedRange{start: test.start, length: 6, source: byteWant, marks: marks},
			)
		})
	}
	genericByteWindow := genericByteSlice(definedByteValue, uint8(1), uint8(9))
	require.Equal(t, definedBytes("0attack9"), genericByteWindow)
	requireNativeByteRanges(t, []byte(genericByteWindow),
		nativeExpectedRange{start: 1, length: 6, source: byteWant, marks: marks},
	)

	convertedString := string(byteValue)
	require.Equal(t, "00attack99", convertedString)
	requireNativeStringRanges(t, convertedString,
		nativeExpectedRange{start: 2, length: 6, source: byteWant, marks: marks},
	)
	var namedResult definedString = definedString(byteValue)
	require.Equal(t, definedString("00attack99"), namedResult)
	requireNativeStringRanges(t, string(namedResult),
		nativeExpectedRange{start: 2, length: 6, source: byteWant, marks: marks},
	)
	genericResult := genericConcat(definedString("prefix:"), defined)
	require.Equal(t, definedString("prefix:00attack99"), genericResult)
	requireNativeStringRanges(t, string(genericResult),
		nativeExpectedRange{start: 9, length: 6, source: stringWant, marks: marks},
	)
}

func genericConcat[T ~string](left, right T) T { return left + right }

func genericSlice[T ~string, I integerForTest](value T, low, high I) T { return value[low:high] }

func genericByteSlice[T ~[]byte, I integerForTest](value T, low, high I) T {
	return value[low:high]
}

type integerForTest interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

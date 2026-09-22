// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func bytesToStringReturn(value definedBytes) definedString {
	return definedString(value)
}

func genericBytesToString[T ~[]byte, S ~string](value T) S {
	return S(value)
}

//go:noinline

func identityString(value string) string {
	return value
}

func nativeConcat17(x, source string) string {
	return x + x + x + x + x + x + x + x + x + x + x + x + x + x + x + x + source
}

func TestNativeBytesToStringConversionForms(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("run with Orchestrion")
	}
	ctx := beginNativePropagation(t)
	source := nativeByteSource(t, ctx, "conversion", []byte("attack"))
	marks := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	value := nativeBytesWithRanges(t, []byte("00attack99"),
		nativeByteRangeSeed{source: source, start: 2, length: 6, marks: marks},
	)
	wantSource := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "conversion"},
		Value:  "attack",
	}

	assigned := string(value)
	var declared definedString = definedString(value)
	returned := bytesToStringReturn(definedBytes(value))
	generic := genericBytesToString[definedBytes, definedString](definedBytes(value))
	for name, got := range map[string]string{
		"assignment":  assigned,
		"declaration": string(declared),
		"return":      string(returned),
		"generic":     string(generic),
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, "00attack99", got)
			requireNativeStringRanges(t, got,
				nativeExpectedRange{start: 2, length: 6, source: wantSource, marks: marks},
			)
		})
	}
}

func TestUnsupportedNativeOperatorContextsDoNotInventProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("run with Orchestrion")
	}
	ctx := beginNativePropagation(t)
	stringSeed := nativeStringSource(t, ctx, "string-negative", "attack")
	marks := []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection}
	stringValue := nativeStringWithRanges(t, "attack",
		nativeStringRangeSeed{source: stringSeed, length: 6, marks: marks},
	)
	byteSeed := nativeByteSource(t, ctx, "bytes-negative", []byte("attack"))
	byteValue := nativeBytesWithRanges(t, []byte("attack"),
		nativeByteRangeSeed{source: byteSeed, length: 6, marks: marks},
	)

	concat17 := nativeConcat17("x", stringValue)
	require.Equal(t, strings.Repeat("x", 16)+"attack", concat17)
	requireNativeStringRanges(t, concat17)

	plusAssign := "prefix:"
	plusAssign += stringValue
	require.Equal(t, "prefix:attack", plusAssign)
	requireNativeStringRanges(t, plusAssign)

	callArgument := identityString(string(byteValue))
	require.Equal(t, "attack", callArgument)
	requireNativeStringRanges(t, callArgument)

	concatenatedConversion := "prefix:" + string(byteValue)
	require.Equal(t, "prefix:attack", concatenatedConversion)
	requireNativeStringRanges(t, concatenatedConversion)

	keys := map[string]bool{string(byteValue): true}
	require.True(t, keys["attack"])
	for key := range keys {
		requireNativeStringRanges(t, key)
	}
	require.True(t, string(byteValue) == "attack")
	for range string(byteValue) {
	}

	convertedBytes := []byte(stringValue)
	require.Equal(t, []byte("attack"), convertedBytes)
	requireNativeByteRanges(t, convertedBytes)
	appended := append([]byte("prefix:"), byteValue...)
	require.Equal(t, []byte("prefix:attack"), appended)
	requireNativeByteRanges(t, appended)
	copied := make([]byte, len(byteValue))
	require.Equal(t, len(byteValue), copy(copied, byteValue))
	require.Equal(t, byteValue, copied)
	requireNativeByteRanges(t, copied)
}

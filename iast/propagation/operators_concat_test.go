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

func nativeConcatCases(value string) []struct {
	name string
	call func() string
} {
	x := "x"
	return []struct {
		name string
		call func() string
	}{
		{"concat 2", func() string { return x + value }},
		{"concat 3", func() string { return x + x + value }},
		{"concat 4", func() string { return x + x + x + value }},
		{"concat 5", func() string { return x + x + x + x + value }},
		{"concat 6", func() string { return x + x + x + x + x + value }},
		{"concat 7", func() string { return x + x + x + x + x + x + value }},
		{"concat 8", func() string { return x + x + x + x + x + x + x + value }},
		{"concat 9", func() string { return x + x + x + x + x + x + x + x + value }},
		{"concat 10", func() string { return x + x + x + x + x + x + x + x + x + value }},
		{"concat 11", func() string { return x + x + x + x + x + x + x + x + x + x + value }},
		{"concat 12", func() string { return x + x + x + x + x + x + x + x + x + x + x + value }},
		{"concat 13", func() string { return x + x + x + x + x + x + x + x + x + x + x + x + value }},
		{"concat 14", func() string {
			return x + x + x + x + x + x + x + x + x + x + x + x + x + value
		}},
		{"concat 15", func() string {
			return x + x + x + x + x + x + x + x + x + x + x + x + x + x + value
		}},
		{"concat 16", func() string {
			return x + x + x + x + x + x + x + x + x + x + x + x + x + x + x + value
		}},
	}
}

func TestNativeOperatorConcatsAllAdvertisedArities(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("run with Orchestrion")
	}
	ctx := beginNativePropagation(t)
	source := nativeStringSource(t, ctx, "concat", "attack")
	marks := []taint.VulnerabilityType{
		taint.VulnerabilityTypeSqlInjection,
		taint.VulnerabilityTypeCommandInjection,
	}
	value := nativeStringWithRanges(t, "attack",
		nativeStringRangeSeed{source: source, length: 6, marks: marks},
	)
	wantSource := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "concat"},
		Value:  "attack",
	}
	for index, test := range nativeConcatCases(value) {
		t.Run(test.name, func(t *testing.T) {
			prefixLength := index + 1
			got := test.call()
			require.Equal(t, strings.Repeat("x", prefixLength)+"attack", got)
			requireNativeStringRanges(t, got, nativeExpectedRange{
				start:  uint32(prefixLength),
				length: 6,
				source: wantSource,
				marks:  marks,
			})
		})
	}

	leftSource := nativeStringSource(t, ctx, "left", "left")
	rightSource := nativeStringSource(t, ctx, "right", "right")
	left := nativeStringWithRanges(t, "left",
		nativeStringRangeSeed{source: leftSource, length: 4, marks: marks},
	)
	right := nativeStringWithRanges(t, "right",
		nativeStringRangeSeed{
			source: rightSource,
			length: 5,
			marks:  []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection},
		},
	)
	got := left + ":" + right
	require.Equal(t, "left:right", got)
	requireNativeStringRanges(t, got,
		nativeExpectedRange{
			length: 4,
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "left"},
				Value:  "left",
			},
			marks: marks,
		},
		nativeExpectedRange{
			start:  5,
			length: 5,
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "right"},
				Value:  "right",
			},
			marks: []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection},
		},
	)
}

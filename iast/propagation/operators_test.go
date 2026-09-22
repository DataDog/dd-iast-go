// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"context"
	"strings"
	"testing"

	iastpropagation "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type definedString string
type definedBytes []byte

func concatCases(value string) []struct {
	name string
	call func() string
} {
	return []struct {
		name string
		call func() string
	}{
		{"Concat2", func() string { return iastpropagation.Concat2("x", value) }},
		{"Concat3", func() string { return iastpropagation.Concat3("x", "x", value) }},
		{"Concat4", func() string { return iastpropagation.Concat4("x", "x", "x", value) }},
		{"Concat5", func() string { return iastpropagation.Concat5("x", "x", "x", "x", value) }},
		{"Concat6", func() string { return iastpropagation.Concat6("x", "x", "x", "x", "x", value) }},
		{"Concat7", func() string { return iastpropagation.Concat7("x", "x", "x", "x", "x", "x", value) }},
		{"Concat8", func() string { return iastpropagation.Concat8("x", "x", "x", "x", "x", "x", "x", value) }},
		{"Concat9", func() string { return iastpropagation.Concat9("x", "x", "x", "x", "x", "x", "x", "x", value) }},
		{"Concat10", func() string { return iastpropagation.Concat10("x", "x", "x", "x", "x", "x", "x", "x", "x", value) }},
		{"Concat11", func() string {
			return iastpropagation.Concat11("x", "x", "x", "x", "x", "x", "x", "x", "x", "x", value)
		}},
		{"Concat12", func() string {
			return iastpropagation.Concat12("x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", value)
		}},
		{"Concat13", func() string {
			return iastpropagation.Concat13("x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", value)
		}},
		{"Concat14", func() string {
			return iastpropagation.Concat14("x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", value)
		}},
		{"Concat15", func() string {
			return iastpropagation.Concat15("x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", value)
		}},
		{"Concat16", func() string {
			return iastpropagation.Concat16("x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", "x", value)
		}},
	}
}

func TestOperatorWrappersInactive(t *testing.T) {
	require.Nil(t, request.ActiveStore())
	for index, test := range concatCases("z") {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, strings.Repeat("x", index+1)+"z", test.call())
		})
	}

	text := definedString("abcdef")
	require.Equal(t, text, iastpropagation.StringSliceAll(text))
	require.Equal(t, definedString("cdef"), iastpropagation.StringSliceLow(text, 2))
	require.Equal(t, definedString("abcd"), iastpropagation.StringSliceHigh(text, 4))
	require.Equal(t, definedString("bcd"), iastpropagation.StringSliceBounds(text, 1, 4))

	data := definedBytes("abcdef")
	require.Equal(t, data, iastpropagation.BytesSliceAll(data))
	require.Equal(t, definedBytes("cdef"), iastpropagation.BytesSliceLow(data, 2))
	require.Equal(t, definedBytes("abcd"), iastpropagation.BytesSliceHigh(data, 4))
	require.Equal(t, definedBytes("bcd"), iastpropagation.BytesSliceBounds(data, 1, 4))
	full := iastpropagation.BytesSliceFull(data, 1, 4, 5)
	require.Equal(t, definedBytes("bcd"), full)
	require.Equal(t, 4, cap(full))
	fullZero := iastpropagation.BytesSliceFullZero(data, 4, 5)
	require.Equal(t, definedBytes("abcd"), fullZero)
	require.Equal(t, 5, cap(fullZero))
}

func TestOperatorWrappersPropagateAllAritiesAndSlices(t *testing.T) {
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, _, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(func() { request.FinishContext(ctx, true) })

	source := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "q"}, "attack")
	for index, test := range concatCases(source) {
		t.Run(test.name, func(t *testing.T) {
			result := test.call()
			require.Equal(t, strings.Repeat("x", index+1)+source, result)
			require.True(t, taint.IsTaintedString(result))
		})
	}

	defined := definedString(source)
	for name, result := range map[string]definedString{
		"all":    iastpropagation.StringSliceAll(defined),
		"low":    iastpropagation.StringSliceLow(defined, 1),
		"high":   iastpropagation.StringSliceHigh(defined, 5),
		"bounds": iastpropagation.StringSliceBounds(defined, 1, 5),
	} {
		t.Run("string_"+name, func(t *testing.T) {
			require.True(t, taint.IsTaintedString(result))
		})
	}

	data := definedBytes(taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte("payload")))
	for name, result := range map[string]definedBytes{
		"all":       iastpropagation.BytesSliceAll(data),
		"low":       iastpropagation.BytesSliceLow(data, 1),
		"high":      iastpropagation.BytesSliceHigh(data, 6),
		"bounds":    iastpropagation.BytesSliceBounds(data, 1, 6),
		"full":      iastpropagation.BytesSliceFull(data, 1, 6, 7),
		"full_zero": iastpropagation.BytesSliceFullZero(data, 6, 7),
	} {
		t.Run("bytes_"+name, func(t *testing.T) {
			require.True(t, taint.IsTaintedBytes(result))
		})
	}
}

func BenchmarkOperatorConcat4Inactive(b *testing.B) {
	a, c := "alpha", "charlie"
	second, fourth := "bravo", "delta"
	b.ReportAllocs()
	for b.Loop() {
		operatorStringSink = a + second + c + fourth
	}
}

func BenchmarkOperatorConcat4ActiveClean(b *testing.B) {
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	ctx, _, created := request.Begin(context.Background())
	if !created {
		b.Fatal("scope not created")
	}
	defer request.FinishContext(ctx, true)
	a, c := "alpha", "charlie"
	second, fourth := "bravo", "delta"
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		operatorStringSink = a + second + c + fourth
	}
}

func BenchmarkOperatorConversionsInactive(b *testing.B) {
	text := "alpha-bravo-charlie"
	data := []byte(text)
	b.ReportAllocs()
	for b.Loop() {
		operatorStringSink = string(data)
	}
}

func BenchmarkOperatorOptimizedConversionExcluded(b *testing.B) {
	data := []byte("alpha-bravo-charlie")
	b.ReportAllocs()
	for b.Loop() {
		operatorIntSink = len(string(data))
	}
}

func BenchmarkOperatorSlicesInactive(b *testing.B) {
	text := "alpha-bravo-charlie"
	data := []byte(text)
	b.ReportAllocs()
	for b.Loop() {
		operatorStringSink = text[3:15]
		operatorBytesSink = data[3:15:18]
	}
}

var operatorStringSink string
var operatorBytesSink []byte
var operatorIntSink int

func TestOperatorEvaluationAndPanicSemantics(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("run with Orchestrion")
	}
	order := make([]int, 0, 3)
	operand := func(index int, value string) string { order = append(order, index); return value }
	require.Equal(t, "abc", operand(1, "a")+operand(2, "b")+operand(3, "c"))
	require.Equal(t, []int{1, 2, 3}, order)

	sliceOrder := make([]int, 0, 4)
	sliceOperand := func() []byte {
		sliceOrder = append(sliceOrder, 1)
		return []byte("abcdef")
	}
	index := func(order, value int) int {
		sliceOrder = append(sliceOrder, order)
		return value
	}
	require.Equal(t, []byte("bcd"), sliceOperand()[index(2, 1):index(3, 4):index(4, 5)])
	require.Equal(t, []int{1, 2, 3, 4}, sliceOrder)

	conversionCalls := 0
	conversionOperand := func() []byte {
		conversionCalls++
		return []byte("abc")
	}
	require.Equal(t, "abc", string(conversionOperand()))
	require.Equal(t, 1, conversionCalls)

	defer func() { require.NotNil(t, recover()) }()
	value := "abc"
	_ = value[0:4]
}

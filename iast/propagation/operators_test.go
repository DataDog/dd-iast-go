// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"context"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type definedString string
type definedBytes []byte

func TestOperatorConcatAndSlices(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("run with Orchestrion")
	}
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	ctx, _, created := request.Begin(context.Background())
	require.True(t, created)
	defer request.FinishContext(ctx, true)

	source := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "q"}, "attack")
	joined := "before:" + source + ":after"
	require.Equal(t, "before:attack:after", joined)
	require.True(t, taint.IsTaintedString(joined))
	require.True(t, taint.IsTaintedString(joined[7:13]))
	aliased := source + ""
	require.Equal(t, unsafe.StringData(source), unsafe.StringData(aliased))
	require.True(t, taint.IsTaintedString(aliased))

	defined := definedString(source)
	window := defined[1:5]
	require.Equal(t, definedString("ttac"), window)
	require.True(t, taint.IsTaintedString(window))

	bytes := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte("payload"))
	definedByteValue := definedBytes(bytes)
	byteWindow := definedByteValue[1:5:6]
	require.Equal(t, definedBytes("aylo"), byteWindow)
	require.Equal(t, 5, cap(byteWindow))
	require.True(t, taint.IsTaintedBytes(byteWindow))

	convertedString := string(bytes)
	require.Equal(t, "payload", convertedString)
	require.True(t, taint.IsTaintedString(convertedString))
	var namedResult definedString = definedString(bytes)
	require.Equal(t, definedString("payload"), namedResult)
	require.True(t, taint.IsTaintedString(namedResult))
	genericResult := genericConcat(definedString("prefix:"), defined)
	require.Equal(t, definedString("prefix:attack"), genericResult)
	require.True(t, taint.IsTaintedString(genericResult))
	require.True(t, taint.IsTaintedString(genericSlice(defined, 1, 5)))
}

func genericConcat[T ~string](left, right T) T                         { return left + right }
func genericSlice[T ~string, I integerForTest](value T, low, high I) T { return value[low:high] }

type integerForTest interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
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

	defer func() { require.NotNil(t, recover()) }()
	value := "abc"
	_ = value[0:4]
}

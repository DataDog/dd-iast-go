// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

// BenchmarkConcat4Tainted/Untainted reproduce the perf-bench-quality finding
// that internal/taint/propagation (the core hot-path engine invoked by every
// woven operator/stdlib call site) has zero Benchmark* functions anywhere in
// the repository. This measures propagation.Concat4 directly, both for a
// MayContain-miss (all clean operands) and a MayContain-hit (one tainted
// operand, which is the actual customer attack scenario).
func BenchmarkConcat4Untainted(b *testing.B) {
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	ctx, _, created := request.Begin(context.Background())
	if !created {
		b.Fatal("scope not created")
	}
	defer request.FinishContext(ctx, true)
	a, c, second, fourth := "alpha", "charlie", "bravo", "delta"
	result := a + second + c + fourth
	var sink string
	b.ReportAllocs()
	for b.Loop() {
		sink = propagation.Concat4(a, second, c, fourth, result)
	}
	_ = sink
}

func BenchmarkConcat4Tainted(b *testing.B) {
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	ctx, _, created := request.Begin(context.Background())
	if !created {
		b.Fatal("scope not created")
	}
	defer request.FinishContext(ctx, true)
	a := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "a"}, "alpha")
	c, second, fourth := "charlie", "bravo", "delta"
	result := a + second + c + fourth
	var sink string
	b.ReportAllocs()
	for b.Loop() {
		sink = propagation.Concat4(a, second, c, fourth, result)
	}
	_ = sink
}

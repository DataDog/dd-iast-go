// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package sql

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/sqlbridge"
	"github.com/DataDog/dd-iast-go/taint"
)

// BenchmarkReportActiveTainted is a reproducer for the perf-bench-quality
// review: it measures the cost of Report when the query text is ACTUALLY
// tainted (a real attacker-controlled source), unlike BenchmarkReportActiveClean
// which only ever calls Report with a compile-time literal that can never hit
// evidence.CollectString's MayContain gate.
func BenchmarkReportActiveTainted(b *testing.B) {
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	b.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		b.Fatal("active scope was not created")
	}
	b.Cleanup(scope.Finish)
	tainted := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "q"}, "SELECT * FROM users WHERE name = 'attacker'")
	b.ReportAllocs()
	for b.Loop() {
		Report(ctx, tainted, sqlbridge.KindQuery)
	}
}

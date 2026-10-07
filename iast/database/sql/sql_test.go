// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package sql

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/sqlbridge"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestReport(t *testing.T) {
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)

	before := telemetry.ExecutedSink.SqlInjection.Load()
	Report(ctx, "SELECT 1", sqlbridge.KindExec)
	tainted := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "q"}, "SELECT * FROM users")
	Report(ctx, tainted, sqlbridge.KindQuery)
	require.Equal(t, before+2, telemetry.ExecutedSink.SqlInjection.Load())
}

// TestReportAtCapacityDoesNoReportWork makes reports of a tainted query
// until the request has the maximum number of vulnerabilities. Below the
// capacity, each report is committed. At the capacity, Report must do only
// the evidence collection: no SQL analysis, no redaction and no stack
// capture. The allocations show this, because these steps allocate.
func TestReportAtCapacityDoesNoReportWork(t *testing.T) {
	// The taint bits need the woven runtime.
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test")
	}
	if !heapbits.Enabled() {
		t.Skip("the heap taint bits are not supported on this platform")
	}
	const capacity = 8
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	oldCapacity, oldDedup, oldStack := config.VulnerabilitiesPerRequest, config.DeduplicationEnabled, config.StackTraceEnabled
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	config.VulnerabilitiesPerRequest, config.DeduplicationEnabled, config.StackTraceEnabled = capacity, false, true
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
		config.VulnerabilitiesPerRequest, config.DeduplicationEnabled, config.StackTraceEnabled = oldCapacity, oldDedup, oldStack
	})
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	span, ctx := tracer.StartSpanFromContext(ctx, "request")
	annotation := spans.BindScope(span, scope)
	require.NotNil(t, annotation)
	t.Cleanup(func() {
		spans.Finished(span)
		scope.Finish()
		span.Finish()
	})
	count := func() int {
		annotation.RLock()
		defer annotation.RUnlock()
		return len(annotation.Vulnerabilities)
	}
	query := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "q"}, "SELECT * FROM users WHERE name = 'alice'")

	// AllocsPerRun calls the function one more time before it measures.
	const committed = capacity / 2
	report := testing.AllocsPerRun(committed-1, func() { Report(ctx, query, sqlbridge.KindQuery) })
	require.Equal(t, committed, count(), "each report below the capacity must be committed")
	for count() < capacity {
		before := count()
		Report(ctx, query, sqlbridge.KindQuery)
		require.Equal(t, before+1, count(), "a report below the capacity was not committed")
	}

	// The check itself can allocate in the tracer (the span lookup of the
	// context), as the collection does.
	snapshot, status := vulnerability.CollectString(ctx, query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, evidence.StatusCollected, status)
	check := testing.AllocsPerRun(16, func() {
		require.True(t, vulnerability.TaintedReportBlocked(ctx, constants.VulnerabilityTypeSqlInjection, snapshot))
	})
	require.LessOrEqual(t, check, 1.0, "the check must not allocate more than the span lookup")
	collect := testing.AllocsPerRun(16, func() {
		_, status := vulnerability.CollectString(ctx, query, constants.VulnerabilityTypeSqlInjection)
		require.Equal(t, evidence.StatusCollected, status)
	})
	executed := telemetry.ExecutedTainted.Load()
	capped := testing.AllocsPerRun(16, func() { Report(ctx, query, sqlbridge.KindQuery) })
	require.Equal(t, capacity, count(), "a report at the capacity was committed")
	require.Equal(t, executed+17, telemetry.ExecutedTainted.Load(), "each tainted execution at the capacity must be counted")
	require.LessOrEqual(t, capped, collect+check, "a report at the capacity must do only the collection and the check")
	t.Logf("allocations: committed report %.0f, blocked report %.0f (collection %.0f, check %.0f)", report, capped, collect, check)
	require.Greater(t, report, capped, "a committed report must do more work than a blocked report")
}

func BenchmarkReportActiveClean(b *testing.B) {
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
	b.ReportAllocs()
	for b.Loop() {
		Report(ctx, "SELECT 1", sqlbridge.KindExec)
	}
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package exec

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestBoundedJoin(t *testing.T) {
	joined, ok := boundedJoin([]string{"echo", "hello world"})
	require.True(t, ok)
	require.Equal(t, "echo hello world", joined)

	maximum := strings.Repeat("x", maxJoinedBytes)
	joined, ok = boundedJoin([]string{maximum})
	require.True(t, ok)
	require.Equal(t, maximum, joined)

	tooMany := make([]string, evidence.MaxJoinedValues+1)
	for name, argv := range map[string][]string{
		"empty":              nil,
		"too many arguments": tooMany,
		"oversized argument": {strings.Repeat("x", maxJoinedBytes+1)},
		"separator overflow": {maximum, ""},
	} {
		t.Run(name, func(t *testing.T) {
			joined, ok := boundedJoin(argv)
			require.False(t, ok)
			require.Empty(t, joined)
		})
	}
}

func TestMayContainArgumentAndReport(t *testing.T) {
	require.False(t, mayContainArgument(nil))
	require.False(t, mayContainArgument(make([]string, evidence.MaxJoinedValues+1)))
	require.False(t, mayContainArgument([]string{"clean"}))
	// The taint bits need the woven runtime.
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test")
	}
	if !heapbits.Enabled() {
		t.Skip("the heap taint bits are not supported on this platform")
	}

	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)

	require.False(t, mayContainArgument([]string{"echo", "clean"}))
	tainted := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "cmd"}, "attack")
	require.True(t, mayContainArgument([]string{"echo", tainted}))

	// The gate must drop an oversized joined command line before it reads the
	// heap taint bits: a tainted argument does not open the gate when the
	// joined length is larger than maxJoinedBytes.
	source := taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "cmd"}
	largest := taint.TaintString(ctx, source, strings.Repeat("y", maxJoinedBytes-len("echo ")))
	require.True(t, heapbits.AnyString(largest))
	require.True(t, mayContainArgument([]string{"echo", largest}))
	require.False(t, mayContainArgument([]string{"echo", largest, ""}))
	require.False(t, mayContainArgument([]string{largest, tainted}))
	require.False(t, mayContainArgument([]string{tainted, largest}))

	before := telemetry.ExecutedSink.CommandInjection.Load()
	Report(ctx, nil)
	Report(ctx, []string{"echo", tainted})
	oversized := taint.TaintString(
		ctx,
		taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "cmd"},
		strings.Repeat("x", redaction.MaxAnalyzerBytes+1),
	)
	Report(ctx, []string{oversized})
	require.Equal(t, before+3, telemetry.ExecutedSink.CommandInjection.Load())
}

// TestReportAtCapacityDoesNoReportWork makes reports of a tainted command
// until the request has the maximum number of vulnerabilities. Below the
// capacity, each report is committed. At the capacity, Report must do only
// the command analysis (it makes the joined value), the evidence collection
// and the check: no redaction and no stack capture. The allocations show
// this, because these steps allocate.
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
	tainted := taint.TaintString(ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "cmd"}, "attack; rm -rf /")
	argv := []string{"sh", "-c", tainted}

	// AllocsPerRun calls the function one more time before it measures.
	const committed = capacity / 2
	report := testing.AllocsPerRun(committed-1, func() { Report(ctx, argv) })
	require.Equal(t, committed, count(), "each report below the capacity must be committed")
	for count() < capacity {
		before := count()
		Report(ctx, argv)
		require.Equal(t, before+1, count(), "a report below the capacity was not committed")
	}

	analysis := redaction.AnalyzeCommand(argv)
	require.Equal(t, redaction.AnalysisOK, analysis.Status)
	snapshot, status := vulnerability.CollectJoinedStrings(ctx, argv, " ", analysis.Value, constants.VulnerabilityTypeCommandInjection)
	require.Equal(t, evidence.StatusCollected, status)
	// The check itself can allocate in the tracer (the span lookup of the
	// context), as the collection does.
	check := testing.AllocsPerRun(16, func() {
		require.True(t, vulnerability.TaintedReportBlocked(ctx, constants.VulnerabilityTypeCommandInjection, snapshot))
	})
	require.LessOrEqual(t, check, 1.0, "the check must not allocate more than the span lookup")
	collect := testing.AllocsPerRun(16, func() {
		analysis := redaction.AnalyzeCommand(argv)
		_, status := vulnerability.CollectJoinedStrings(ctx, argv, " ", analysis.Value, constants.VulnerabilityTypeCommandInjection)
		require.Equal(t, evidence.StatusCollected, status)
	})
	executed := telemetry.ExecutedTainted.Load()
	capped := testing.AllocsPerRun(16, func() { Report(ctx, argv) })
	require.Equal(t, capacity, count(), "a report at the capacity was committed")
	require.Equal(t, executed+17, telemetry.ExecutedTainted.Load(), "each tainted execution at the capacity must be counted")
	require.LessOrEqual(t, capped, collect+check, "a report at the capacity must do only the analysis, the collection and the check")
	require.Greater(t, report, capped, "a committed report must do more work than a blocked report")
	t.Logf("allocations: committed report %.0f, blocked report %.0f (analysis and collection %.0f, check %.0f)", report, capped, collect, check)
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
	argv := []string{"echo", "clean"}
	b.ReportAllocs()
	for b.Loop() {
		Report(ctx, argv)
	}
}

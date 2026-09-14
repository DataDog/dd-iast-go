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
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func TestBoundedJoin(t *testing.T) {
	joined, ok := boundedJoin([]string{"echo", "hello world"})
	require.True(t, ok)
	require.Equal(t, "echo hello world", joined)

	maximum := strings.Repeat("x", store.MaxRootBytes)
	joined, ok = boundedJoin([]string{maximum})
	require.True(t, ok)
	require.Equal(t, maximum, joined)

	tooMany := make([]string, evidence.MaxJoinedValues+1)
	for name, argv := range map[string][]string{
		"empty":              nil,
		"too many arguments": tooMany,
		"oversized argument": {strings.Repeat("x", store.MaxRootBytes+1)},
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

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package exec

import (
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

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

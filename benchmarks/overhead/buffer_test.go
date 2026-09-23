// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/DataDog/dd-iast-go/benchmarks/overhead"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func BenchmarkBytesBufferCopies(b *testing.B) {
	if !built.WithOrchestrion {
		b.Skip("requires woven ordinary-call fixture")
	}
	for _, mode := range []string{"read", "write", "active-unrelated"} {
		b.Run(mode, func(b *testing.B) {
			previousEnabled, previousSampling := config.Enabled, config.RequestSamplingPct
			config.Enabled, config.RequestSamplingPct = true, 100
			ctx, scope, created := request.Begin(context.Background())
			if !created {
				b.Fatal("request not created")
			}
			b.Cleanup(func() {
				scope.Finish()
				config.Enabled, config.RequestSamplingPct = previousEnabled, previousSampling
			})
			input := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "buffer"}, "attacker")
			buffer := overhead.NewTrackedBuffer(input)
			// The runner's control build has no IAST propagation aspects.
			if telemetry.InstrumentedPropagation != 0 && !writerbridge.Active() {
				b.Fatal("ordinary-call fixture did not establish writer state")
			}
			var unrelated bytes.Buffer
			unrelated.Grow(64)
			write, reset := unrelated.WriteString, unrelated.Reset
			b.ReportAllocs()
			for b.Loop() {
				switch mode {
				case "read":
					resultString = overhead.ReadBufferCopy(*buffer)
				case "write":
					resultString = overhead.WriteBufferCopy(buffer, input)
				case "active-unrelated":
					write("clean")
					reset()
				}
			}
		})
	}
}

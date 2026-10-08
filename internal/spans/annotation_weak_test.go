// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans_test

import (
	"context"
	"crypto/des"
	"crypto/md5"
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestWeakCallsPreserveHTTPDecision(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires Orchestrion weaving of ordinary weak-crypto calls")
	}
	for _, rate := range []int{0, 100} {
		name := "rejected"
		if rate == 100 {
			name = "sampled"
		}
		t.Run(name, func(t *testing.T) {
			mock := configureSamplingTest(t)
			config.RequestSamplingPct = rate
			weakCallsInHTTPContext(context.Background(), t)
			finished := mock.FinishedSpans()
			if len(finished) != 1 {
				t.Fatalf("finished spans = %d, want one request and no orphans", len(finished))
			}
			if rate == 0 {
				if finished[0].Tag(spans.SpanTagEnabled) != float64(0) || finished[0].Tag(spans.SpanTagJson) != nil {
					t.Fatal("context-free weak calls reported on a rejected HTTP owner")
				}
				return
			}
			var event model.Event
			payload, ok := finished[0].Tag(spans.SpanTagJson).(string)
			if !ok {
				t.Fatal("sampled request omitted the vulnerability event")
			}
			if err := json.Unmarshal([]byte(payload), &event); err != nil {
				t.Fatal(err)
			}
			if len(event.Vulnerabilities) != 2 {
				t.Fatalf("weak findings = %d, want hash and cipher", len(event.Vulnerabilities))
			}
			for _, finding := range event.Vulnerabilities {
				if finding.Location == nil || finding.Location.SpanID != finished[0].Context().SpanID() || finding.Location.Path == "" || finding.Location.Line == 0 {
					t.Fatalf("incomplete weak-sink location: %#v", finding.Location)
				}
			}
		})
	}
}

func weakCallsInHTTPContext(ctx context.Context, t *testing.T) {
	ctx, created := request.BeginServerContext(ctx)
	defer request.FinishContext(ctx, created)
	if !created {
		t.Fatal("HTTP owner scope unavailable")
	}
	span, ctx := tracer.StartSpanFromContext(ctx, "http-owner")
	defer span.Finish()
	spans.BindScopeFromContext(ctx)
	defer spans.Finished(span)
	config.RequestSamplingPct = 100
	if got := md5.Sum([]byte("hello")); got != [md5.Size]byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92} {
		t.Fatalf("MD5 host return changed: %x", got)
	}
	if _, err := des.NewCipher([]byte("bad")); err != des.KeySizeError(3) {
		t.Fatalf("DES host error changed: %v", err)
	}
}

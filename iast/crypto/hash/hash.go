// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hash

import (
	"context"
	"crypto"
	"encoding/json"
	"log/slog"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/stack"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func ReportWeakHash(ctx context.Context, hash crypto.Hash) {
	if !config.Enabled {
		return
	}

	if ctx == nil {
		ctx = context.Background()
	}

	span, ok := tracer.SpanFromContext(ctx)
	if !ok {
		span = spans.NewOrphanVulnerabilitySpan()
		defer span.Finish()
	}

	event := spans.AnnotationFor(span)
	if !event.Sampled {
		return
	}

	telemetry.ExecutedSink.WeakHash.Add(1)

	location := &model.Location{SpanID: span.Context().SpanID()}
	for frame := range stack.Frames(1) {
		location.Path = frame.File
		location.Line = new(frame.Line - 1) // Zero-based
		if frame.Function != "" {
			location.Type, location.Method = stack.MethodAndTypeFrom(frame.Function)
		}
		break
	}

	event.Lock()
	defer event.Unlock()

	vuln := model.Vulnerability{
		Type:     constants.VulnerabilityTypeWeakHash,
		Evidence: &model.UnredactedStringValue{Value: hash.String()},
		Location: location,
	}
	if !event.AddVulnerability(vuln) {
		instrumentation.Instance.TelemetryLog().
			Warn("failed to add vulnerability to event (out of capacity?)", slog.Any("vulnerability", vuln))
		return
	}

	data, err := json.Marshal(event)
	if err != nil {
		instrumentation.Instance.
			Logger().
			Warn("failed to marshal vulnerability event: %s", err)
		return
	}
	span.SetTag(spans.SpanTagJson, string(data))
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hash

import (
	"context"
	"crypto"
	"encoding/json"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/constants"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/stack"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func ReportWeakHash(ctx context.Context, hash crypto.Hash) {
	if ctx == nil {
		ctx = context.Background()
	}

	span, ok := tracer.SpanFromContext(ctx)
	if !ok {
		span = spans.NewOrphanVulnerabilitySpan()
		defer span.Finish()
	}

	span.SetTag(constants.SpanTagEnabled, 1)
	event := spans.AnnotationFor(span)

	location := &model.Location{SpanID: span.Context().SpanID()}
	for frame := range stack.Frames(1) {
		if frame.File == "<generated>" {
			continue
		}
		location.Path = frame.File
		location.Line = new(frame.Line - 1) // Zero-based
		if frame.Function != "" {
			lastDot := strings.LastIndex(frame.Function, ".")
			location.Method = frame.Function[lastDot+1:]
			if lastDot >= 0 {
				location.Type = frame.Function[:lastDot]
			}
		}
		break
	}

	event.Lock()
	defer event.Unlock()

	event.Vulnerabilities = append(event.Vulnerabilities, &model.Vulnerability{
		Type:     model.VulnerabilityTypeWeakHash,
		Evidence: &model.UnredactedStringValue{Value: hash.String()},
		Location: location,
	})

	data, err := json.Marshal(event)
	if err != nil {
		instrumentation.Instrumentation.
			Logger().
			Warn("failed to marshal vulnerability event: %s", err)
		return
	}
	span.SetTag(constants.SpanTagJson, string(data))
}

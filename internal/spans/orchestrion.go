// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"log/slog"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

const samplingMechanismAppSec = 5

func logPayloadTruncation(payload LimitedPayload) {
	if payload.Truncated {
		instrumentation.Instance.TelemetryLog().Debug("truncated IAST event at encoded payload limit")
	}
}

// Finished is called by [*tracer.Span.Finish] and removes the [*Annotation]
// from storage, as the span is defunct.
func Finished(span *tracer.Span) {
	ann, ok := store.LoadAndDelete(weak.Make(span))
	if !ok {
		return
	}

	defer ann.submitTelemetry()

	ann.Lock()
	defer ann.Unlock()
	ann.closed.Store(true)

	if len(ann.Event.Vulnerabilities) > 0 {
		payload, err := BuildLimitedPayload(&ann.Event, PayloadEncodingMsgpack)
		if err != nil {
			instrumentation.Instance.TelemetryLog().
				Warn("failed to build bounded vulnerability event", slog.Any("error", err))
		} else if span.SetMetaStruct(SpanTagMetaStruct, payload.Event) {
			span.SetTag(ext.ManualKeep, samplingMechanismAppSec)
			logPayloadTruncation(payload)
		} else {
			payload, err = BuildLimitedPayload(&ann.Event, PayloadEncodingJSON)
			if err != nil {
				instrumentation.Instance.TelemetryLog().
					Warn("failed to marshal bounded vulnerability event to JSON", slog.Any("error", err))
			} else {
				span.SetTag(ext.ManualKeep, samplingMechanismAppSec)
				span.SetTag(SpanTagJson, string(payload.Encoded))
				logPayloadTruncation(payload)
			}
		}
	}
	ann.releaseSourceIdentities()
}

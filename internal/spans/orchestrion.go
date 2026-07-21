// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"encoding/json"
	"log/slog"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

const samplingMechanismAppSec = 5

// Finished is called by [*tracer.Span.Finish] and removes the [*Annotation]
// from storage, as the span is defunct.
func Finished(span *tracer.Span) {
	ann, ok := store.LoadAndDelete(weak.Make(span))
	if !ok {
		return
	}

	defer ann.submitTelemetry()

	ann.RLock()
	defer ann.RUnlock()

	if len(ann.Event.Vulnerabilities) > 0 {
		span.SetTag(ext.ManualKeep, samplingMechanismAppSec)
		if !span.SetMetaStruct(SpanTagMetaStruct, &ann.Event) {
			data, err := json.Marshal(ann.Event)
			if err != nil {
				instrumentation.Instance.TelemetryLog().
					Warn("failed to marshal vulnerability event to JSON", slog.Any("error", err))
			} else {
				span.SetTag(SpanTagJson, string(data))
			}
		}
	}
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"encoding/json"
	"log/slog"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/puzpuzpuz/xsync/v4"

	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

const samplingMechanismAppSec = 5

// Finished is called by [*tracer.Span.Finish]. It closes the [*Annotation] of
// the span, which gives back its capacity, and writes the findings to the span.
// No finding is added after this returns.
func Finished(span *tracer.Span) {
	if span == nil || !config.Enabled || config.RequestSamplingPct == 0 || config.MaxConcurrentRequests == 0 {
		return
	}
	// Only a root span has an annotation.
	if root := span.Root(); root != nil && root != span {
		return
	}

	id := span.Context().SpanID()
	key := weak.Make(span)
	ann, ok := lookup(key, id)
	if !ok {
		if !sampled(span) {
			return
		}
		// No report came before the finish: remember the root as finished, so
		// that a report that arrives later does not create an annotation.
		if entries.Load() >= storeLimit() {
			trimStore()
		}
		ann, _ = store.Compute(key, func(old *Annotation, loaded bool) (*Annotation, xsync.ComputeOp) {
			if loaded {
				if old.spanID == id {
					return old, xsync.CancelOp
				}
				// The new entry takes the place of the entry of an earlier span.
				old.closeAndRelease()
			} else if !reserveEntry() {
				// Set while the bucket of the key is locked, so a report of this root
				// that waits for the bucket sees it.
				refuseFor(refuseWindow)
				return nil, xsync.CancelOp
			}
			return newTombstone(id), xsync.UpdateOp
		})
		if ann == nil {
			// The store is full of finished roots that are still reachable, and
			// new annotations are refused for a while: a late report of this root
			// cannot get one.
			return
		}
	}

	if ann.tombstone {
		return
	}

	// A second call (a concurrent Finish of the same span) waits here until the
	// first one has written the findings to the span.
	ann.finishOnce.Do(func() {
		owner := ann.close()
		ann.publish(span)
		retainClosed(key, ann)
		if owner {
			// The capacity is given back when the findings are written, so a
			// stalled finish cannot let new requests pile up behind it.
			release()
		}
	})
}

// publish writes the findings to the span, and sends the telemetry.
func (a *Annotation) publish(span *tracer.Span) {
	defer a.submitTelemetry()

	// The tag is also set when the annotation is created. Setting it here
	// guarantees that findings never leave without it.
	if a.Sampled {
		span.SetTag(SpanTagEnabled, 1)
	}

	a.RLock()
	defer a.RUnlock()

	if len(a.Vulnerabilities) > 0 {
		span.SetTag(ext.ManualKeep, samplingMechanismAppSec)
		if !span.SetMetaStruct(SpanTagMetaStruct, &a.Event) {
			data, err := json.Marshal(a.Event)
			if err != nil {
				instrumentation.Instance.TelemetryLog().
					Warn("failed to marshal vulnerability event to JSON", slog.Any("error", err))
			} else {
				span.SetTag(SpanTagJson, string(data))
			}
		}
	}
}

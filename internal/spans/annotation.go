// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"log/slog"
	"math/rand/v2"
	"sync"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/constants"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/puzpuzpuz/xsync/v4"
)

var (
	// store is the association of tracer spans to annotation objects.
	store = xsync.NewMap[weak.Pointer[tracer.Span], *Annotation](xsync.WithPresize(2 * config.MaxConcurrentRequests))
	// triggerTrimThreshold is the threshold utilization at which we start
	// actively trying to remove dead keys from the map.
	triggerTrimThreshold = max(config.MaxConcurrentRequests*3/4, 1)
)

type Annotation struct {
	sync.RWMutex
	model.Event
	Sampled bool
}

// AnnotationFor returns the [*Annotation] for the root of the given
// [*tracer.Span] (or the span itself if it does not have a valid, un-finished
// root). If none exists yet, a new [*Annotation] is allocated.
func AnnotationFor(span *tracer.Span) *Annotation {
	root := span.Root()
	if root == nil {
		instrumentation.Instance.TelemetryLog().
			Debug("iast/annotation: span has no root, using span itself", slog.Any("span", span.Context().SpanID()))
		root = span
	}

	spanID := root.Context().SpanID()

	// Can't do this within the TryCompute callback as this would deadlock.
	hasSpace := trimStore()

	ptr := weak.Make(root)
	ann, _ := store.LoadOrCompute(
		ptr,
		func() (*Annotation, bool) {
			if !hasSpace {
				instrumentation.Instance.TelemetryLog().
					Warn("iast/annotation: max concurrent requests reached, not storing annotation for span", slog.Any("span", spanID))
				return nil, false
			}
			ann := new(Annotation)
			ann.Sampled = samplingDecision()
			if ann.Sampled {
				root.SetTag(constants.SpanTagEnabled, 1)
			} else {
				root.SetTag(constants.SpanTagEnabled, 0)
			}
			return new(Annotation), false
		},
	)

	if ann != nil && ann.Sampled {
		span.SetTag(constants.SpanTagEnabled, 1)
	}

	if ann == nil {
		ann = new(Annotation)
	}

	return ann
}

// Finished is called by [*tracer.Span.Finish] and removes the [*Annotation]
// from storage, as the span is defunct.
func Finished(span *tracer.Span) {
	store.Delete(weak.Make(span))
}

// trimStore removes keys from the map where the [weak.Pointer] has turned nil,
// if the current utilization is over [triggerTrimThreshold]. Returns true if
// there are available slots in the map after the trim (i.e, the map is below
// [config.MaxConcurrentRequests]).
func trimStore() bool {
	if store.Size() < triggerTrimThreshold {
		return true
	}
	store.DeleteMatching(func(key weak.Pointer[tracer.Span], _ *Annotation) (delete bool, stop bool) {
		return key.Value() == nil, false
	})
	return store.Size() < config.MaxConcurrentRequests
}

// samplingDecision returns true if the request should be sampled for IAST.
func samplingDecision() bool {
	switch config.RequestSamplingPct {
	case 0:
		return false
	case 100:
		return true
	default:
		return rand.IntN(100) < config.RequestSamplingPct
	}
}

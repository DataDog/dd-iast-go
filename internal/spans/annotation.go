// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
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
	// +checklocks:RWMutex
	model.Event

	Sampled bool

	// RequestTainted is the number of tainted elemets at the end of the request.
	RequestTainted atomic.Uint64
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
				root.SetTag(SpanTagEnabled, 1)
			} else {
				root.SetTag(SpanTagEnabled, 0)
			}
			return ann, false
		},
	)

	if ann == nil {
		ann = new(Annotation)
	}

	return ann
}

func (a *Annotation) submitTelemetry() {
	if config.TelemetryVerbosity == config.LogLevelOff {
		return
	}
	client := instrumentation.Instance.TelemetryMetrics()
	client.Count(instrumentation.TelemetryNamespaceIAST, "request.tainted", nil).Submit(float64(a.RequestTainted.Load()))
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

func init() {
	// Note: this is here and not in the [github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry] package in
	// order to avoid creating a dependency from it to some of the tracer's internal, as it would make it much harder to
	// avoid creating circular dependencies when instrumenting packages the tracer itself uses.
	instrumentation.Instance.TelemetryMetrics().OnHeartbeat(func(c instrumentation.TelemetryMetrics) {
		if config.TelemetryVerbosity == config.LogLevelOff {
			return
		}

		for origin, count := range telemetry.InstrumentedSource {
			c.Count(instrumentation.TelemetryNamespaceIAST, "instrumented.source", []string{instrumentation.TelemetryTagSourceType + ":" + origin.String()}).Submit(float64(count))
		}
		c.Count(instrumentation.TelemetryNamespaceIAST, "instrumented.propagation", nil).Submit(float64(telemetry.InstrumentedPropagation))
		for vulnType, count := range telemetry.InstrumentedSink {
			c.Count(instrumentation.TelemetryNamespaceIAST, "instrumented.sink", []string{instrumentation.TelemetryTagVulnerabilityType + ":" + vulnType.String()}).Submit(float64(count))
		}

		cnt := telemetry.ExecutedTainted.Swap(0)
		if cnt != 0 {
			c.Count(instrumentation.TelemetryNamespaceIAST, "executed.tainted", nil).Submit(float64(cnt))
		}
		for origin, count := range telemetry.ExecutedSource.Each {
			cnt := count.Swap(0)
			if cnt == 0 {
				continue
			}
			c.Count(instrumentation.TelemetryNamespaceIAST, "executed.source", []string{instrumentation.TelemetryTagSourceType + ":" + origin.String()}).Submit(float64(cnt))
		}
		for vulnType, count := range telemetry.ExecutedSink.Each {
			cnt := count.Swap(0)
			if cnt == 0 {
				continue
			}
			c.Count(instrumentation.TelemetryNamespaceIAST, "executed.sink", []string{instrumentation.TelemetryTagVulnerabilityType + ":" + vulnType.String()}).Submit(float64(cnt))
		}

		if config.TelemetryVerbosity != config.LogLevelDebug {
			return
		}
		cnt = telemetry.ExecutedPropagation.Swap(0)
		if cnt != 0 {
			c.Count(instrumentation.TelemetryNamespaceIAST, "executed.propagation", nil).Submit(float64(cnt))
		}
	})
}

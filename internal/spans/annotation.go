// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/config/loader"
	"github.com/DataDog/dd-iast-go/internal/instrumentation"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/puzpuzpuz/xsync/v4"
)

var (
	// nonSampledAnnotation is immutable by convention. Reporting returns before
	// touching Event or RequestTainted when Sampled is false.
	nonSampledAnnotation = new(Annotation)
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
	closed atomic.Bool
	// +checklocks:RWMutex
	sourceIdentities []SourceIdentity
	// +checklocks:RWMutex
	sourceIdentityBytes int64
	// +checklocks:RWMutex
	sourceIndex [2 * MaxEventSources]uint16
	// +checklocks:RWMutex
	eventSourceIndexes [MaxEventSources]int

	// Sampled is immutable after annotation construction.
	Sampled bool

	// RequestTainted is the number of tainted elemets at the end of the request.
	RequestTainted atomic.Uint64
}

// Closed reports whether span finishing has closed the annotation.
func (a *Annotation) Closed() bool {
	return a == nil || a.closed.Load()
}

// TryUseOpen invokes use with the annotation exclusively locked when it is
// open. It returns false on nil, contention, or a closed annotation. The
// callback must not re-lock the annotation, finish its span, or let a panic
// escape.
func (a *Annotation) TryUseOpen(use func(*Annotation)) bool {
	if a == nil || use == nil || !a.Sampled {
		return false
	}
	if !a.RWMutex.TryLock() {
		return false
	}
	defer a.RWMutex.Unlock() // +checklocksforce: TryLock.
	if a.closed.Load() {
		return false
	}
	use(a)
	return true
}

// ExistingForSpan returns the existing root annotation without creating one.
// The caller must use Annotation.TryUseOpen and tolerate closure after return.
func ExistingForSpan(span *tracer.Span) (*tracer.Span, *Annotation, bool) {
	if span == nil {
		return nil, nil, false
	}
	root := span.Root()
	if root == nil {
		root = span
	}
	annotation, ok := store.Load(weak.Make(root))
	if !ok || annotation == nil || annotation.Closed() {
		return nil, nil, false
	}
	return root, annotation, true
}

// TryUseExisting invokes use with the existing open annotation for span
// exclusively locked. It never creates an annotation. The callback has the
// same restrictions as [Annotation.TryUseOpen].
func TryUseExisting(span *tracer.Span, use func(*Annotation)) bool {
	if span == nil {
		return false
	}
	root := span.Root()
	if root == nil {
		root = span
	}
	ann, ok := store.Load(weak.Make(root))
	return ok && ann.TryUseOpen(use)
}

// AnnotationFor returns the [*Annotation] for the root of the given
// [*tracer.Span] (or the span itself if it does not have a valid, un-finished
// root). If none exists yet and storage has capacity, a new [*Annotation] is
// allocated, retaining both positive and negative sampling decisions.
func AnnotationFor(span *tracer.Span) *Annotation {
	if span == nil {
		return nonSampledAnnotation
	}
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
	ann, _ := store.LoadOrCompute(ptr, func() (*Annotation, bool) {
		if !hasSpace {
			instrumentation.Instance.TelemetryLog().
				Warn("iast/annotation: max concurrent requests reached, not storing annotation for span", slog.Any("span", spanID))
			return nil, true
		}
		return &Annotation{Sampled: samplingDecision()}, false
	})
	if ann == nil {
		ann = nonSampledAnnotation
	}
	root.SetTag(SpanTagEnabled, ann.enabledTag())
	return ann
}

// BindScopeContext binds a handler context and discards the annotation result.
func BindScopeContext(ctx context.Context) {
	BindScopeFromContext(ctx)
}

// BindScopeFromContext binds a scope and span carried by ctx, when both exist.
func BindScopeFromContext(ctx context.Context) *Annotation {
	scope := request.FromContext(ctx)
	if scope == nil {
		return nil
	}
	span, ok := tracer.SpanFromContext(ctx)
	if !ok {
		return nil
	}
	return BindScope(span, scope)
}

// AnnotationForContext reuses the request's precomputed decision when present.
// Taint-free orphan and non-request findings retain the legacy sampling path.
func AnnotationForContext(ctx context.Context, span *tracer.Span) *Annotation {
	if scope := request.FromContext(ctx); scope != nil {
		if ann := BindScope(span, scope); ann != nil {
			return ann
		}
		return nonSampledAnnotation
	}
	return AnnotationFor(span)
}

// BindScope reuses the root span's decision or, when space is available, stores
// the request's current decision. A stored span decision takes precedence.
func BindScope(span *tracer.Span, scope *request.Scope) *Annotation {
	if span == nil || scope == nil {
		return nil
	}
	root := span.Root()
	if root == nil {
		root = span
	}
	ptr := weak.Make(root)
	if existing, ok := store.Load(ptr); ok {
		if !existing.Sampled {
			return nil
		}
		bindOwnerSpan(scope, root, existing)
		return existing
	}
	active := scope.Active()
	hasSpace := trimStore()
	ann, _ := store.LoadOrCompute(ptr, func() (*Annotation, bool) {
		if !hasSpace {
			return nil, true
		}
		return &Annotation{Sampled: active}, false
	})
	if ann == nil || !ann.Sampled {
		root.SetTag(SpanTagEnabled, 0)
		return nil
	}
	root.SetTag(SpanTagEnabled, 1)
	bindOwnerSpan(scope, root, ann)
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
	if config.MaxConcurrentRequests == 0 {
		return false
	}
	if store.Size() < triggerTrimThreshold {
		return true
	}
	store.DeleteMatching(releaseDeadAnnotation)
	return store.Size() < config.MaxConcurrentRequests
}

// +checklocksignore
func releaseDeadAnnotation(key weak.Pointer[tracer.Span], ann *Annotation) (delete bool, stop bool) {
	if key.Value() != nil || ann == nil {
		return false, false
	}
	if !ann.RWMutex.TryLock() {
		return false, false
	}
	defer ann.RWMutex.Unlock() // +checklocksforce: TryLock.
	ann.closed.Store(true)
	ann.releaseSourceIdentities()
	return true, false
}

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

func (a *Annotation) enabledTag() int {
	if a != nil && a.Sampled {
		return 1
	}
	return 0
}

func init() {
	enabled := config.Observe(loader.Observer{
		Warn: func(format string, args ...any) {
			instrumentation.Instance.Logger().Warn(format, args...)
		},
		RegisterDefault: func(name string, value any) {
			instrumentation.Instance.TelemetryRegisterAppConfig(name, value, instrumentation.OriginDefault)
		},
		RegisterEnvironment: func(name string, value any) {
			instrumentation.Instance.TelemetryRegisterAppConfig(name, value, instrumentation.OriginEnvVar)
		},
	})
	if enabled {
		instrumentation.Instance.TelemetryProductStarted(instrumentation.TelemetryNamespaceIAST)
	}

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
		cnt = telemetry.CoarsenedPropagation.Swap(0)
		if cnt != 0 {
			c.Count(instrumentation.TelemetryNamespaceIAST, "propagation.coarsened", nil).Submit(float64(cnt))
		}
		cnt = telemetry.DroppedPropagation.Swap(0)
		if cnt != 0 {
			c.Count(instrumentation.TelemetryNamespaceIAST, "propagation.dropped", nil).Submit(float64(cnt))
		}
	})
}

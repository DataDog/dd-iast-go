// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"runtime"
	"sync"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/puzpuzpuz/xsync/v3"
)

var (
	// maxAnnotations is the maximum size of the store map before we start
	// dropping values.
	maxAnnotations = 128
	// store is the association of tracer spans to annotation objects.
	store = xsync.NewMapOf[weak.Pointer[tracer.Span], *Annotation](xsync.WithPresize(maxAnnotations))
	// triggerTrimThreshold is the threshold utilization at which we start
	// actively trying to remove dead keys from the map.
	triggerTrimThreshold = maxAnnotations * 3 / 4
)

type Annotation struct {
	sync.RWMutex
	model.Event
}

// AnnotationFor returns the [*Annotation] for the root of the given
// [*tracer.Span] (or the span itself if it does not have a valid, un-finished
// root). If none exists yet, a new [*Annotation] is allocated.
func AnnotationFor(span *tracer.Span) *Annotation {
	if !trimStore() {
		return &Annotation{}
	}

	root := span.Root()
	if root == nil {
		root = span
	}

	ptr := weak.Make(root)
	event, _ := store.LoadOrCompute(
		ptr,
		func() *Annotation {
			runtime.AddCleanup(
				span,
				func(ptr weak.Pointer[tracer.Span]) {
					store.Delete(ptr)
				},
				ptr,
			)
			return new(Annotation)
		},
	)

	return event
}

// trimStore removes keys from the map where the [weak.Pointer] has turned nil,
// if the current utilization is over [triggerTrimThreshold]. Returns true if
// there are available slots in the map after the trim (i.e, the map is below
// [maxAnnotations]).
func trimStore() bool {
	if store.Size() < triggerTrimThreshold {
		return true
	}
	store.Range(func(key weak.Pointer[tracer.Span], _ *Annotation) bool {
		if key.Value() == nil {
			store.Delete(key)
		}
		return true
	})
	return store.Size() < maxAnnotations
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package spans

import (
	"runtime"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/puzpuzpuz/xsync/v3"
)

var (
	maxAnnotations = 128
	store          = xsync.NewMapOf[weak.Pointer[tracer.Span], *model.Event](xsync.WithPresize(maxAnnotations))
)

func AnnotationFor(span *tracer.Span) *model.Event {
	trimStore()

	ptr := weak.Make(span)
	event, _ := store.LoadOrCompute(
		ptr,
		func() *model.Event {
			runtime.AddCleanup(
				span,
				func(ptr weak.Pointer[tracer.Span]) {
					store.Delete(ptr)
				},
				ptr,
			)
			return new(model.Event)
		},
	)
	return event
}

func trimStore() {
	if store.Size() < maxAnnotations {
		return
	}
	store.Range(func(key weak.Pointer[tracer.Span], _ *model.Event) bool {
		if key.Value() == nil {
			store.Delete(key)
		}
		return true
	})
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package http instruments net/http request ownership and application handler
// binding. Import it through the repository's Orchestrion tool package.
package http

import (
	"context"

	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// BindStartSpan binds an already-created span context to its request scope and
// returns the span and context unchanged. It supports the multi-result expression
// wrapper for tracer.StartSpanFromContext call sites.
func BindStartSpan(ctx context.Context, span *tracer.Span) (*tracer.Span, context.Context) {
	if request.FromContext(ctx) != nil {
		spans.BindScopeFromContext(ctx)
	}
	return span, ctx
}

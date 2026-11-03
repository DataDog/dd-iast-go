// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

// This file is not part of the "spans" package. The otelc rules in otelc.yml
// ("span_finish_declarations") copy it into the dd-trace-go "ddtrace/tracer"
// package at build time. The "//go:build ignore" constraint keeps it out of this
// package.

package tracer

import _ "unsafe" // For go:linkname

//go:linkname __dd__iast_spans_Finished github.com/DataDog/dd-iast-go/internal/spans.Finished
func __dd__iast_spans_Finished(span *Span)

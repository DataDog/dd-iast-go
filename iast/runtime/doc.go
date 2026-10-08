// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package runtime weaves taint propagation hooks into the Go runtime. The
// hooks copy the heap taint bits of internal/taint/heapbits through string
// concatenation, []byte(a+b), string(b), []byte(s), string(runes), []rune(s),
// and the copy of the old elements when append grows a slice (growslice). Import
// it through the repository's Orchestrion tool package.
//
// The hooks use the bit functions that the aspects of internal/taint/heapbits
// inject in the runtime: both packages must be imported in orchestrion.tool.go.
// Without the heapbits aspects, the build fails ("undefined: __dd_taint_...").
//
// The hooks do not change the application source code, so they do not change
// the evaluation order or the constant expressions of the application. Slices
// of a tainted value need no hook: the bits describe memory, and a slice uses
// the same memory.
//
// The hooks do nothing until the first taint is set in the process (the sticky
// gate of heapbits). After that, they cost one taint check for each input.
//
// Not hooked: copy, the appended part of append(x, y...), and make + copy (the
// compiler emits an inline memmove). These forms lose the taint.
//
// The propagation of []byte(s) and []rune(s) can be turned off (the
// DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED setting, stored by package
// propbridge): the mutable results of these conversions can keep taint after a
// direct write that IAST does not see.
package runtime

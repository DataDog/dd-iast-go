// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package runtime weaves taint propagation hooks into the Go runtime. The
// hooks propagate taint through string concatenation, []byte(a+b), string(b),
// []byte(s), string(rs) and []rune(s). Import it through the repository's
// Orchestrion tool package.
//
// The hooks do not change the application source code, so they do not change
// the evaluation order or the constant expressions of the application. Slices
// of a tainted value need no hook: the store finds every window of a tainted
// root through its interior-pointer index.
//
// Set DD_IAST_STRING_TO_SLICE_PROPAGATION_ENABLED=false to turn off the
// propagation of []byte(s) and []rune(s). The mutable results of these
// conversions can keep taint after a direct write that IAST does not see.
package runtime

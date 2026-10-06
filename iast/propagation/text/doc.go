// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package text holds the taint propagation hooks of the standard library
// packages strings, bytes, strconv and net/url (see orchestrion.yml). The
// hooks are injected in the standard library at compile time by Orchestrion;
// this package only counts them for the telemetry.
//
// The hooks copy the heap taint bits of package internal/taint/heapbits where
// the standard library copies bytes with copy (or with the appended part of
// append): the runtime hooks of iast/runtime cannot see these copies. For the
// functions that change bytes (case changes, quote, escape), the hooks set the
// bits of the output and record a derived entry, so that the sink can find the
// source of the output (plan heapbits-sqli-cmdi, sections 6.2 and 6.3).
package text

import "github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"

// instrumentedPropagationPoints is the number of aspects of orchestrion.yml
// (one for each hooked function).
const instrumentedPropagationPoints = 28

func init() {
	telemetry.InstrumentedPropagation += instrumentedPropagationPoints
}

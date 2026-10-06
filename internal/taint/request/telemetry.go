// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	_ "unsafe" // linkname

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
)

// The number of hooks of the standard library propagation packages
// (iast/propagation/text, iast/propagation/stream and
// iast/propagation/jsonv2). The application does
// not link these packages: Orchestrion only reads their orchestrion.yml. The
// woven standard library packages strings and fmt push the numbers (pull
// linkname here); they are 0 when the program is not woven with these
// aspects.
var (
	//go:linkname textPoints __dd_iast_telemetry.text_points
	textPoints uint32

	//go:linkname streamPoints __dd_iast_telemetry.stream_points
	streamPoints uint32

	// jsonv2Points is pushed by encoding/json/jsontext, which is in the
	// build only with GOEXPERIMENT=jsonv2 (the default of Go 1.27).
	//
	//go:linkname jsonv2Points __dd_iast_telemetry.jsonv2_points
	jsonv2Points uint32
)

// stdlibPropagationPoints returns the number of woven propagation hooks of
// the standard library (the text, stream and jsonv2 aspects).
func stdlibPropagationPoints() uint {
	return uint(textPoints) + uint(streamPoints) + uint(jsonv2Points)
}

func init() {
	telemetry.InstrumentedPropagation += stdlibPropagationPoints()
}

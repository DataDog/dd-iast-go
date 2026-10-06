// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// TestStdlibPropagationPoints: this test program does not import
// iast/propagation/text or iast/propagation/stream (their init functions do
// not run), but the woven packages strings and fmt give the number of their
// hooks to telemetry. The numbers are instrumentedPropagationPoints of
// iast/propagation/text (28) and iast/propagation/stream (18), plus
// iast/propagation/jsonv2 (3) when encoding/json/jsontext is in the build
// (GOEXPERIMENT=jsonv2, the default of Go 1.27).
func TestStdlibPropagationPoints(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	want := uint(28 + 18)
	if jsonv2Points != 0 {
		require.Equal(t, uint32(3), jsonv2Points)
		want += 3
	}
	require.Equal(t, want, telemetry.InstrumentedPropagation)
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	_ "encoding/json" // the woven encoding/json pushes the number of its hooks
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// TestStdlibPropagationPoints: this test program does not import
// iast/propagation/text, iast/propagation/stream or iast/propagation/jsonv2
// (their init functions do not run), but the woven standard library packages
// give the number of their hooks to telemetry. The numbers are
// instrumentedPropagationPoints of iast/propagation/text (34) and
// iast/propagation/stream (14), plus the hooks of the encoding/json variant
// of the build:
//
//   - without GOEXPERIMENT=jsonv2 (Go 1.26.6 by default, Go 1.27.1 with
//     GOEXPERIMENT=nojsonv2): the 4 encoding/json hooks of
//     iast/propagation/stream (total 52);
//   - with GOEXPERIMENT=jsonv2 (Go 1.27.1 by default): the 3 hooks of
//     iast/propagation/jsonv2 (total 51).
func TestStdlibPropagationPoints(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	require.Equal(t, uint32(34), textPoints)
	require.Equal(t, uint32(14), streamPoints)
	if jsonv2Experiment {
		require.Zero(t, streamJSONPoints, "the v1 files of encoding/json are not in the build")
		require.Equal(t, uint32(3), jsonv2Points)
		require.Equal(t, uint(51), telemetry.InstrumentedPropagation)
	} else {
		require.Equal(t, uint32(4), streamJSONPoints)
		require.Zero(t, jsonv2Points, "encoding/json/jsontext is not in the build")
		require.Equal(t, uint(52), telemetry.InstrumentedPropagation)
	}
}

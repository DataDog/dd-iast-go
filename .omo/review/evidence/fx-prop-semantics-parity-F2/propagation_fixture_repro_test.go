// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func TestFmtSprintf_marks_zero_precision_operand_as_sql_evidence(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("reproducer requires Orchestrion")
	}

	// Given
	ctx := beginNativePropagation(t)
	operand := nativeStringSource(t, ctx, "unemitted", "attacker-controlled")
	const cleanQuery = "SELECT 40 + 2 /*  */"

	// When
	query := testapp.Sprintf("SELECT 40 + 2 /* %.0s */", operand)
	_, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)

	// Then
	t.Logf("query=%q native_bytes=%q query_tainted=%t clean_control_tainted=%t sink_status=%v",
		query, cleanQuery, taint.IsTaintedString(query), taint.IsTaintedString(cleanQuery), status)
	require.Equal(t, cleanQuery, query, "the zero-precision operand emitted no bytes")
	require.True(t, taint.IsTaintedString(query), "reproducer: clean output inherits taint from the omitted operand")
	require.False(t, taint.IsTaintedString(cleanQuery), "byte-identical literal control remains clean")
	require.Equal(t, evidence.StatusCollected, status, "the SQL sink would collect false taint")
}

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

type parityTable struct{ Name string }

func (table parityTable) String() string { return table.Name }

func TestParitySprintfStructFieldKeepsTaint(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("reproducer requires Orchestrion")
	}
	ctx := beginNativePropagation(t)
	input := nativeStringSource(t, ctx, "column", "users WHERE 1=1 --")

	query := testapp.Sprintf("SELECT * FROM %v", parityTable{Name: input})

	_, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	t.Logf("query=%q tainted=%t sql_collection=%v", query, taint.IsTaintedString(query), status)
	require.True(t, taint.IsTaintedString(query), "a formatted tainted struct field must reach the SQL sink")
}

func TestParityMapDeletingTaintedSuffixLeavesCleanSQL(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("reproducer requires Orchestrion")
	}
	ctx := beginNativePropagation(t)
	input := nativeStringSource(t, ctx, "suffix", "XXXX")
	query := testapp.Map(func(r rune) rune {
		if r == 'X' {
			return -1
		}
		return r
	}, "SELECT 1 "+input)

	_, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	t.Logf("query=%q tainted=%t clean_control_tainted=%t sql_collection=%v",
		query, taint.IsTaintedString(query), taint.IsTaintedString("SELECT 1 "), status)
	require.Equal(t, "SELECT 1 ", query)
	require.False(t, taint.IsTaintedString(query), "removed input must not taint the retained constant query")
}

func TestParitySprintfZeroPrecisionLeavesCleanSQL(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("reproducer requires Orchestrion")
	}
	ctx := beginNativePropagation(t)
	input := nativeStringSource(t, ctx, "suffix", "ATTACK")

	query := testapp.Sprintf("SELECT 1%.0s", input)

	_, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	t.Logf("query=%q tainted=%t clean_control_tainted=%t sql_collection=%v",
		query, taint.IsTaintedString(query), taint.IsTaintedString("SELECT 1"), status)
	require.Equal(t, "SELECT 1", query)
	require.False(t, taint.IsTaintedString(query), "zero-width formatted input must not taint constant output")
}

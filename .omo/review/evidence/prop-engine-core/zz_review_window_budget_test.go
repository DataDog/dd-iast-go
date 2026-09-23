package propagation_test

import (
	"strings"
	"testing"
	"unsafe"

	wrappers "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

func TestReviewStringSplit_retains_last_nonempty_field_after_empty_fields(t *testing.T) {
	// Given: 32 empty fields precede the only non-empty field.
	_, scope := beginScope(t)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	value, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "query", strings.Repeat(",", 32)+"attack")
	require.True(t, ok)
	require.True(t, request.IsTaintedString(value), "the source must be registered")
	require.False(t, request.IsTaintedString(strings.Clone("attack")), "byte-identical clean control")

	// When: the direct-call wrapper derives split result windows.
	fields := wrappers.StringsSplit(value, ",")

	// Then: the first 32 fields are empty, but the 33rd is still a tainted window.
	require.Len(t, fields, 33)
	require.Equal(t, "attack", fields[32])
	t.Logf("string last field=%q, tainted=%t", fields[32], request.IsTaintedString(fields[32]))
	require.True(t, request.IsTaintedString(fields[32]), "the first nonempty field must keep provenance")
}

func TestReviewBytesSplit_retains_last_nonempty_field_after_empty_fields(t *testing.T) {
	// Given: the same shape for a tracked byte root.
	_, scope := beginScope(t)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	value, ok := analysis.TaintBytes(constants.OriginHttpRequestParameter, "body", []byte(strings.Repeat(",", 32)+"attack"))
	require.True(t, ok)
	require.True(t, request.IsTaintedBytes(value), "the source must be registered")
	require.False(t, request.IsTaintedBytes([]byte("attack")), "byte-identical clean control")

	// When: the direct-call wrapper derives split result windows.
	fields := wrappers.BytesSplit(value, []byte(","))

	// Then: the 33rd field should retain its owner and source.
	require.Len(t, fields, 33)
	require.Equal(t, []byte("attack"), fields[32])
	t.Logf("bytes last field=%q, tainted=%t", fields[32], request.IsTaintedBytes(fields[32]))
	require.True(t, request.IsTaintedBytes(fields[32]), "the first nonempty field must keep provenance")
}

func TestReviewEmptyWindows_do_not_count_as_dropped_provenance(t *testing.T) {
	// Given: a tracked source but no publishable output windows.
	_, scope := beginScope(t)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	value, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "query", "attacker")
	require.True(t, ok)
	before := telemetry.DroppedPropagation.Load()

	// When: the list contains 33 empty outputs.
	propagation.StringWindows(value, make([]string, 33))

	// Then: no provenance contribution was dropped.
	after := telemetry.DroppedPropagation.Load()
	t.Logf("empty windows: dropped counter before=%d after=%d", before, after)
	require.Equal(t, before, after)
}

func TestWindowReviewCleanDerivedWindow_does_not_clone_result(t *testing.T) {
	// Given: the input is a clean region in a tainted managed root.
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	root, _ := taintString(t, owner, "xxa b", []ranges.Range{{Length: 2, SourceID: 1}})
	clean := root[2:]
	propagation.StringWindow(root, clean)
	require.False(t, request.IsTaintedString(clean))
	native := strings.ReplaceAll(clean, " ", "+")

	// When: a coarse transform receives that clean derived input.
	out := propagation.CoarseString(native, clean)

	// Then: unchanged provenance must not force a second allocation.
	t.Logf("clean input: result cloned=%t, tainted=%t", unsafe.StringData(out) != unsafe.StringData(native), request.IsTaintedString(out))
	require.True(t, unsafe.StringData(out) == unsafe.StringData(native))
}

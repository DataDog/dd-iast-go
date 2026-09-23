package propagation_test

import (
	"iter"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

var reviewSequence iter.Seq[string]

func TestReviewStringsIteratorFactoryNoOwnerAllocations(t *testing.T) {
	input := "alpha,beta,gamma"
	nativeDirect := testing.AllocsPerRun(100, func() {
		reviewSequence = strings.SplitSeq(input, ",")
	})
	wrappedDirect := testing.AllocsPerRun(100, func() {
		reviewSequence = propagation.StringsSplitSeq(input, ",")
	})
	t.Logf("direct SplitSeq allocations/call: native=%.0f wrapped=%.0f", nativeDirect, wrappedDirect)
	require.Equal(t, nativeDirect, wrappedDirect)
	for _, test := range []struct {
		name   string
		native func() iter.Seq[string]
		wrap   func() iter.Seq[string]
	}{
		{"SplitSeq", func() iter.Seq[string] { return strings.SplitSeq(input, ",") }, func() iter.Seq[string] { return propagation.StringsSplitSeq(input, ",") }},
		{"SplitAfterSeq", func() iter.Seq[string] { return strings.SplitAfterSeq(input, ",") }, func() iter.Seq[string] { return propagation.StringsSplitAfterSeq(input, ",") }},
		{"Lines", func() iter.Seq[string] { return strings.Lines(input) }, func() iter.Seq[string] { return propagation.StringsLines(input) }},
		{"FieldsSeq", func() iter.Seq[string] { return strings.FieldsSeq(input) }, func() iter.Seq[string] { return propagation.StringsFieldsSeq(input) }},
		{"FieldsFuncSeq", func() iter.Seq[string] { return strings.FieldsFuncSeq(input, func(r rune) bool { return r == ',' }) }, func() iter.Seq[string] {
			return propagation.StringsFieldsFuncSeq(input, func(r rune) bool { return r == ',' })
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, slices.Collect(test.native()), slices.Collect(test.wrap()))
			native := testing.AllocsPerRun(100, func() { reviewSequence = test.native() })
			wrapped := testing.AllocsPerRun(100, func() { reviewSequence = test.wrap() })
			t.Logf("factory allocations/call: native=%.0f wrapped=%.0f", native, wrapped)
			require.Equal(t, native, wrapped, "no-owner wrapper should not allocate more than the native iterator")
		})
	}
}

func TestReviewStringsNamedAndGenericCallsPropagate(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires woven application calls")
	}
	value := activeString(t, "  alpha,beta  ")
	requireTaintedStrings(t, testapp.ReviewNamedTrim(value))
	requireTaintedStrings(t, testapp.ReviewGenericTrim(value))
	before, after, found := testapp.ReviewGenericCut(value)
	require.True(t, found)
	requireTaintedStrings(t, before, after)
}

func TestReviewReplacerReceiverAndArgumentEvaluateOnce(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires woven application calls")
	}
	value := activeString(t, "  alpha,beta  ")
	result, receivers, arguments := testapp.ReviewReplacerEvaluation(value)
	require.Equal(t, "  alpha;beta  ", result)
	require.Equal(t, 1, receivers)
	require.Equal(t, 1, arguments)
	require.True(t, taint.IsTaintedString(result))
}

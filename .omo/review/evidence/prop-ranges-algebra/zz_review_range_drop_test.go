package propagation_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestReview_JoinRecordsRangeTruncationWhenEleventhRangeIsDropped(t *testing.T) {
	// Given eleven separated copies of a tainted, two-byte source.
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintString(t, owner, "AB", []ranges.Range{{Length: 2, SourceID: 1}})
	elements := make([]string, 11)
	for i := range elements {
		elements[i] = input
	}
	beforeRanges := owner.Counters().Ranges
	beforePropagation := telemetry.DroppedPropagation.Load()

	// When JoinString creates eleven disjoint tainted ranges at limit ten.
	value := propagation.JoinString(elements, ".", strings.Join(elements, "."))
	got := lookupRanges(s, value)
	afterRanges := owner.Counters().Ranges
	afterPropagation := telemetry.DroppedPropagation.Load()
	t.Logf("result ranges=%d; owner range drops=%d -> %d; propagation drops=%d -> %d",
		len(got), beforeRanges, afterRanges, beforePropagation, afterPropagation)

	// Then its documented tail drop must be observable in a drop counter.
	require.Len(t, got, 10)
	require.True(t, afterRanges > beforeRanges || afterPropagation > beforePropagation,
		"the eleventh range was discarded without recording a range drop")
}

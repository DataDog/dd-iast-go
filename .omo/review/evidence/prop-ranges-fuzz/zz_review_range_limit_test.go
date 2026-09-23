// Review-only reproducer (prop-ranges-fuzz): coarse results are adopted with
// ranges.DefaultLimit instead of config.MaxRangeCount, and every later exact
// operation inherits the limit of the first owner entry it sees. The effective
// range cap therefore depends on value history and argument order.

package propagation_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/stretchr/testify/require"
)

func reviewJoinAfterCoarse(t *testing.T, configured uint64, sources int) (direct, viaCoarse int) {
	previous := config.MaxRangeCount
	config.MaxRangeCount = configured
	t.Cleanup(func() { config.MaxRangeCount = previous })

	s, scope := beginScope(t)
	analysis, ok := scope.Analysis()
	require.True(t, ok)
	elements := make([]string, sources)
	for i := range elements {
		v, ok := analysis.TaintString(constants.OriginHttpRequestParameter, fmt.Sprintf("p%d", i), fmt.Sprintf("v%02d", i))
		require.True(t, ok)
		elements[i] = v
	}
	// Baseline: exact join over the raw sources (first entry carries the configured limit).
	joined := propagation.JoinString(elements, ",", strings.Join(elements, ","))
	direct = len(lookupRanges(s, joined))

	// Same shape, but the first element went through a coarse transform first
	// (e.g. strings.ToUpper on non-ASCII, fmt.Sprint, url.QueryEscape).
	coarse := propagation.CoarseString(strings.Clone("C"+elements[0][1:]), elements[0])
	require.NotEmpty(t, lookupRanges(s, coarse))
	withCoarse := append([]string{coarse}, elements[1:]...)
	joined2 := propagation.JoinString(withCoarse, ",", strings.Join(withCoarse, ","))
	viaCoarse = len(lookupRanges(s, joined2))
	t.Logf("configured DD_IAST_MAX_RANGE_COUNT=%d sources=%d: direct join ranges=%d, join-after-coarse ranges=%d", configured, sources, direct, viaCoarse)
	return direct, viaCoarse
}

func TestReviewCoarseResetsConfiguredRangeLimit(t *testing.T) {
	t.Run("configured_64_truncated_to_10", func(t *testing.T) {
		direct, viaCoarse := reviewJoinAfterCoarse(t, 64, 16)
		require.Equal(t, 16, direct)
		require.Equal(t, 16, viaCoarse, "configured limit 64 must be honored after a coarse step")
	})
	t.Run("configured_2_exceeded", func(t *testing.T) {
		direct, viaCoarse := reviewJoinAfterCoarse(t, 2, 6)
		require.Equal(t, 2, direct)
		require.LessOrEqual(t, viaCoarse, 2, "configured limit 2 must not be exceeded after a coarse step")
	})
}

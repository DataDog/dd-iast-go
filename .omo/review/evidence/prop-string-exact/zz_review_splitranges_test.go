package propagation_test

import (
	"strings"
	"testing"

	wrappers "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func TestReviewStringsSplitTaintedFirstNonEmptyAfterEmptyPrefix(t *testing.T) {
	// Given: a live source whose split begins with 32 empty elements.
	input := activeString(t, strings.Repeat(",", 32)+"secret")

	// When: the supported strings.Split wrapper derives all results.
	parts := wrappers.StringsSplit(input, ",")

	// Then: the first non-empty result should retain its source.
	require.Len(t, parts, 33)
	require.Equal(t, "secret", parts[32])
	require.True(t, taint.IsTaintedString(parts[32]), "first non-empty result loses taint")
}

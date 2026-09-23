package propagation_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestReviewSplitEmptyPrefixPreservesFirstNonEmptyWindow(t *testing.T) {
	// Given: 32 empty Split results precede the only non-empty result.
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input := strings.Repeat(",", 32) + "secret"
	managed, _ := taintString(t, owner, input, []ranges.Range{
		{Start: 32, Length: 6, SourceID: 7},
	})

	// When: a supported split derives its substring windows.
	parts := strings.Split(managed, ",")
	require.Len(t, parts, 33)
	propagation.StringWindows(managed, parts)

	// Then: the first non-empty result keeps its exact source and offset.
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 7}}, lookupRanges(s, parts[32]))
}

func TestReviewReplaceEmptyOldAndOverlappingMatches(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		old         string
		replacement string
		n           int
		want        []ranges.Range
	}{
		{
			name:  "count zero ignores replacement",
			input: "aaaa", old: "aa", replacement: "XY", n: 0,
			want: []ranges.Range{{Length: 4, SourceID: 7}},
		},
		{
			name:  "negative count uses nonoverlapping matches",
			input: "aaaa", old: "aa", replacement: "XY", n: -1,
			want: []ranges.Range{{Length: 4, SourceID: 8}},
		},
		{
			name:  "single match keeps the unmapped suffix",
			input: "aaaa", old: "aa", replacement: "XY", n: 1,
			want: []ranges.Range{{Length: 2, SourceID: 8}, {Start: 2, Length: 2, SourceID: 7}},
		},
		{
			name:  "empty old inserts around UTF8 rune boundaries",
			input: "éx", old: "", replacement: "XY", n: -1,
			want: []ranges.Range{
				{Length: 2, SourceID: 8},
				{Start: 2, Length: 2, SourceID: 7},
				{Start: 4, Length: 2, SourceID: 8},
				{Start: 6, Length: 1, SourceID: 7},
				{Start: 7, Length: 2, SourceID: 8},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given: independent taint sources for the input and replacement.
			s, _ := beginScope(t)
			owner := acquireOwner(t, s)
			input, _ := taintString(t, owner, test.input, []ranges.Range{
				{Length: uint32(len(test.input)), SourceID: 7},
			})
			replacement, _ := taintString(t, owner, test.replacement, []ranges.Range{
				{Length: uint32(len(test.replacement)), SourceID: 8},
			})

			// When: the native operation is propagated.
			native := strings.Replace(input, test.old, replacement, test.n)
			got := propagation.ReplaceString(input, test.old, replacement, native, test.n)

			// Then: the result and each source's exact byte offsets agree.
			require.Equal(t, native, got)
			require.Equal(t, test.want, lookupRanges(s, got))
		})
	}
}

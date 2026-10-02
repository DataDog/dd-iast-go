// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func runeTestSet(t *testing.T, length uint32, raw ...ranges.Range) *ranges.Set {
	t.Helper()
	var set ranges.Set
	require.True(t, ranges.Canonicalize(&set, ranges.HardLimit, raw, length).Valid)
	return &set
}

func setRanges(set *ranges.Set) []ranges.Range {
	out := make([]ranges.Range, set.Len())
	set.CopyTo(out)
	return out
}

func rr(start, length uint32, source ranges.SourceID) ranges.Range {
	return ranges.Range{Start: start, Length: length, SourceID: source}
}

func TestStringRangesToRunes(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		in    []ranges.Range
		want  []ranges.Range
	}{
		{"ascii", "hello world", []ranges.Range{rr(6, 5, 1)}, []ranges.Range{rr(24, 20, 1)}},
		// "héllo 世界": h=0, é=1..2, l=3, l=4, o=5, space=6, 世=7..9, 界=10..12.
		{"multi-byte word", "héllo 世界", []ranges.Range{rr(7, 6, 1)}, []ranges.Range{rr(24, 8, 1)}},
		{"inside a rune", "héllo", []ranges.Range{rr(2, 3, 1)}, []ranges.Range{rr(4, 12, 1)}},
		{"two ranges in one rune", "é", []ranges.Range{rr(0, 1, 1), rr(1, 1, 2)}, []ranges.Range{rr(0, 4, 1)}},
		{"invalid byte", "a\xffb", []ranges.Range{rr(1, 1, 1)}, []ranges.Range{rr(4, 4, 1)}},
		{"two sources", "ab世cd", []ranges.Range{rr(0, 1, 1), rr(2, 3, 2), rr(6, 1, 3)}, []ranges.Range{rr(0, 4, 1), rr(8, 4, 2), rr(16, 4, 3)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			src := runeTestSet(t, uint32(len(test.value)), test.in...)
			var dst ranges.Set
			require.True(t, stringRangesToRunes(&dst, ranges.HardLimit, src, test.value, len([]rune(test.value))))
			require.Equal(t, test.want, setRanges(&dst))
		})
	}
	var dst ranges.Set
	src := runeTestSet(t, 4, rr(0, 4, 1))
	require.False(t, stringRangesToRunes(&dst, ranges.HardLimit, src, "ab", 2), "the ranges are longer than the value")
	require.False(t, stringRangesToRunes(&dst, ranges.HardLimit, runeTestSet(t, 2, rr(0, 2, 1)), "ab", 1), "too few runes")
	require.False(t, stringRangesToRunes(nil, ranges.HardLimit, src, "abcd", 4))
	require.True(t, stringRangesToRunes(&dst, ranges.HardLimit, &ranges.Set{}, "", 0))
	require.Zero(t, dst.Len())
}

func TestRuneRangesToString(t *testing.T) {
	for _, test := range []struct {
		name  string
		runes []rune
		in    []ranges.Range
		want  []ranges.Range
	}{
		{"ascii", []rune("hello world"), []ranges.Range{rr(24, 20, 1)}, []ranges.Range{rr(6, 5, 1)}},
		{"multi-byte word", []rune("héllo 世界"), []ranges.Range{rr(24, 8, 1)}, []ranges.Range{rr(7, 6, 1)}},
		{"partial rune bytes", []rune("héllo"), []ranges.Range{rr(5, 2, 1)}, []ranges.Range{rr(1, 2, 1)}},
		{"surrogate", []rune{'a', 0xD800, 'b'}, []ranges.Range{rr(4, 4, 1)}, []ranges.Range{rr(1, 3, 1)}},
		{"invalid rune", []rune{'a', -1, utf8.MaxRune + 1}, []ranges.Range{rr(4, 8, 1)}, []ranges.Range{rr(1, 6, 1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := string(test.runes)
			src := runeTestSet(t, uint32(4*len(test.runes)), test.in...)
			var dst ranges.Set
			require.True(t, runeRangesToString(&dst, ranges.HardLimit, src, test.runes, uint32(len(result))))
			require.Equal(t, test.want, setRanges(&dst))
		})
	}
	// A result shorter than the encoded runes (the runes changed during the
	// conversion) clips the ranges.
	runes := []rune("abcd")
	var dst ranges.Set
	require.True(t, runeRangesToString(&dst, ranges.HardLimit, runeTestSet(t, 16, rr(8, 8, 1)), runes, 3))
	require.Equal(t, []ranges.Range{rr(2, 1, 1)}, setRanges(&dst))
	require.True(t, runeRangesToString(&dst, ranges.HardLimit, runeTestSet(t, 16, rr(12, 4, 1)), runes, 3))
	require.Zero(t, dst.Len())
	require.False(t, runeRangesToString(&dst, ranges.HardLimit, runeTestSet(t, 20, rr(16, 4, 1)), runes, 4), "the ranges are longer than the runes")
}

func TestRuneRoundTripKeepsExactRanges(t *testing.T) {
	for _, value := range []string{"plain ascii text", "héllo 世界 ok", strings.Repeat("é世a", 20)} {
		runes := []rune(value)
		var raw []ranges.Range
		offset := 0
		for i, r := range runes {
			width := utf8.RuneLen(r)
			if i%3 == 0 {
				raw = append(raw, rr(uint32(offset), uint32(width), ranges.SourceID(1+i%5)))
			}
			offset += width
		}
		if len(raw) > ranges.HardLimit {
			raw = raw[:ranges.HardLimit]
		}
		src := runeTestSet(t, uint32(len(value)), raw...)
		var mid, back ranges.Set
		require.True(t, stringRangesToRunes(&mid, ranges.HardLimit, src, value, len(runes)))
		require.True(t, runeRangesToString(&back, ranges.HardLimit, &mid, runes, uint32(len(value))))
		require.Equal(t, setRanges(src), setRanges(&back), value)
	}
}

func TestRuneMappingDoesNotAllocate(t *testing.T) {
	value := "héllo 世界"
	runes := []rune(value)
	src := runeTestSet(t, uint32(len(value)), rr(1, 2, 1), rr(7, 3, 2))
	var mid, back ranges.Set
	require.Zero(t, testing.AllocsPerRun(100, func() {
		stringRangesToRunes(&mid, ranges.HardLimit, src, value, len(runes))
		runeRangesToString(&back, ranges.HardLimit, &mid, runes, uint32(len(value)))
	}))
}

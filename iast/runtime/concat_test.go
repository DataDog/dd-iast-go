// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/stretchr/testify/require"
)

// TestHooksFire checks that each of the 6 hooked runtime
// functions propagates the exact ranges of its input.
func TestHooksFire(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintString(t, ctx, "q", "attack")
	data := taintBytes(t, ctx, "b", []byte("00attack99"))
	text := taintString(t, ctx, "r", "héllo")
	runes := heapRunes("wörld!")
	adoptRunes(t, text, runes, 1, 5)

	t.Run("concatstrings", func(t *testing.T) {
		before := entries()
		got := heapConcat2("pre:", value)
		require.Equal(t, "pre:attack", got)
		require.Equal(t, []span{{4, 6, "q"}}, spansOf(got))
		require.Greater(t, entries(), before)
	})
	t.Run("concatbytes", func(t *testing.T) {
		got := heapConcatBytes("pre:", value)
		require.Equal(t, []byte("pre:attack"), got)
		require.Equal(t, []span{{4, 6, "q"}}, bytesSpansOf(got))
	})
	t.Run("slicebytetostring", func(t *testing.T) {
		got := heapB2S(data[1:9])
		require.Equal(t, "0attack9", got)
		require.Equal(t, []span{{0, 8, "b"}}, spansOf(got))
	})
	t.Run("stringtoslicebyte", func(t *testing.T) {
		got := heapS2B(value)
		require.Equal(t, []byte("attack"), got)
		require.Equal(t, []span{{0, 6, "q"}}, bytesSpansOf(got))
	})
	t.Run("slicerunetostring", func(t *testing.T) {
		// Runes 1 to 4 ("örld") are tainted. "ö" has 2 bytes in UTF-8.
		got := heapR2S(runes)
		require.Equal(t, "wörld!", got)
		require.Equal(t, []span{{1, 5, "r"}}, spansOf(got))
	})
	t.Run("stringtoslicerune", func(t *testing.T) {
		got := heapS2R(text)
		require.Equal(t, []rune("héllo"), got)
		require.Equal(t, [][2]uint32{{0, 20}}, runeRanges(got))
	})
}

type definedString string

func genericConcat[T ~string](left, right T) T { return left + right }

//go:noinline
func concat17(x, last string) string {
	return x + x + x + x + x + x + x + x + x + x + x + x + x + x + x + x + last
}

//go:noinline
func concat40(x, last string) string {
	return x + x + x + x + x + x + x + x + x + x +
		x + x + x + x + x + x + x + x + x + x +
		x + x + x + x + x + x + x + x + x + x +
		x + x + x + x + x + x + x + x + x + last
}

// concat18 concatenates a[0] to a[17] with one expression.
//
//go:noinline
func concat18(a []string) string {
	return a[0] + a[1] + a[2] + a[3] + a[4] + a[5] + a[6] + a[7] + a[8] +
		a[9] + a[10] + a[11] + a[12] + a[13] + a[14] + a[15] + a[16] + a[17]
}

// TestConcatCases checks the concatenation forms: 2, 3, 6, 17 and 40
// operands (17 and 40 are above the exact limit), strconv.Quote, +=, defined
// and generic string types, []byte(a+b) and the identity case.
func TestConcatCases(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	value := taintString(t, ctx, "q", "attack")
	x := "x"

	for _, test := range []struct {
		name string
		got  string
		want []span
	}{
		{"a+b", heapConcat2(x, value), []span{{1, 6, "q"}}},
		{"a+b+c", heapConcat3(x, value, x), []span{{1, 6, "q"}}},
		{"6 operands", heapConcat6(x, x, value, x, value, x), []span{{2, 6, "q"}, {9, 6, "q"}}},
		{"17 operands, only the last tainted", concat17(x, value), []span{{16, 6, "q"}}},
		{"40 operands, only the last tainted", concat40(x, value), []span{{39, 6, "q"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, spansOf(test.got))
		})
	}

	t.Run("quote", func(t *testing.T) {
		// This was the v1 failure of the prototype. The strconv.Quote
		// wrapper propagates coarse ranges, so check only the source.
		got := spansOf(strconv.Quote("x" + value))
		require.NotEmpty(t, got)
		require.Equal(t, "q", got[0].name)
	})
	t.Run("plus assign", func(t *testing.T) {
		got := "prefix:"
		got += value
		require.Equal(t, []span{{7, 6, "q"}}, spansOf(got))
	})
	t.Run("defined and generic", func(t *testing.T) {
		defined := definedString(value)
		got := definedString("prefix:") + defined
		require.Equal(t, []span{{7, 6, "q"}}, spansOf(string(got)))
		generic := genericConcat(definedString("pre:"), defined)
		require.Equal(t, []span{{4, 6, "q"}}, spansOf(string(generic)))
	})
	t.Run("bytes of concat", func(t *testing.T) {
		got := []byte("pre:" + value + ":post")
		require.Equal(t, []span{{4, 6, "q"}}, bytesSpansOf(got))
	})
	t.Run("identity", func(t *testing.T) {
		empty := ""
		got := empty + value
		require.Equal(t, unsafe.StringData(value), unsafe.StringData(got))
		require.Equal(t, []span{{0, 6, "q"}}, spansOf(got))
	})
}

// TestConcatTwoOwners checks concatenations with more than 16 operands of two
// owners: the ranges of each owner cover only its own bytes.
func TestConcatTwoOwners(t *testing.T) {
	requireWoven(t)
	alpha := taintString(t, begin(t), "alpha", "AA")
	bravo := taintString(t, begin(t), "bravo", "BB")

	t.Run("interleaved", func(t *testing.T) {
		parts := make([]string, 18)
		for i := range parts {
			parts[i] = alpha
			if i%2 == 1 {
				parts[i] = bravo
			}
		}
		got := concat18(parts)
		var wantA, wantB []span
		for i := range parts {
			if i%2 == 0 {
				wantA = append(wantA, span{uint32(2 * i), 2, "alpha"})
			} else {
				wantB = append(wantB, span{uint32(2 * i), 2, "bravo"})
			}
		}
		var gotA, gotB []span
		for _, s := range spansOf(got) {
			if s.name == "alpha" {
				gotA = append(gotA, s)
			} else {
				gotB = append(gotB, s)
			}
		}
		// The coarse path merges only the ranges of one owner that touch, and
		// the range limit drops the tail.
		require.Equal(t, wantA[:ranges.DefaultLimit-1], gotA[:ranges.DefaultLimit-1])
		require.Equal(t, wantB[:ranges.DefaultLimit-1], gotB[:ranges.DefaultLimit-1])
	})

	t.Run("shared operand", func(t *testing.T) {
		// Alpha taints the two ends of shared, bravo the middle.
		shared := heapConcat3(alpha, bravo, alpha)
		require.Equal(t, []span{{0, 2, "alpha"}, {4, 2, "alpha"}, {2, 2, "bravo"}}, spansOf(shared))
		parts := make([]string, 18)
		for i := range parts {
			parts[i] = "-"
		}
		parts[17] = shared
		got := concat18(parts)
		// 17 bytes of "-", then shared: alpha on [17, 19) and [21, 23),
		// bravo on [19, 21).
		const bravoStart, bravoEnd = 19, 21
		for _, s := range spansOf(got) {
			switch s.name {
			case "alpha":
				overlaps := s.start < bravoEnd && bravoStart < s.start+s.length
				require.False(t, overlaps, "a range of alpha covers the bytes of bravo: %+v", s)
			case "bravo":
				require.Equal(t, span{bravoStart, bravoEnd - bravoStart, "bravo"}, s)
			}
		}
	})
}

// TestConcatRangeLimit checks that a concatenation with more ranges than the
// range limit keeps the first ranges and records one ranges drop, on the
// exact path (<= 16 operands) and on the coarse path.
func TestConcatRangeLimit(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	source := taintString(t, ctx, "q", "ab")
	owner, id := ownerOf(t, source)
	sparse := func(value string, n int) string {
		t.Helper()
		raw := make([]ranges.Range, n)
		for i := range raw {
			raw[i] = ranges.Range{Start: uint32(2 * i), Length: 1, SourceID: id}
		}
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, raw, uint32(len(value))).Valid)
		managed := strings.Clone(value)
		_, ok := owner.AdoptString(managed, &set)
		require.True(t, ok)
		return managed
	}
	left := sparse("a.b.c.d.e.f.", 6)
	right := sparse("g.h.i.j.k.", 5)

	before := owner.Counters().Ranges
	got := heapConcat3(left, "|", right)
	require.Len(t, spansOf(got), ranges.DefaultLimit)
	require.Equal(t, before+1, owner.Counters().Ranges, "exact path")

	parts := make([]string, 18)
	for i := range parts {
		parts[i] = left
	}
	before = owner.Counters().Ranges
	got = concat18(parts)
	require.Len(t, spansOf(got), ranges.DefaultLimit)
	require.Equal(t, before+1, owner.Counters().Ranges, "coarse path")
}

// TestConcatClean checks that a clean concatenation is not tainted when the
// gate is on.
func TestConcatClean(t *testing.T) {
	requireWoven(t)
	ctx := begin(t)
	_ = taintString(t, ctx, "q", "attack")
	require.NotZero(t, runtimebridge.GateValue())
	require.Empty(t, spansOf(heapConcat2("clean-", strings.Clone("value"))))
}

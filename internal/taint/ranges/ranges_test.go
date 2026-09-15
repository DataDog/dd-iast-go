// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestCanonicalizeFirstInputProvenance(t *testing.T) {
	raw := []ranges.Range{
		{Start: 4, Length: 4, SourceID: 0},
		{Start: 2, Length: 8, SourceID: 1},
	}
	got, outcome := canonical(t, 10, raw, 10)
	require.True(t, outcome.Valid)
	require.False(t, outcome.Truncated)
	require.Equal(t, []ranges.Range{
		{Start: 2, Length: 2, SourceID: 1},
		{Start: 4, Length: 4, SourceID: 0},
		{Start: 8, Length: 2, SourceID: 1},
	}, snapshot(&got))
}

func TestCanonicalizeMultipleSplits(t *testing.T) {
	raw := []ranges.Range{
		{Start: 2, Length: 2, SourceID: 0},
		{Start: 6, Length: 2, SourceID: 1},
		{Start: 0, Length: 10, SourceID: 2},
	}
	got, outcome := canonical(t, 10, raw, 10)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Start: 0, Length: 2, SourceID: 2},
		{Start: 2, Length: 2, SourceID: 0},
		{Start: 4, Length: 2, SourceID: 2},
		{Start: 6, Length: 2, SourceID: 1},
		{Start: 8, Length: 2, SourceID: 2},
	}, snapshot(&got))
}

func TestCanonicalizeMergesOnlyEqualProvenance(t *testing.T) {
	mark, ok := ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	require.True(t, ok)
	got, outcome := canonical(t, 10, []ranges.Range{
		{Start: 0, Length: 2, SourceID: 0, Marks: mark},
		{Start: 2, Length: 2, SourceID: 0, Marks: mark},
		{Start: 4, Length: 2, SourceID: 1, Marks: mark},
		{Start: 6, Length: 2, SourceID: 1},
	}, 8)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Start: 0, Length: 4, SourceID: 0, Marks: mark},
		{Start: 4, Length: 2, SourceID: 1, Marks: mark},
		{Start: 6, Length: 2, SourceID: 1},
	}, snapshot(&got))
}

func TestCanonicalizeRejectsInvalidInput(t *testing.T) {
	valid := []ranges.Range{{Start: 0, Length: 1, SourceID: 0}}
	cases := map[string][]ranges.Range{
		"zero length":   {{Start: 0, Length: 0}},
		"overflow":      {{Start: math.MaxUint32, Length: 2}},
		"outside value": {{Start: 9, Length: 2}},
		"bit zero mark": {{Start: 0, Length: 1, Marks: 1}},
		"unknown mark":  {{Start: 0, Length: 1, Marks: uint64(1) << 63}},
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			var got ranges.Set
			outcome := ranges.Canonicalize(&got, 10, append(valid, invalid...), 10)
			require.False(t, outcome.Valid)
			require.Equal(t, 0, got.Len())
		})
	}

	var got ranges.Set
	tooMany := make([]ranges.Range, ranges.MaxCanonicalInput+1)
	outcome := ranges.Canonicalize(&got, 10, tooMany, math.MaxUint32)
	require.False(t, outcome.Valid)
	require.Equal(t, 0, got.Len())
}

func TestCanonicalizeLimits(t *testing.T) {
	for _, count := range []int{9, 10, 11, 64, 65} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			raw := separated(count)
			var got ranges.Set
			outcome := ranges.Canonicalize(&got, 10, raw, uint32(count*2))
			require.True(t, outcome.Valid)
			require.Equal(t, min(count, 10), got.Len())
			require.Equal(t, count > 10, outcome.Truncated)
			for i := 0; i < got.Len(); i++ {
				r, ok := got.At(i)
				require.True(t, ok)
				require.Equal(t, uint32(i*2), r.Start)
			}
		})
	}

	var hard ranges.Set
	outcome := ranges.Canonicalize(&hard, ranges.ClampLimit(1_000), separated(65), 130)
	require.True(t, outcome.Valid)
	require.True(t, outcome.Truncated)
	require.Equal(t, ranges.HardLimit, hard.Len())
}

func TestCanonicalizeUsesByteOffsets(t *testing.T) {
	value := []byte("a€b")
	got, outcome := canonical(t, 10, []ranges.Range{
		{Start: 1, Length: 1, SourceID: 0}, // inside the three-byte encoding
		{Start: 2, Length: 2, SourceID: 1},
	}, uint32(len(value)))
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Start: 1, Length: 1, SourceID: 0},
		{Start: 2, Length: 2, SourceID: 1},
	}, snapshot(&got))

	invalidUTF8 := []byte{0xff, 0x80, 'x'}
	got, outcome = canonical(t, 10, []ranges.Range{{Start: 1, Length: 1, SourceID: 0}}, uint32(len(invalidUTF8)))
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{{Start: 1, Length: 1, SourceID: 0}}, snapshot(&got))
}

func TestAdoptCanonical(t *testing.T) {
	input := []ranges.Range{
		{Start: 0, Length: 1, SourceID: 0},
		{Start: 2, Length: 1, SourceID: 1},
	}
	var got ranges.Set
	outcome := ranges.AdoptCanonical(&got, 10, input, 3)
	require.True(t, outcome.Valid)
	require.Equal(t, input, snapshot(&got))

	outcome = ranges.AdoptCanonical(&got, 1, input, 3)
	require.True(t, outcome.Valid)
	require.True(t, outcome.Truncated)
	require.Equal(t, input[:1], snapshot(&got))

	outcome = ranges.AdoptCanonical(&got, 10, []ranges.Range{
		{Start: 1, Length: 1},
		{Start: 0, Length: 1},
	}, 2)
	require.False(t, outcome.Valid)
	require.Zero(t, got.Len())

	outcome = ranges.AdoptCanonical(&got, 64, separated(65), 130)
	require.False(t, outcome.Valid)
	require.Zero(t, got.Len())
}

func TestClampLimit(t *testing.T) {
	require.Equal(t, ranges.Limit(1), ranges.ClampLimit(0))
	require.Equal(t, ranges.Limit(1), ranges.ClampLimit(1))
	require.Equal(t, ranges.Limit(ranges.DefaultLimit), ranges.ClampLimit(ranges.DefaultLimit))
	require.Equal(t, ranges.Limit(ranges.HardLimit), ranges.ClampLimit(ranges.HardLimit+1))

	var got ranges.Set
	outcome := ranges.Canonicalize(&got, ranges.Limit(255), []ranges.Range{{Length: 1}}, 1)
	require.True(t, outcome.Valid)
	require.Equal(t, ranges.Limit(ranges.HardLimit), got.Limit())
}

func TestSetAccessorsAndNilSafety(t *testing.T) {
	var nilSet *ranges.Set
	require.Equal(t, 0, nilSet.Len())
	require.Equal(t, ranges.Limit(ranges.DefaultLimit), nilSet.Limit())
	_, ok := nilSet.At(0)
	require.False(t, ok)
	require.Equal(t, 0, nilSet.CopyTo(make([]ranges.Range, 1)))
	require.False(t, nilSet.ValidFor(0))

	outcome := ranges.Canonicalize(nil, 10, nil, 0)
	require.False(t, outcome.Valid)
}

func TestMarkMergesNewlyEqualAdjacentRanges(t *testing.T) {
	sql, ok := ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	require.True(t, ok)
	set, outcome := canonical(t, 10, []ranges.Range{
		{Start: 0, Length: 2, SourceID: 7},
		{Start: 2, Length: 2, SourceID: 7, Marks: sql},
	}, 4)
	require.True(t, outcome.Valid)

	var marked ranges.Set
	outcome = ranges.MarkAll(&marked, &set, constants.VulnerabilityTypeSqlInjection)
	require.True(t, outcome.Valid)
	require.True(t, marked.ValidFor(4))
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 7, Marks: sql}}, snapshot(&marked))

	var propagated ranges.Set
	outcome = ranges.Concat(&propagated, 10, &marked, 4, nil, 0)
	require.True(t, outcome.Valid)
	require.Equal(t, snapshot(&marked), snapshot(&propagated))
}

func TestMarkAndUnsafeFor(t *testing.T) {
	set, _ := canonical(t, 10, []ranges.Range{
		{Start: 0, Length: 2, SourceID: 0},
		{Start: 2, Length: 2, SourceID: 1},
	}, 4)
	var marked ranges.Set
	outcome := ranges.MarkSource(&marked, &set, 0, constants.VulnerabilityTypeSqlInjection)
	require.True(t, outcome.Valid)
	require.True(t, ranges.HasMark(mustAt(t, &marked, 0).Marks, constants.VulnerabilityTypeSqlInjection))
	require.False(t, ranges.HasMark(mustAt(t, &marked, 1).Marks, constants.VulnerabilityTypeSqlInjection))

	outcome = ranges.MarkAll(&marked, &marked, constants.VulnerabilityTypeCommandInjection)
	require.True(t, outcome.Valid)
	for i := 0; i < marked.Len(); i++ {
		require.True(t, ranges.HasMark(mustAt(t, &marked, i).Marks, constants.VulnerabilityTypeCommandInjection))
	}

	var unsafe ranges.Set
	outcome = ranges.UnsafeFor(&unsafe, &marked, constants.VulnerabilityTypeSqlInjection)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{mustAt(t, &marked, 1)}, snapshot(&unsafe))
	require.True(t, ranges.HasMark(mustAt(t, &unsafe, 0).Marks, constants.VulnerabilityTypeCommandInjection), "non-target marks must survive")

	outcome = ranges.MarkAll(&marked, &set, 0)
	require.False(t, outcome.Valid)
	require.Equal(t, 0, marked.Len())
	outcome = ranges.UnsafeFor(&unsafe, &set, constants.VulnerabilityType(255))
	require.False(t, outcome.Valid)
	require.Equal(t, 0, unsafe.Len())
}

func TestCanonicalizeNoAlloc(t *testing.T) {
	raw := []ranges.Range{
		{Start: 4, Length: 4, SourceID: 0},
		{Start: 2, Length: 8, SourceID: 1},
	}
	var dst ranges.Set
	ranges.Canonicalize(&dst, 10, raw, 10) // grow the goroutine stack first
	allocs := testing.AllocsPerRun(100, func() {
		outcome := ranges.Canonicalize(&dst, 10, raw, 10)
		if !outcome.Valid {
			panic("unexpected invalid result")
		}
	})
	require.Zero(t, allocs)
}

func canonical(t *testing.T, limit ranges.Limit, raw []ranges.Range, valueLen uint32) (ranges.Set, ranges.Outcome) {
	t.Helper()
	var result ranges.Set
	outcome := ranges.Canonicalize(&result, limit, raw, valueLen)
	if outcome.Valid {
		require.True(t, result.ValidFor(valueLen))
	}
	return result, outcome
}

func snapshot(set *ranges.Set) []ranges.Range {
	result := make([]ranges.Range, set.Len())
	set.CopyTo(result)
	return result
}

func mustAt(t *testing.T, set *ranges.Set, index int) ranges.Range {
	t.Helper()
	r, ok := set.At(index)
	require.True(t, ok)
	return r
}

func separated(count int) []ranges.Range {
	result := make([]ranges.Range, count)
	for i := range result {
		result[i] = ranges.Range{Start: uint32(i * 2), Length: 1, SourceID: ranges.SourceID(i)}
	}
	return result
}

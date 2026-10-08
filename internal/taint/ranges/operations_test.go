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

func TestConcatAndSlice(t *testing.T) {
	left, _ := canonical(t, 10, []ranges.Range{{Start: 0, Length: 2, SourceID: 0, Marks: 4}}, 3)
	right, _ := canonical(t, 10, []ranges.Range{{Start: 1, Length: 2, SourceID: 1, Marks: 8}}, 4)
	var joined ranges.Set
	outcome := ranges.Concat(&joined, 10, &left, 3, &right, 4)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Start: 0, Length: 2, SourceID: 0, Marks: 4},
		{Start: 4, Length: 2, SourceID: 1, Marks: 8},
	}, snapshot(&joined))

	var sliced ranges.Set
	outcome = ranges.Slice(&sliced, 10, &joined, 7, 1, 6)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Start: 0, Length: 1, SourceID: 0, Marks: 4},
		{Start: 3, Length: 2, SourceID: 1, Marks: 8},
	}, snapshot(&sliced))

	outcome = ranges.Slice(&sliced, 10, &joined, 7, 6, 5)
	require.False(t, outcome.Valid)
	require.Zero(t, sliced.Len())
	outcome = ranges.Concat(&joined, 10, nil, math.MaxUint32, nil, 1)
	require.False(t, outcome.Valid)
	require.Zero(t, joined.Len())
}

func TestJoin(t *testing.T) {
	first, _ := canonical(t, 10, []ranges.Range{{Length: 2, SourceID: 0}}, 2)
	second, _ := canonical(t, 10, []ranges.Range{{Start: 1, Length: 1, SourceID: 1}}, 2)
	separator, _ := canonical(t, 10, []ranges.Range{{Length: 1, SourceID: 2}}, 1)
	var got ranges.Set
	outcome := ranges.Join(&got, 10, []ranges.Part{
		{Ranges: &first, Length: 2},
		{Ranges: &second, Length: 2},
	}, ranges.Part{Ranges: &separator, Length: 1})
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 0},
		{Start: 2, Length: 1, SourceID: 2},
		{Start: 4, Length: 1, SourceID: 1},
	}, snapshot(&got))

	outcome = ranges.Join(&got, 10, nil, ranges.Part{Ranges: &separator, Length: 1})
	require.True(t, outcome.Valid)
	require.Zero(t, got.Len())
}

func TestRepeatEmptyTerminatesForHugeCount(t *testing.T) {
	var got ranges.Set
	outcome := ranges.Repeat(&got, 10, nil, 0, math.MaxInt)
	require.True(t, outcome.Valid)
	require.Zero(t, got.Len())

	var empty ranges.Set
	outcome = ranges.Repeat(&got, 10, &empty, 1, math.MaxInt)
	require.True(t, outcome.Valid)
	require.Zero(t, got.Len())
}

func TestRepeatRejectsCountProductOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("requires a 64-bit int")
	}
	sourceLen := uint32(1 << 26)
	source, _ := canonical(t, 10, []ranges.Range{{Length: 1, SourceID: 0}}, sourceLen)
	var got ranges.Set
	outcome := ranges.Repeat(&got, 10, &source, sourceLen, int(uint64(1)<<38))
	require.False(t, outcome.Valid)
	require.Zero(t, got.Len())
}

func TestRepeat(t *testing.T) {
	whole, _ := canonical(t, 10, []ranges.Range{{Length: 3, SourceID: 0}}, 3)
	var got ranges.Set
	outcome := ranges.Repeat(&got, 10, &whole, 3, 1_000_000)
	require.True(t, outcome.Valid)
	require.False(t, outcome.Truncated)
	require.Equal(t, []ranges.Range{{Length: 3_000_000, SourceID: 0}}, snapshot(&got))

	partial, _ := canonical(t, 10, []ranges.Range{{Length: 1, SourceID: 1}}, 2)
	outcome = ranges.Repeat(&got, 10, &partial, 2, 11)
	require.True(t, outcome.Valid)
	require.True(t, outcome.Truncated)
	require.Equal(t, 10, got.Len())
	for i := 0; i < got.Len(); i++ {
		require.Equal(t, uint32(i*2), mustAt(t, &got, i).Start)
	}

	outcome = ranges.Repeat(&got, 10, &partial, 2, -1)
	require.False(t, outcome.Valid)
	outcome = ranges.Repeat(&got, 10, &partial, math.MaxUint32, 2)
	require.False(t, outcome.Valid)
}

func TestComposeReplacement(t *testing.T) {
	original, _ := canonical(t, 10, []ranges.Range{{Length: 6, SourceID: 0}}, 6)
	replacement, _ := canonical(t, 10, []ranges.Range{{Length: 2, SourceID: 1}}, 2)
	segments := []ranges.Segment{
		{Part: ranges.Part{Ranges: &original, Length: 6}, Low: 0, High: 2},
		{Part: ranges.Part{Ranges: &replacement, Length: 2}, Low: 0, High: 2},
		{Part: ranges.Part{Ranges: &original, Length: 6}, Low: 4, High: 6},
	}
	var got ranges.Set
	outcome := ranges.Compose(&got, 10, segments)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 0},
		{Start: 2, Length: 2, SourceID: 1},
		{Start: 4, Length: 2, SourceID: 0},
	}, snapshot(&got))
}

func TestClearWriteAppendAndCopy(t *testing.T) {
	base, _ := canonical(t, 10, []ranges.Range{{Length: 10, SourceID: 0}}, 10)
	source, _ := canonical(t, 10, []ranges.Range{{Length: 3, SourceID: 1}}, 3)
	var got ranges.Set
	outcome := ranges.Clear(&got, 10, &base, 10, 4, 5)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Length: 4, SourceID: 0},
		{Start: 5, Length: 5, SourceID: 0},
	}, snapshot(&got))

	outcome = ranges.Write(&got, 10, &base, 10, 4, &source, 3, 3)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Length: 4, SourceID: 0},
		{Start: 4, Length: 3, SourceID: 1},
		{Start: 7, Length: 3, SourceID: 0},
	}, snapshot(&got))

	outcome = ranges.Append(&got, 10, &base, 10, &source, 3)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Length: 10, SourceID: 0},
		{Start: 10, Length: 3, SourceID: 1},
	}, snapshot(&got))

	overlap, _ := canonical(t, 10, []ranges.Range{
		{Length: 2, SourceID: 0},
		{Start: 2, Length: 2, SourceID: 1},
	}, 6)
	outcome = ranges.CopyOverwrite(&overlap, 10, &overlap, 6, 1, &overlap, 6, 0, 4)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Length: 3, SourceID: 0},
		{Start: 3, Length: 2, SourceID: 1},
	}, snapshot(&overlap), "copy must read a pre-copy range snapshot")

	outcome = ranges.Clear(&overlap, 10, &overlap, 6, 2, 3)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 0},
		{Start: 3, Length: 2, SourceID: 1},
	}, snapshot(&overlap), "index assignment clears exactly one byte")
}

func TestCopyAndShift(t *testing.T) {
	set, _ := canonical(t, 10, []ranges.Range{{Start: 1, Length: 2, SourceID: 0}}, 4)
	var got ranges.Set
	outcome := ranges.Copy(&got, 10, &set, 4)
	require.True(t, outcome.Valid)
	require.Equal(t, snapshot(&set), snapshot(&got))

	outcome = ranges.Shift(&got, 10, &set, 4, 3, 7)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{{Start: 4, Length: 2, SourceID: 0}}, snapshot(&got))

	outcome = ranges.Shift(&got, 10, &set, 4, math.MaxUint32, math.MaxUint32)
	require.False(t, outcome.Valid)
	require.Zero(t, got.Len())
}

func TestExactOperationsPreserveMarks(t *testing.T) {
	sql, ok := ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	require.True(t, ok)
	command, ok := ranges.MarkBit(constants.VulnerabilityTypeCommandInjection)
	require.True(t, ok)
	set, _ := canonical(t, 10, []ranges.Range{{Length: 2, SourceID: 0, Marks: sql | command}}, 2)
	var got ranges.Set
	outcome := ranges.Concat(&got, 10, &set, 2, &set, 2)
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 0, Marks: sql | command}}, snapshot(&got))
}

func TestCoarseUsesFirstInputAndMarkIntersection(t *testing.T) {
	sql, _ := ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	command, _ := ranges.MarkBit(constants.VulnerabilityTypeCommandInjection)
	first, _ := canonical(t, 10, []ranges.Range{{Start: 5, Length: 1, SourceID: 2, Marks: sql | command}}, 6)
	second, _ := canonical(t, 10, []ranges.Range{{Length: 1, SourceID: 1, Marks: sql}}, 1)
	var got ranges.Set
	outcome := ranges.Coarse(&got, 10, 20, []ranges.Part{
		{Ranges: &first, Length: 6},
		{Ranges: &second, Length: 1},
	})
	require.True(t, outcome.Valid)
	require.Equal(t, []ranges.Range{{Length: 20, SourceID: 2, Marks: sql}}, snapshot(&got))

	outcome = ranges.Coarse(&got, 10, 0, []ranges.Part{{Ranges: &first, Length: 6}})
	require.True(t, outcome.Valid)
	require.Zero(t, got.Len())
	outcome = ranges.Coarse(&got, 10, 5, []ranges.Part{{Length: 4}})
	require.True(t, outcome.Valid)
	require.Zero(t, got.Len())
}

func TestOperationsNoAlloc(t *testing.T) {
	left, _ := canonical(t, 10, []ranges.Range{{Length: 4, SourceID: 0}}, 4)
	right, _ := canonical(t, 10, []ranges.Range{{Start: 1, Length: 2, SourceID: 1}}, 4)
	var dst ranges.Set
	ranges.Concat(&dst, 10, &left, 4, &right, 4) // grow the goroutine stack first
	allocs := testing.AllocsPerRun(100, func() {
		if !ranges.Concat(&dst, 10, &left, 4, &right, 4).Valid {
			panic("unexpected invalid concat")
		}
		if !ranges.Slice(&dst, 10, &left, 4, 0, 4).Valid {
			panic("unexpected invalid slice")
		}
		if !ranges.CopyOverwrite(&dst, 10, &left, 4, 0, &right, 4, 0, 2).Valid {
			panic("unexpected invalid copy")
		}
	})
	require.Zero(t, allocs)
}

func TestInvalidOperationInputs(t *testing.T) {
	set, _ := canonical(t, 10, []ranges.Range{{Length: 1}}, 1)
	var got ranges.Set

	require.False(t, ranges.Copy(&got, 10, &set, 0).Valid)
	require.Zero(t, got.Len())
	require.False(t, ranges.Compose(&got, 10, []ranges.Segment{{Part: ranges.Part{Ranges: &set, Length: 1}, Low: 1, High: 0}}).Valid)
	require.False(t, ranges.Compose(&got, 10, []ranges.Segment{
		{Part: ranges.Part{Length: math.MaxUint32}, High: math.MaxUint32},
		{Part: ranges.Part{Length: 1}, High: 1},
	}).Valid)
	require.False(t, ranges.Join(&got, 10, []ranges.Part{{Length: math.MaxUint32}, {Length: 1}}, ranges.Part{}).Valid)
	require.False(t, ranges.Join(&got, 10, []ranges.Part{{Ranges: &set, Length: 0}}, ranges.Part{}).Valid)
	require.False(t, ranges.Clear(&got, 10, &set, 1, 1, 0).Valid)
	require.False(t, ranges.Clear(&got, 10, &set, 1, 0, 2).Valid)
	require.False(t, ranges.Overwrite(&got, 10, &set, 1, 1, &set, 1, 0, 1).Valid)
	require.False(t, ranges.Coarse(&got, 10, 1, []ranges.Part{{Ranges: &set, Length: 0}}).Valid)
}

func TestOperationNilSafety(t *testing.T) {
	set, _ := canonical(t, 10, []ranges.Range{{Length: 1}}, 1)
	require.False(t, ranges.Concat(nil, 10, &set, 1, nil, 0).Valid)
	require.False(t, ranges.Slice(nil, 10, &set, 1, 0, 1).Valid)
	require.False(t, ranges.Join(nil, 10, nil, ranges.Part{}).Valid)
	require.False(t, ranges.Repeat(nil, 10, &set, 1, 1).Valid)
	require.False(t, ranges.Compose(nil, 10, nil).Valid)
	require.False(t, ranges.Clear(nil, 10, &set, 1, 0, 1).Valid)
	require.False(t, ranges.CopyOverwrite(nil, 10, &set, 1, 0, &set, 1, 0, 1).Valid)
	require.False(t, ranges.Coarse(nil, 10, 1, nil).Valid)
}

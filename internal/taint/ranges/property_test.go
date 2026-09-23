// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges_test

import (
	"math/rand/v2"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestCanonicalizeAgainstByteOracle(t *testing.T) {
	random := rand.New(rand.NewPCG(0x1A57, 0x600D))
	for iteration := 0; iteration < 10_000; iteration++ {
		valueLen := uint32(random.IntN(64) + 1)
		count := random.IntN(24)
		raw := make([]ranges.Range, count)
		for i := range raw {
			start := uint32(random.IntN(int(valueLen)))
			length := uint32(random.IntN(int(valueLen-start)) + 1)
			raw[i] = ranges.Range{
				Start:    start,
				Length:   length,
				SourceID: ranges.SourceID(random.IntN(8)),
				Marks:    uint64(1) << uint(random.IntN(8)+1),
			}
		}
		limit := ranges.Limit(random.IntN(ranges.HardLimit) + 1)
		var got ranges.Set
		outcome := ranges.Canonicalize(&got, limit, raw, valueLen)
		require.True(t, outcome.Valid, "iteration %d", iteration)
		expected, truncated := canonicalOracle(raw, valueLen, int(limit))
		require.Equal(t, expected, snapshot(&got), "iteration %d raw=%v", iteration, raw)
		require.Equal(t, truncated, outcome.Truncated, "iteration %d", iteration)
		require.True(t, got.ValidFor(valueLen), "iteration %d", iteration)
	}
}

func TestCanonicalizeOracleBeyondHardLimit(t *testing.T) {
	raw := separated(80)
	var got ranges.Set
	outcome := ranges.Canonicalize(&got, 64, raw, 160)
	require.True(t, outcome.Valid)
	expected, truncated := canonicalOracle(raw, 160, 64)
	require.Equal(t, expected, snapshot(&got))
	require.True(t, truncated)
	require.Equal(t, truncated, outcome.Truncated)
}

func TestCompositeOperationsAgainstByteOracle(t *testing.T) {
	random := rand.New(rand.NewPCG(0x51CE, 0xC0FFEE))
	for iteration := 0; iteration < 5_000; iteration++ {
		leftCells := randomCells(random, random.IntN(24)+1)
		rightCells := randomCells(random, random.IntN(24)+1)
		left := setFromCells(t, leftCells)
		right := setFromCells(t, rightCells)
		limit := random.IntN(10) + 1

		var got ranges.Set
		outcome := ranges.Concat(&got, ranges.Limit(limit), &left, uint32(len(leftCells)), &right, uint32(len(rightCells)))
		assertCells(t, iteration, &got, outcome, append(append([]oracleCell(nil), leftCells...), rightCells...), limit)

		low := random.IntN(len(leftCells) + 1)
		high := random.IntN(len(leftCells) + 1)
		if low > high {
			low, high = high, low
		}
		outcome = ranges.Slice(&got, ranges.Limit(limit), &left, uint32(len(leftCells)), uint32(low), uint32(high))
		assertCells(t, iteration, &got, outcome, append([]oracleCell(nil), leftCells[low:high]...), limit)

		clearLow := random.IntN(len(leftCells) + 1)
		clearHigh := random.IntN(len(leftCells) + 1)
		if clearLow > clearHigh {
			clearLow, clearHigh = clearHigh, clearLow
		}
		cleared := append([]oracleCell(nil), leftCells...)
		clear(cleared[clearLow:clearHigh])
		outcome = ranges.Clear(&got, ranges.Limit(limit), &left, uint32(len(leftCells)), uint32(clearLow), uint32(clearHigh))
		assertCells(t, iteration, &got, outcome, cleared, limit)

		n := random.IntN(min(len(leftCells), len(rightCells)) + 1)
		destination := random.IntN(len(leftCells) - n + 1)
		sourceOffset := random.IntN(len(rightCells) - n + 1)
		overwritten := append([]oracleCell(nil), leftCells...)
		copy(overwritten[destination:destination+n], append([]oracleCell(nil), rightCells[sourceOffset:sourceOffset+n]...))
		outcome = ranges.CopyOverwrite(&got, ranges.Limit(limit), &left, uint32(len(leftCells)), uint32(destination), &right, uint32(len(rightCells)), uint32(sourceOffset), uint32(n))
		assertCells(t, iteration, &got, outcome, overwritten, limit)

		count := random.IntN(6)
		repeated := make([]oracleCell, 0, len(leftCells)*count)
		for range count {
			repeated = append(repeated, leftCells...)
		}
		outcome = ranges.Repeat(&got, ranges.Limit(limit), &left, uint32(len(leftCells)), count)
		assertCells(t, iteration, &got, outcome, repeated, limit)

		separatorCells := randomCells(random, random.IntN(4)+1)
		separator := setFromCells(t, separatorCells)
		joined := append([]oracleCell(nil), leftCells...)
		joined = append(joined, separatorCells...)
		joined = append(joined, rightCells...)
		outcome = ranges.Join(&got, ranges.Limit(limit), []ranges.Part{
			{Ranges: &left, Length: uint32(len(leftCells))},
			{Ranges: &right, Length: uint32(len(rightCells))},
		}, ranges.Part{Ranges: &separator, Length: uint32(len(separatorCells))})
		assertCells(t, iteration, &got, outcome, joined, limit)
	}
}

func TestOperationIdentities(t *testing.T) {
	random := rand.New(rand.NewPCG(0xC0DE, 0xCAFE))
	for iteration := 0; iteration < 1_000; iteration++ {
		valueLen := uint32(random.IntN(64) + 1)
		raw := make([]ranges.Range, random.IntN(10)+1)
		for i := range raw {
			start := uint32(random.IntN(int(valueLen)))
			raw[i] = ranges.Range{Start: start, Length: uint32(random.IntN(int(valueLen-start)) + 1), SourceID: ranges.SourceID(i)}
		}
		set, outcome := canonical(t, 64, raw, valueLen)
		require.True(t, outcome.Valid)

		var got ranges.Set
		outcome = ranges.Slice(&got, 64, &set, valueLen, 0, valueLen)
		require.True(t, outcome.Valid)
		require.Equal(t, snapshot(&set), snapshot(&got))

		outcome = ranges.Concat(&got, 64, &set, valueLen, nil, 0)
		require.True(t, outcome.Valid)
		require.Equal(t, snapshot(&set), snapshot(&got))

		outcome = ranges.Repeat(&got, 64, &set, valueLen, 1)
		require.True(t, outcome.Valid)
		require.Equal(t, snapshot(&set), snapshot(&got))
	}
}

type oracleCell struct {
	set      bool
	sourceID ranges.SourceID
	marks    uint64
}

func randomCells(random *rand.Rand, length int) []oracleCell {
	cells := make([]oracleCell, length)
	for i := range cells {
		if random.IntN(4) == 0 {
			continue
		}
		cells[i] = oracleCell{
			set:      true,
			sourceID: ranges.SourceID(random.IntN(5)),
			marks:    uint64(1) << uint(random.IntN(8)+1),
		}
	}
	return cells
}

func setFromCells(t *testing.T, cells []oracleCell) ranges.Set {
	t.Helper()
	raw, _ := rangesFromCells(cells, ranges.HardLimit)
	var set ranges.Set
	outcome := ranges.AdoptCanonical(&set, 64, raw, uint32(len(cells)))
	require.True(t, outcome.Valid)
	return set
}

func assertCells(t *testing.T, iteration int, got *ranges.Set, outcome ranges.Outcome, cells []oracleCell, limit int) {
	t.Helper()
	expected, truncated := rangesFromCells(cells, limit)
	require.True(t, outcome.Valid, "iteration %d", iteration)
	require.Equal(t, expected, snapshot(got), "iteration %d", iteration)
	require.Equal(t, truncated, outcome.Truncated, "iteration %d", iteration)
	require.True(t, got.ValidFor(uint32(len(cells))), "iteration %d", iteration)
}

func rangesFromCells(cells []oracleCell, limit int) ([]ranges.Range, bool) {
	result := make([]ranges.Range, 0, len(cells))
	for position := 0; position < len(cells); {
		cell := cells[position]
		if !cell.set {
			position++
			continue
		}
		end := position + 1
		for end < len(cells) && cells[end] == cell {
			end++
		}
		result = append(result, ranges.Range{Start: uint32(position), Length: uint32(end - position), SourceID: cell.sourceID, Marks: cell.marks})
		position = end
	}
	if len(result) > limit {
		return result[:limit], true
	}
	return result, false
}

func canonicalOracle(raw []ranges.Range, valueLen uint32, limit int) ([]ranges.Range, bool) {
	cells := make([]oracleCell, valueLen)
	for _, r := range raw {
		end := r.Start + r.Length
		for position := r.Start; position < end; position++ {
			if !cells[position].set {
				cells[position] = oracleCell{set: true, sourceID: r.SourceID, marks: r.Marks}
			}
		}
	}
	return rangesFromCells(cells, limit)
}

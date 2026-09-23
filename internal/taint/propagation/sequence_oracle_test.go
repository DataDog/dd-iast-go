// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"slices"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

type sequenceCell struct {
	tainted bool
	source  ranges.SourceID
	marks   uint64
}

type sequenceValue struct {
	kind      sequenceKind
	text      string
	data      []byte
	cells     [sequenceOwnerCount][]sequenceCell
	operation string
}

func (v sequenceValue) length() int {
	if v.kind == sequenceString {
		return len(v.text)
	}
	return len(v.data)
}

func (v sequenceValue) valueBytes() []byte {
	if v.kind == sequenceString {
		return []byte(v.text)
	}
	return v.data
}

func (v *sequenceValue) normalizeFresh() {
	for ownerIndex := range v.cells {
		if v.length() < 2 {
			clear(v.cells[ownerIndex])
		}
		v.cells[ownerIndex] = normalizeSequenceCells(v.cells[ownerIndex])
	}
}

func (v *sequenceValue) normalizeAlias() {
	for ownerIndex := range v.cells {
		if v.length() == 0 {
			clear(v.cells[ownerIndex])
		}
		v.cells[ownerIndex] = normalizeSequenceCells(v.cells[ownerIndex])
	}
}

func normalizeSequenceCells(input []sequenceCell) []sequenceCell {
	cells := append([]sequenceCell(nil), input...)
	rangeCount := 0
	for position := 0; position < len(cells); {
		if !cells[position].tainted {
			position++
			continue
		}
		cell := cells[position]
		end := position + 1
		for end < len(cells) && cells[end] == cell {
			end++
		}
		if rangeCount >= int(ranges.DefaultLimit) {
			for index := position; index < len(cells); index++ {
				cells[index] = sequenceCell{}
			}
			break
		}
		rangeCount++
		position = end
	}
	return cells
}

func copySequenceOwnerCells(input [sequenceOwnerCount][]sequenceCell) [sequenceOwnerCount][]sequenceCell {
	var result [sequenceOwnerCount][]sequenceCell
	for ownerIndex := range result {
		result[ownerIndex] = append([]sequenceCell(nil), input[ownerIndex]...)
	}
	return result
}

func repeatSequenceCells(input []sequenceCell, count int) []sequenceCell {
	result := make([]sequenceCell, 0, len(input)*count)
	for range count {
		result = append(result, input...)
	}
	return result
}

func concatSequenceCells(parts ...[]sequenceCell) []sequenceCell {
	var length int
	for _, part := range parts {
		length += len(part)
	}
	result := make([]sequenceCell, 0, length)
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

func sequenceRanges(cells []sequenceCell) []ranges.Range {
	result := make([]ranges.Range, 0, ranges.DefaultLimit)
	for position := 0; position < len(cells); {
		cell := cells[position]
		if !cell.tainted {
			position++
			continue
		}
		end := position + 1
		for end < len(cells) && cells[end] == cell {
			end++
		}
		result = append(result, ranges.Range{
			Start:    uint32(position),
			Length:   uint32(end - position),
			SourceID: cell.source,
			Marks:    cell.marks,
		})
		position = end
	}
	return result
}

func assertSequenceValue(
	tb testing.TB,
	taintStore *store.Store,
	owners [sequenceOwnerCount]*store.Owner,
	value sequenceValue,
	stage string,
) {
	tb.Helper()
	if value.length() > sequenceMaxOutput {
		tb.Fatalf("%s exceeds output bound: length=%d", stage, value.length())
	}
	if len(value.cells[0]) != value.length() || len(value.cells[1]) != value.length() {
		tb.Fatalf("%s oracle length mismatch: value=%d owner0=%d owner1=%d", stage, value.length(), len(value.cells[0]), len(value.cells[1]))
	}

	var key store.Key
	var valid bool
	if value.kind == sequenceString {
		key, valid = store.StringKey(value.text)
	} else {
		key, valid = store.BytesKey(value.data)
	}
	if !valid {
		for ownerIndex := range owners {
			if len(sequenceRanges(value.cells[ownerIndex])) != 0 {
				tb.Fatalf("%s has attributed bytes without a valid store key", stage)
			}
		}
		return
	}

	var snapshot store.Snapshot
	if !taintStore.Lookup(key, &snapshot) {
		tb.Fatalf("%s lookup unexpectedly contended", stage)
	}
	seen := [sequenceOwnerCount]bool{}
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, ok := snapshot.At(entryIndex)
		if !ok {
			tb.Fatalf("%s snapshot entry %d is unavailable", stage, entryIndex)
		}
		if entry.Ranges.Len() == 0 {
			continue
		}
		ownerIndex := sequenceOwnerIndex(owners, entry)
		if ownerIndex < 0 {
			tb.Fatalf("%s contains unexpected owner index=%d generation=%d id=%d", stage, entry.OwnerIndex, entry.OwnerGen, entry.OwnerID)
		}
		if seen[ownerIndex] {
			tb.Fatalf("%s contains duplicate contribution for owner %d", stage, ownerIndex)
		}
		seen[ownerIndex] = true
		expected := sequenceRanges(value.cells[ownerIndex])
		actual := make([]ranges.Range, entry.Ranges.Len())
		entry.Ranges.CopyTo(actual)
		if !slices.Equal(expected, actual) {
			tb.Fatalf("%s owner %d ranges differ:\nexpected=%v\nactual=%v", stage, ownerIndex, expected, actual)
		}
		actualCells := sequenceCellsFromRanges(tb, value.length(), actual)
		if !slices.Equal(value.cells[ownerIndex], actualCells) {
			tb.Fatalf("%s owner %d byte attribution differs", stage, ownerIndex)
		}
	}
	for ownerIndex := range owners {
		expected := sequenceRanges(value.cells[ownerIndex])
		if len(expected) != 0 && !seen[ownerIndex] {
			tb.Fatalf("%s is missing owner %d contribution: %v", stage, ownerIndex, expected)
		}
	}
}

func sequenceOwnerIndex(owners [sequenceOwnerCount]*store.Owner, entry *store.Entry) int {
	for ownerIndex, owner := range owners {
		index, ok := owner.Index()
		if ok && entry.OwnerIndex == index && entry.OwnerGen == owner.Generation() && entry.OwnerID == owner.ID() {
			return ownerIndex
		}
	}
	return -1
}

func sequenceCellsFromRanges(tb testing.TB, length int, values []ranges.Range) []sequenceCell {
	tb.Helper()
	cells := make([]sequenceCell, length)
	for _, value := range values {
		end := uint64(value.Start) + uint64(value.Length)
		if value.Length == 0 || end > uint64(length) {
			tb.Fatalf("range is outside value bounds: range=%v length=%d", value, length)
		}
		for position := value.Start; position < uint32(end); position++ {
			if cells[position].tainted {
				tb.Fatalf("overlapping ranges at byte %d: %v", position, values)
			}
			cells[position] = sequenceCell{tainted: true, source: value.SourceID, marks: value.Marks}
		}
	}
	return cells
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

const (
	sequenceOwnerCount = 2
	sequenceMaxInput   = 256
	sequenceMaxOutput  = 4 << 10
	sequenceMaxMatches = 32
	sequenceSteps      = 8
	sequenceOperationN = 6
)

type sequenceKind uint8

const (
	sequenceString sequenceKind = iota
	sequenceBytes
)

type sequenceCursor struct {
	data  []byte
	index int
}

func newSequenceCursor(data []byte) *sequenceCursor {
	if len(data) > sequenceMaxInput {
		data = data[:sequenceMaxInput]
	}
	if len(data) == 0 {
		data = []byte{0xc3, 0xa9, 0xff, 'a', 'b', 'a', 0x80, 'z'}
	}
	return &sequenceCursor{data: data}
}

func (c *sequenceCursor) next() byte {
	value := c.data[c.index%len(c.data)]
	c.index++
	return value
}

func (c *sequenceCursor) indexOf(length int) int {
	if length <= 0 {
		return 0
	}
	return int(c.next()) % length
}

func runEngineSequence(tb testing.TB, taintStore *store.Store, encoded []byte) [sequenceOperationN]int {
	tb.Helper()
	cursor := newSequenceCursor(encoded)
	owners := [sequenceOwnerCount]*store.Owner{taintStore.Acquire(), taintStore.Acquire()}
	for index, owner := range owners {
		if owner.Disabled() {
			tb.Fatalf("owner %d admission unexpectedly failed", index)
		}
	}
	defer owners[1].Finish()
	defer owners[0].Finish()

	values := sequenceInitialValues(tb, owners, cursor)
	for index := range values {
		assertSequenceValue(tb, taintStore, owners, values[index], "initial value")
	}

	var coverage [sequenceOperationN]int
	for step := 0; step < sequenceSteps; step++ {
		var operation int
		var result sequenceValue
		operation, result = applySequenceOperation(tb, cursor, values)
		coverage[operation]++
		values = append(values, result)
		assertSequenceValue(
			tb,
			taintStore,
			owners,
			result,
			fmt.Sprintf("operation step %d type %d %s", step, operation, result.operation),
		)
	}
	return coverage
}

func sequenceInitialValues(tb testing.TB, owners [sequenceOwnerCount]*store.Owner, cursor *sequenceCursor) []sequenceValue {
	tb.Helper()
	length := 4 + cursor.indexOf(29)
	special := make([]byte, length)
	for index := range special {
		special[index] = cursor.next()
	}
	special[0], special[1], special[2] = 0xc3, 0xa9, 0xff
	repeated := bytes.Clone(special)

	byteValue := make([]byte, 4+cursor.indexOf(29))
	for index := range byteValue {
		byteValue[index] = cursor.next()
	}
	byteValue[0], byteValue[1], byteValue[2] = 0xe2, 0x82, 0xff

	ascii := make([]byte, 4+cursor.indexOf(29))
	for index := range ascii {
		ascii[index] = "abcaXYZ0"[cursor.indexOf(len("abcaXYZ0"))]
	}

	raw := [][]byte{special, repeated, byteValue, ascii}
	kinds := []sequenceKind{sequenceString, sequenceString, sequenceBytes, sequenceBytes}
	values := make([]sequenceValue, 0, len(raw))
	for valueIndex := range raw {
		var cells [sequenceOwnerCount][]sequenceCell
		for ownerIndex := range cells {
			cells[ownerIndex] = make([]sequenceCell, len(raw[valueIndex]))
			for position := range cells[ownerIndex] {
				selector := cursor.next() + byte(valueIndex*17+ownerIndex*31+position)
				if selector%4 == 0 {
					continue
				}
				cells[ownerIndex][position] = sequenceCell{
					tainted: true,
					source:  ranges.SourceID((int(selector) + valueIndex + ownerIndex) % 8),
					marks:   []uint64{0xe, 0xc, 0xa, 0x6, 0x2}[int(selector)%5],
				}
			}
			cells[ownerIndex] = normalizeSequenceCells(cells[ownerIndex])
		}
		values = append(values, adoptSequenceValue(tb, owners, kinds[valueIndex], raw[valueIndex], cells))
	}
	return values
}

func adoptSequenceValue(
	tb testing.TB,
	owners [sequenceOwnerCount]*store.Owner,
	kind sequenceKind,
	raw []byte,
	cells [sequenceOwnerCount][]sequenceCell,
) sequenceValue {
	tb.Helper()
	value := sequenceValue{kind: kind, cells: cells}
	span := uint32(len(raw))
	if kind == sequenceString {
		value.text = strings.Clone(string(raw))
	} else {
		value.data = bytes.Clone(raw)
		span = uint32(cap(value.data))
	}
	for ownerIndex, owner := range owners {
		expected := sequenceRanges(cells[ownerIndex])
		if len(expected) == 0 {
			continue
		}
		var set ranges.Set
		if !ranges.AdoptCanonical(&set, ranges.DefaultLimit, expected, span).Valid {
			tb.Fatalf("owner %d initial oracle ranges are invalid: %v", ownerIndex, expected)
		}
		var ok bool
		if kind == sequenceString {
			_, ok = owner.AdoptString(value.text, &set)
		} else {
			_, ok = owner.AdoptBytes(value.data, &set)
		}
		if !ok {
			tb.Fatalf("owner %d initial value admission failed", ownerIndex)
		}
	}
	return value
}

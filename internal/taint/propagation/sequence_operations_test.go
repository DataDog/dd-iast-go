// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

func applySequenceOperation(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) (int, sequenceValue) {
	tb.Helper()
	operation := cursor.indexOf(sequenceOperationN)
	switch operation {
	case 0:
		return operation, sequenceCopy(tb, values[cursor.indexOf(len(values))])
	case 1:
		return operation, sequenceWindow(tb, cursor, values[cursor.indexOf(len(values))])
	case 2:
		return operation, sequenceRepeat(tb, cursor, values[cursor.indexOf(len(values))])
	case 3:
		return sequenceJoin(tb, cursor, values)
	case 4:
		return sequenceReplace(tb, cursor, values)
	default:
		return operation, sequenceConvert(tb, cursor, values)
	}
}

func sequenceCopy(tb testing.TB, input sequenceValue) sequenceValue {
	tb.Helper()
	result := sequenceValue{kind: input.kind}
	result.cells = copySequenceOwnerCells(input.cells)
	if input.kind == sequenceString {
		native := strings.Clone(input.text)
		result.text = propagation.CopyString(input.text, native)
		if result.text != native {
			tb.Fatalf("CopyString changed native value: got %q want %q", result.text, native)
		}
	} else {
		native := bytes.Clone(input.data)
		result.data = propagation.CopyBytes(input.data, native)
		if !bytes.Equal(result.data, native) {
			tb.Fatalf("CopyBytes changed native value: got %x want %x", result.data, native)
		}
	}
	result.normalizeFresh()
	return result
}

func sequenceWindow(tb testing.TB, cursor *sequenceCursor, input sequenceValue) sequenceValue {
	tb.Helper()
	if input.length() == 0 {
		return sequenceCopy(tb, input)
	}
	low := cursor.indexOf(input.length() + 1)
	high := cursor.indexOf(input.length() + 1)
	if low > high {
		low, high = high, low
	}
	result := sequenceValue{kind: input.kind}
	for ownerIndex := range result.cells {
		result.cells[ownerIndex] = append([]sequenceCell(nil), input.cells[ownerIndex][low:high]...)
	}
	if input.kind == sequenceString {
		result.text = input.text[low:high]
		propagation.StringWindow(input.text, result.text)
	} else {
		result.data = input.data[low:high]
		propagation.ByteWindow(input.data, result.data)
	}
	result.normalizeAlias()
	return result
}

func sequenceRepeat(tb testing.TB, cursor *sequenceCursor, input sequenceValue) sequenceValue {
	tb.Helper()
	count := cursor.indexOf(4)
	if input.length()*count > sequenceMaxOutput {
		count = 1
	}
	result := sequenceValue{kind: input.kind}
	for ownerIndex := range result.cells {
		result.cells[ownerIndex] = repeatSequenceCells(input.cells[ownerIndex], count)
	}
	if input.kind == sequenceString {
		native := strings.Repeat(input.text, count)
		result.text = propagation.RepeatString(input.text, native, count)
		if result.text != native {
			tb.Fatalf("RepeatString changed native value: got %q want %q", result.text, native)
		}
		if count == 1 {
			result.normalizeAlias()
		} else {
			result.normalizeFresh()
		}
	} else {
		native := bytes.Repeat(input.data, count)
		result.data = propagation.RepeatBytes(input.data, native, count)
		if !bytes.Equal(result.data, native) {
			tb.Fatalf("RepeatBytes changed native value: got %x want %x", result.data, native)
		}
		result.normalizeFresh()
	}
	return result
}

func sequenceJoin(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) (int, sequenceValue) {
	tb.Helper()
	firstIndex := cursor.indexOf(len(values))
	first := values[firstIndex]
	second := values[pickSequenceKind(cursor, values, first.kind)]
	separator := values[pickSequenceKind(cursor, values, first.kind)]
	if first.length()+second.length()+separator.length() > sequenceMaxOutput {
		return 0, sequenceCopy(tb, first)
	}
	result := sequenceValue{kind: first.kind}
	for ownerIndex := range result.cells {
		result.cells[ownerIndex] = concatSequenceCells(
			first.cells[ownerIndex],
			separator.cells[ownerIndex],
			second.cells[ownerIndex],
		)
	}
	if first.kind == sequenceString {
		elements := []string{first.text, second.text}
		native := strings.Join(elements, separator.text)
		result.text = propagation.JoinString(elements, separator.text, native)
		if result.text != native {
			tb.Fatalf("JoinString changed native value: got %q want %q", result.text, native)
		}
	} else {
		elements := [][]byte{first.data, second.data}
		native := bytes.Join(elements, separator.data)
		result.data = propagation.JoinBytes(elements, separator.data, native)
		if !bytes.Equal(result.data, native) {
			tb.Fatalf("JoinBytes changed native value: got %x want %x", result.data, native)
		}
	}
	result.normalizeFresh()
	return 3, result
}

func sequenceConvert(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) sequenceValue {
	tb.Helper()
	input := values[pickSequenceKind(cursor, values, sequenceBytes)]
	if len(input.data) < 2 {
		return sequenceCopy(tb, input)
	}
	native := string(input.data)
	result := sequenceValue{kind: sequenceString, cells: copySequenceOwnerCells(input.cells)}
	result.text = propagation.BytesToString(input.data, native)
	if result.text != native {
		tb.Fatalf("BytesToString changed native value: got %q want %q", result.text, native)
	}
	result.normalizeFresh()
	return result
}

func pickSequenceKind(cursor *sequenceCursor, values []sequenceValue, kind sequenceKind) int {
	var candidates [sequenceSteps + 4]int
	count := 0
	for index := range values {
		if values[index].kind == kind {
			candidates[count] = index
			count++
		}
	}
	return candidates[cursor.indexOf(count)]
}

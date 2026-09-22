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
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

func sequenceReplace(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) (int, sequenceValue) {
	tb.Helper()
	input := values[cursor.indexOf(len(values))]
	if input.length() == 0 {
		return 0, sequenceCopy(tb, input)
	}
	replacement := values[pickSequenceKind(cursor, values, input.kind)]
	oldIndex := cursor.indexOf(input.length())
	old := input.valueBytes()[oldIndex : oldIndex+1]
	counts := [...]int{1, 2, 3, -1}
	count := counts[cursor.indexOf(len(counts))]
	matches := bytes.Count(input.valueBytes(), old)
	if count < 0 && matches > sequenceMaxMatches {
		count = 3
	}
	if count >= 0 {
		matches = min(matches, count)
	}
	outputLength := input.length() + matches*(replacement.length()-len(old))
	if outputLength < 0 || outputLength > sequenceMaxOutput {
		return 0, sequenceCopy(tb, input)
	}

	result := sequenceValue{kind: input.kind}
	var expected []byte
	expected, result.cells = replaceSequenceCells(input, old, replacement, count)
	result.operation = fmt.Sprintf(
		"replace kind=%d input=%x old=%x replacement=%x count=%d",
		input.kind,
		input.valueBytes(),
		old,
		replacement.valueBytes(),
		count,
	)
	aliasResult := false
	if input.kind == sequenceString {
		native := strings.Replace(input.text, string(old), replacement.text, count)
		if !bytes.Equal(expected, []byte(native)) {
			tb.Fatalf("string replacement oracle value differs: got %x want %x", expected, []byte(native))
		}
		nativePointer := uintptr(unsafe.Pointer(unsafe.StringData(native)))
		inputPointer := uintptr(unsafe.Pointer(unsafe.StringData(input.text)))
		aliasResult = len(native) != 0 &&
			nativePointer >= inputPointer &&
			nativePointer+uintptr(len(native)) <= inputPointer+uintptr(len(input.text))
		if aliasResult {
			result.cells = copySequenceOwnerCells(input.cells)
		}
		result.text = propagation.ReplaceString(input.text, string(old), replacement.text, native, count)
		if result.text != native {
			tb.Fatalf("ReplaceString changed native value: got %q want %q", result.text, native)
		}
	} else {
		native := bytes.Replace(input.data, old, replacement.data, count)
		if !bytes.Equal(expected, native) {
			tb.Fatalf("byte replacement oracle value differs: got %x want %x", expected, native)
		}
		result.data = propagation.ReplaceBytes(input.data, old, replacement.data, native, count)
		if !bytes.Equal(result.data, native) {
			tb.Fatalf("ReplaceBytes changed native value: got %x want %x", result.data, native)
		}
	}
	if aliasResult {
		result.normalizeAlias()
	} else {
		result.normalizeFresh()
	}
	return 4, result
}

func replaceSequenceCells(
	input sequenceValue,
	old []byte,
	replacement sequenceValue,
	count int,
) ([]byte, [sequenceOwnerCount][]sequenceCell) {
	var output []byte
	var cells [sequenceOwnerCount][]sequenceCell
	inputBytes := input.valueBytes()
	remaining := count
	last := 0
	for remaining != 0 {
		relative := bytes.Index(inputBytes[last:], old)
		if relative < 0 {
			break
		}
		position := last + relative
		output = append(output, inputBytes[last:position]...)
		output = append(output, replacement.valueBytes()...)
		for ownerIndex := range cells {
			cells[ownerIndex] = append(cells[ownerIndex], input.cells[ownerIndex][last:position]...)
			cells[ownerIndex] = append(cells[ownerIndex], replacement.cells[ownerIndex]...)
		}
		last = position + len(old)
		if remaining > 0 {
			remaining--
		}
	}
	output = append(output, inputBytes[last:]...)
	for ownerIndex := range cells {
		cells[ownerIndex] = append(cells[ownerIndex], input.cells[ownerIndex][last:]...)
	}
	return output, cells
}

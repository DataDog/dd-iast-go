// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"bytes"

	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

// BytesClone wraps bytes.Clone.
func BytesClone(value []byte) []byte {
	result := bytes.Clone(value)
	return internal.CopyBytes(value, result)
}

// BytesJoin wraps bytes.Join.
func BytesJoin(elements [][]byte, separator []byte) []byte {
	result := bytes.Join(elements, separator)
	return internal.JoinBytes(elements, separator, result)
}

// BytesRepeat wraps bytes.Repeat.
func BytesRepeat(value []byte, count int) []byte {
	result := bytes.Repeat(value, count)
	return internal.RepeatBytes(value, result, count)
}

// BytesCut wraps bytes.Cut.
func BytesCut(value, separator []byte) (before, after []byte, found bool) {
	before, after, found = bytes.Cut(value, separator)
	internal.ByteWindow(value, before)
	internal.ByteWindow(value, after)
	return before, after, found
}

// BytesCutPrefix wraps bytes.CutPrefix.
func BytesCutPrefix(value, prefix []byte) (after []byte, found bool) {
	after, found = bytes.CutPrefix(value, prefix)
	internal.ByteWindow(value, after)
	return after, found
}

// BytesCutSuffix wraps bytes.CutSuffix.
func BytesCutSuffix(value, suffix []byte) (before []byte, found bool) {
	before, found = bytes.CutSuffix(value, suffix)
	internal.ByteWindow(value, before)
	return before, found
}

// BytesSplit wraps bytes.Split.
func BytesSplit(value, separator []byte) [][]byte {
	result := bytes.Split(value, separator)
	internal.ByteWindows(value, result)
	return result
}

// BytesSplitN wraps bytes.SplitN.
func BytesSplitN(value, separator []byte, count int) [][]byte {
	result := bytes.SplitN(value, separator, count)
	internal.ByteWindows(value, result)
	return result
}

// BytesSplitAfter wraps bytes.SplitAfter.
func BytesSplitAfter(value, separator []byte) [][]byte {
	result := bytes.SplitAfter(value, separator)
	internal.ByteWindows(value, result)
	return result
}

// BytesSplitAfterN wraps bytes.SplitAfterN.
func BytesSplitAfterN(value, separator []byte, count int) [][]byte {
	result := bytes.SplitAfterN(value, separator, count)
	internal.ByteWindows(value, result)
	return result
}

// BytesFields wraps bytes.Fields.
func BytesFields(value []byte) [][]byte {
	result := bytes.Fields(value)
	internal.ByteWindows(value, result)
	return result
}

// BytesFieldsFunc wraps bytes.FieldsFunc.
func BytesFieldsFunc(value []byte, predicate func(rune) bool) [][]byte {
	result := bytes.FieldsFunc(value, predicate)
	internal.ByteWindows(value, result)
	return result
}

// BytesTrim wraps bytes.Trim.
func BytesTrim(value []byte, cutset string) []byte {
	result := bytes.Trim(value, cutset)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimSpace wraps bytes.TrimSpace.
func BytesTrimSpace(value []byte) []byte {
	result := bytes.TrimSpace(value)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimLeft wraps bytes.TrimLeft.
func BytesTrimLeft(value []byte, cutset string) []byte {
	result := bytes.TrimLeft(value, cutset)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimRight wraps bytes.TrimRight.
func BytesTrimRight(value []byte, cutset string) []byte {
	result := bytes.TrimRight(value, cutset)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimPrefix wraps bytes.TrimPrefix.
func BytesTrimPrefix(value, prefix []byte) []byte {
	result := bytes.TrimPrefix(value, prefix)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimSuffix wraps bytes.TrimSuffix.
func BytesTrimSuffix(value, suffix []byte) []byte {
	result := bytes.TrimSuffix(value, suffix)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimFunc wraps bytes.TrimFunc.
func BytesTrimFunc(value []byte, predicate func(rune) bool) []byte {
	result := bytes.TrimFunc(value, predicate)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimLeftFunc wraps bytes.TrimLeftFunc.
func BytesTrimLeftFunc(value []byte, predicate func(rune) bool) []byte {
	result := bytes.TrimLeftFunc(value, predicate)
	internal.ByteWindow(value, result)
	return result
}

// BytesTrimRightFunc wraps bytes.TrimRightFunc.
func BytesTrimRightFunc(value []byte, predicate func(rune) bool) []byte {
	result := bytes.TrimRightFunc(value, predicate)
	internal.ByteWindow(value, result)
	return result
}

// BytesReplace wraps bytes.Replace.
func BytesReplace(value, old, replacement []byte, count int) []byte {
	result := bytes.Replace(value, old, replacement, count)
	return internal.ReplaceBytes(value, old, replacement, result, count)
}

// BytesReplaceAll wraps bytes.ReplaceAll.
func BytesReplaceAll(value, old, replacement []byte) []byte {
	result := bytes.ReplaceAll(value, old, replacement)
	return internal.ReplaceBytes(value, old, replacement, result, -1)
}

// BytesToLower wraps bytes.ToLower.
func BytesToLower(value []byte) []byte {
	return internal.CaseBytes(value, bytes.ToLower(value))
}

// BytesToUpper wraps bytes.ToUpper.
func BytesToUpper(value []byte) []byte {
	return internal.CaseBytes(value, bytes.ToUpper(value))
}

// BytesToTitle wraps bytes.ToTitle.
func BytesToTitle(value []byte) []byte {
	return internal.CaseBytes(value, bytes.ToTitle(value))
}

// BytesMap wraps bytes.Map.
func BytesMap(mapping func(rune) rune, value []byte) []byte {
	return internal.CoarseBytes(bytes.Map(mapping, value), value)
}

// BytesToValidUTF8 wraps bytes.ToValidUTF8.
func BytesToValidUTF8(value, replacement []byte) []byte {
	return internal.ValidUTF8Bytes(value, replacement, bytes.ToValidUTF8(value, replacement))
}

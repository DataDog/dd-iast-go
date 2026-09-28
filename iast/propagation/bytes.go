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

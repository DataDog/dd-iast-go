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
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestPathOneBytePropagationResultsAreRejected(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "ab", []ranges.Range{{Length: 2, SourceID: 1}})
	window := managed[:1]
	propagation.StringWindow(managed, window)
	require.Equal(t, []ranges.Range{{Length: 1, SourceID: 1}}, lookupRanges(s, window))
	charged := owner.Charged()

	fresh := strings.Clone(window)
	require.True(t, unsafe.StringData(fresh) != unsafe.StringData(window))
	copied := propagation.CopyString(window, fresh)
	require.True(t, unsafe.StringData(copied) == unsafe.StringData(fresh))
	require.Nil(t, lookupRanges(s, copied))

	joinedNative := strings.Join([]string{window, ""}, "")
	require.Len(t, joinedNative, 1)
	require.True(t, unsafe.StringData(joinedNative) != unsafe.StringData(window))
	joined := propagation.JoinString([]string{window, ""}, "", joinedNative)
	require.Equal(t, joinedNative, joined)
	require.Nil(t, lookupRanges(s, joined))

	replacedNative := strings.Replace(managed, "b", "", -1)
	require.Len(t, replacedNative, 1)
	require.True(t, unsafe.StringData(replacedNative) != unsafe.StringData(managed))
	replaced := propagation.ReplaceString(managed, "b", "", replacedNative, -1)
	require.Equal(t, replacedNative, replaced)
	require.Nil(t, lookupRanges(s, replaced))

	kelvin, _ := taintString(t, owner, "\u212a", []ranges.Range{{Length: 3, SourceID: 2}})
	lowerNative := strings.ToLower(kelvin)
	require.Equal(t, "k", lowerNative)
	require.True(t, unsafe.StringData(lowerNative) != unsafe.StringData(kelvin))
	lower := propagation.CaseString(kelvin, lowerNative)
	require.Equal(t, lowerNative, lower)
	require.Nil(t, lookupRanges(s, lower))

	require.Equal(t, charged+8, owner.Charged(), "only the Kelvin-sign root adds a size-class charge")
}

func TestPathStringAliasContractsPreserveRoots(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "ALREADY-UPPER", []ranges.Range{{Start: 2, Length: 5, SourceID: 3, Marks: 0xa}})
	charged := owner.Charged()

	caseNative := strings.ToUpper(managed)
	require.True(t, unsafe.StringData(caseNative) == unsafe.StringData(managed))
	cased := propagation.CaseString(managed, caseNative)
	require.True(t, unsafe.StringData(cased) == unsafe.StringData(managed))
	require.Equal(t, []ranges.Range{{Start: 2, Length: 5, SourceID: 3, Marks: 0xa}}, lookupRanges(s, cased))
	require.Equal(t, charged, owner.Charged())

	replaceNative := strings.Replace(managed, "missing", "value", -1)
	require.True(t, unsafe.StringData(replaceNative) == unsafe.StringData(managed))
	replaced := propagation.ReplaceString(managed, "missing", "value", replaceNative, -1)
	require.True(t, unsafe.StringData(replaced) == unsafe.StringData(managed))
	require.Equal(t, []ranges.Range{{Start: 2, Length: 5, SourceID: 3, Marks: 0xa}}, lookupRanges(s, replaced))
	require.Equal(t, charged, owner.Charged())
}

func TestPathRepeatBytesCountOneAliasInternalContract(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintBytes(t, owner, []byte("alias"), []ranges.Range{{Start: 1, Length: 3, SourceID: 4, Marks: 0x6}})
	charged := owner.Charged()
	data := unsafe.SliceData(managed)

	// This directly pins RepeatBytes' documented engine-only alias contract.
	// Go 1.26.6 bytes.Repeat allocates even for count one, so this is not native
	// bytes.Repeat evidence.
	result := propagation.RepeatBytes(managed, managed, 1)

	require.True(t, unsafe.SliceData(result) == data)
	require.Equal(t, []ranges.Range{{Start: 1, Length: 3, SourceID: 4, Marks: 0x6}}, lookupByteRanges(s, result))
	require.Equal(t, charged, owner.Charged(), "deriving the alias must not add a root charge")
}

func TestPathReplaceStringEmptyPatternBeyondExactBudget(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintString(t, owner, strings.Repeat("a", maxTestReplaceMatches+1), []ranges.Range{{
		Length:   maxTestReplaceMatches + 1,
		SourceID: 5,
		Marks:    0xc,
	}})
	native := strings.ReplaceAll(input, "", "__")
	result := propagation.ReplaceString(input, "", "__", native, -1)

	require.Equal(t, native, result)
	require.Equal(t, []ranges.Range{{Length: uint32(len(result)), SourceID: 5, Marks: 0xc}}, lookupRanges(s, result))
}

func TestPathSparseWindowListsStopAtInputBound(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		s, _ := beginScope(t)
		owner := acquireOwner(t, s)
		input, _ := taintString(t, owner, strings.Repeat("x", 48), []ranges.Range{{Length: 48, SourceID: 6}})
		outputs := make([]string, 40)
		for index := range outputs {
			if index%2 == 0 {
				outputs[index] = input[index : index+1]
			}
		}
		charged := owner.Charged()

		propagation.StringWindows(input, outputs)

		require.Equal(t, []ranges.Range{{Length: 1, SourceID: 6}}, lookupRanges(s, outputs[30]))
		require.Nil(t, lookupRanges(s, outputs[32]), "the first output beyond the inspected index bound must not publish")
		require.Equal(t, int32(17), owner.Values(), "one root plus sixteen sparse windows")
		require.Equal(t, charged, owner.Charged(), "windows retain the existing root without a new charge")
	})

	t.Run("bytes", func(t *testing.T) {
		s, _ := beginScope(t)
		owner := acquireOwner(t, s)
		input, _ := taintBytes(t, owner, bytes.Repeat([]byte{'x'}, 48), []ranges.Range{{Length: 48, SourceID: 7}})
		outputs := make([][]byte, 40)
		for index := range outputs {
			if index%2 == 0 {
				outputs[index] = input[index : index+1]
			}
		}
		charged := owner.Charged()

		propagation.ByteWindows(input, outputs)

		require.Equal(t, []ranges.Range{{Length: 1, SourceID: 7}}, lookupByteRanges(s, outputs[30]))
		require.Nil(t, lookupByteRanges(s, outputs[32]), "the first output beyond the inspected index bound must not publish")
		require.Equal(t, int32(17), owner.Values(), "one root plus sixteen sparse windows")
		require.Equal(t, charged, owner.Charged(), "windows retain the existing root without a new charge")
	})
}

func TestPathCleanDerivedWindowsDoNotPublish(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)

	stringRoot, stringRef := taintString(t, owner, "xx-clean", []ranges.Range{{Length: 2, SourceID: 8, Marks: 0xe}})
	cleanString := stringRoot[3:]
	stringKey, ok := store.StringKey(cleanString)
	require.True(t, ok)
	require.True(t, owner.Derive(stringKey, stringRef))
	require.NotNil(t, lookupRanges(s, cleanString))
	require.Empty(t, lookupRanges(s, cleanString))

	byteRoot, byteRef := taintBytes(t, owner, []byte("xx-clean"), []ranges.Range{{Length: 2, SourceID: 9, Marks: 0xe}})
	cleanBytes := byteRoot[3:]
	byteKey, ok := store.BytesKey(cleanBytes)
	require.True(t, ok)
	require.True(t, owner.Derive(byteKey, byteRef))
	require.NotNil(t, lookupByteRanges(s, cleanBytes))
	require.Empty(t, lookupByteRanges(s, cleanBytes))
	charged := owner.Charged()

	joinedStringNative := strings.Join([]string{cleanString, "suffix"}, "-")
	joinedString := propagation.JoinString([]string{cleanString, "suffix"}, "-", joinedStringNative)
	require.Equal(t, joinedStringNative, joinedString)
	require.Nil(t, lookupRanges(s, joinedString))

	replacedStringNative := strings.ReplaceAll(cleanString, "e", "E")
	replacedString := propagation.ReplaceString(cleanString, "e", "E", replacedStringNative, -1)
	require.Equal(t, replacedStringNative, replacedString)
	require.Nil(t, lookupRanges(s, replacedString))

	caseStringNative := strings.ToUpper(cleanString)
	caseString := propagation.CaseString(cleanString, caseStringNative)
	require.Equal(t, caseStringNative, caseString)
	require.Nil(t, lookupRanges(s, caseString))

	coarseStringNative := strings.Join([]string{"coarse", cleanString}, ":")
	coarseString := propagation.CoarseString(coarseStringNative, cleanString)
	require.Equal(t, coarseStringNative, coarseString)
	require.Nil(t, lookupRanges(s, coarseString))

	formatNative := fmt.Sprintf("[%s]", cleanString)
	formatted := propagation.CoarseFormatString(formatNative, []any{cleanString})
	require.Equal(t, formatNative, formatted)
	require.Nil(t, lookupRanges(s, formatted))

	joinedBytesNative := bytes.Join([][]byte{cleanBytes, []byte("suffix")}, []byte("-"))
	joinedBytes := propagation.JoinBytes([][]byte{cleanBytes, []byte("suffix")}, []byte("-"), joinedBytesNative)
	require.Equal(t, joinedBytesNative, joinedBytes)
	require.Nil(t, lookupByteRanges(s, joinedBytes))

	replacedBytesNative := bytes.ReplaceAll(cleanBytes, []byte("e"), []byte("E"))
	replacedBytes := propagation.ReplaceBytes(cleanBytes, []byte("e"), []byte("E"), replacedBytesNative, -1)
	require.Equal(t, replacedBytesNative, replacedBytes)
	require.Nil(t, lookupByteRanges(s, replacedBytes))

	caseBytesNative := bytes.ToUpper(cleanBytes)
	caseBytes := propagation.CaseBytes(cleanBytes, caseBytesNative)
	require.Equal(t, caseBytesNative, caseBytes)
	require.Nil(t, lookupByteRanges(s, caseBytes))

	coarseBytesNative := []byte("coarse:clean")
	coarseBytes := propagation.CoarseBytes(coarseBytesNative, cleanBytes)
	require.True(t, unsafe.SliceData(coarseBytes) == unsafe.SliceData(coarseBytesNative))
	require.Nil(t, lookupByteRanges(s, coarseBytes))

	require.Equal(t, charged, owner.Charged(), "rangeless windows must not create output roots")
}

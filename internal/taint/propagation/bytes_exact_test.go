// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// taintBytes publishes value as a managed byte root with the given raw ranges.
// The managed slice has a capacity at least its length so adoption charges cap.
func taintBytes(t *testing.T, owner *store.Owner, value []byte, rs []ranges.Range) ([]byte, store.RootRef) {
	t.Helper()
	require.GreaterOrEqual(t, len(value), 2, "managed byte roots require len>=2")
	capacity := len(value)
	if capacity < 4 {
		capacity = 4
	}
	managed := make([]byte, len(value), capacity)
	copy(managed, value)
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, rs, uint32(cap(managed))).Valid)
	ref, ok := owner.AdoptBytes(managed, &set)
	require.True(t, ok)
	require.NotZero(t, ref.Generation)
	return managed, ref
}

func TestJoinBytesPreservesElementAndSeparatorRanges(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	left, _ := taintBytes(t, owner, []byte("left"), []ranges.Range{{Length: 4, SourceID: 0}})
	right, _ := taintBytes(t, owner, []byte("right"), []ranges.Range{{Length: 5, SourceID: 1}})
	separator, _ := taintBytes(t, owner, []byte("::"), []ranges.Range{{Length: 2, SourceID: 2}})
	elements := [][]byte{left, []byte("plain"), right}
	result := bytes.Join(elements, separator)
	resultData := unsafe.SliceData(result)
	out := propagation.JoinBytes(elements, separator, result)
	require.True(t, unsafe.SliceData(out) == resultData, "byte join result must not be replaced")
	require.Equal(t, []ranges.Range{
		{Length: 4, SourceID: 0},
		{Start: 4, Length: 2, SourceID: 2},
		{Start: 11, Length: 2, SourceID: 2},
		{Start: 13, Length: 5, SourceID: 1},
	}, lookupByteRanges(s, out))
}

func TestJoinBytesSingleElementIsAdoptedNotDerived(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintBytes(t, owner, []byte("attacker"), []ranges.Range{{Length: 8, SourceID: 0}})
	// bytes.Join with one element returns a fresh copy, not an alias.
	result := bytes.Join([][]byte{managed}, []byte(","))
	require.True(t, unsafe.SliceData(result) != unsafe.SliceData(managed), "single-element join must be a fresh copy")
	resultData := unsafe.SliceData(result)
	out := propagation.JoinBytes([][]byte{managed}, []byte(","), result)
	require.True(t, unsafe.SliceData(out) == resultData, "single-element result must be adopted as-is")
	require.Equal(t, []ranges.Range{{Length: 8, SourceID: 0}}, lookupByteRanges(s, out))
}

func TestJoinBytesCoarseFallbackBeyondSixteenElements(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintBytes(t, owner, []byte("ab"), []ranges.Range{{Length: 2, SourceID: 3}})
	elements := make([][]byte, 17)
	for i := range elements {
		elements[i] = managed
	}
	result := bytes.Join(elements, []byte(","))
	out := propagation.JoinBytes(elements, []byte(","), result)
	// Coarse provenance publishes one whole-output range per owner.
	require.Equal(t, []ranges.Range{{Length: uint32(len(out)), SourceID: 3}}, lookupByteRanges(s, out))
}

func TestJoinBytesCoarseFallbackIncludesSeparator(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	separator, _ := taintBytes(t, owner, []byte("::"), []ranges.Range{{Length: 2, SourceID: 7}})
	elements := make([][]byte, maxTestReplaceMatches)
	for index := range elements {
		elements[index] = []byte("x")
	}
	result := bytes.Join(elements, separator)
	out := propagation.JoinBytes(elements, separator, result)
	require.Equal(t, []ranges.Range{{Length: uint32(len(out)), SourceID: 7}}, lookupByteRanges(s, out))
}

func TestReplaceBytesMapsCopiedAndReplacementSegments(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintBytes(t, owner, []byte("abc-abc"), []ranges.Range{
		{Length: 3, SourceID: 0},
		{Start: 3, Length: 1, SourceID: 2},
	})
	replacement, _ := taintBytes(t, owner, []byte("XY"), []ranges.Range{{Length: 2, SourceID: 1}})
	result := bytes.ReplaceAll(input, []byte("abc"), replacement)
	resultData := unsafe.SliceData(result)
	out := propagation.ReplaceBytes(input, []byte("abc"), replacement, result, -1)
	require.True(t, unsafe.SliceData(out) == resultData, "byte replace result must not be replaced")
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 1},
		{Start: 2, Length: 1, SourceID: 2},
		{Start: 3, Length: 2, SourceID: 1},
	}, lookupByteRanges(s, out))
}

func TestReplaceBytesBoundaryThirtyTwoMatchesExactThenCoarse(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	// 32 matches stay exact; the 33rd match forces coarse provenance. The two
	// cases are distinguished by source ID: exact replacement ranges carry the
	// replacement source, while a coarse range carries the first input source.
	exactInput := []byte(strings.Repeat("a", maxTestReplaceMatches))
	exactManaged, _ := taintBytes(t, owner, exactInput, []ranges.Range{{Length: uint32(len(exactInput)), SourceID: 0}})
	exactReplacement, _ := taintBytes(t, owner, []byte("bb"), []ranges.Range{{Length: 2, SourceID: 1}})
	require.Equal(t, 2, len(exactReplacement))
	exactResult := bytes.ReplaceAll(exactManaged, []byte("a"), exactReplacement)
	out := propagation.ReplaceBytes(exactManaged, []byte("a"), exactReplacement, exactResult, -1)
	require.Equal(t, []ranges.Range{{Length: uint32(len(out)), SourceID: 1}}, lookupByteRanges(s, out), "32 matches stay exact with the replacement source")

	coarseInput := []byte(strings.Repeat("a", maxTestReplaceMatches+1))
	coarseManaged, _ := taintBytes(t, owner, coarseInput, []ranges.Range{{Length: uint32(len(coarseInput)), SourceID: 5}})
	coarseReplacement, _ := taintBytes(t, owner, []byte("bb"), []ranges.Range{{Length: 2, SourceID: 6}})
	coarseResult := bytes.ReplaceAll(coarseManaged, []byte("a"), coarseReplacement)
	coarse := propagation.ReplaceBytes(coarseManaged, []byte("a"), coarseReplacement, coarseResult, -1)
	require.Equal(t, []ranges.Range{{Length: uint32(len(coarse)), SourceID: 5}}, lookupByteRanges(s, coarse), "33 matches use coarse input source")
	_ = exactReplacement
}

func TestReplaceBytesEmptyOldUnicodeAndInvalidUTF8(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	// "éx" is 3 bytes: é=2 bytes, x=1 byte. Empty old inserts the replacement
	// before every rune and at the end, matching bytes.Replace exactly.
	input, _ := taintBytes(t, owner, []byte("éx"), []ranges.Range{{Length: 3, SourceID: 0}})
	replacement, _ := taintBytes(t, owner, []byte("__"), []ranges.Range{{Length: 2, SourceID: 1}})
	result := bytes.ReplaceAll(input, []byte(""), replacement)
	out := propagation.ReplaceBytes(input, []byte(""), replacement, result, -1)
	require.Equal(t, []byte("__é__x__"), out)
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 1},
		{Start: 2, Length: 2, SourceID: 0},
		{Start: 4, Length: 2, SourceID: 1},
		{Start: 6, Length: 1, SourceID: 0},
		{Start: 7, Length: 2, SourceID: 1},
	}, lookupByteRanges(s, out))

	// Invalid UTF-8: a lone 0xFF byte is treated as a single-byte rune, exactly
	// like bytes.Replace and utf8.DecodeRune.
	bad := []byte{0xFF, byte('x')}
	badManaged, _ := taintBytes(t, owner, bad, []ranges.Range{{Length: 2, SourceID: 2}})
	badReplacement, _ := taintBytes(t, owner, []byte("++"), []ranges.Range{{Length: 2, SourceID: 3}})
	badResult := bytes.ReplaceAll(badManaged, []byte(""), badReplacement)
	badOut := propagation.ReplaceBytes(badManaged, []byte(""), badReplacement, badResult, -1)
	require.Equal(t, []byte("++\xff++x++"), badOut)
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 3},
		{Start: 2, Length: 1, SourceID: 2},
		{Start: 3, Length: 2, SourceID: 3},
		{Start: 5, Length: 1, SourceID: 2},
		{Start: 6, Length: 2, SourceID: 3},
	}, lookupByteRanges(s, badOut))
}

func TestReplaceBytesPreservesPartialRanges(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintBytes(t, owner, []byte("0123456789"),
		[]ranges.Range{{Start: 0, Length: 3, SourceID: 0}, {Start: 5, Length: 2, SourceID: 1}})
	// Replace the middle "345" with "XY": byte 5 is part of the match and is
	// removed, so only byte 6 of the second range survives at output offset 5.
	result := bytes.Replace(input, []byte("345"), []byte("XY"), 1)
	out := propagation.ReplaceBytes(input, []byte("345"), []byte("XY"), result, 1)
	require.Equal(t, []ranges.Range{
		{Start: 0, Length: 3, SourceID: 0},
		{Start: 5, Length: 1, SourceID: 1},
	}, lookupByteRanges(s, out))
}

func TestJoinBytesTwoOwnersKeepLocalSourceIDs(t *testing.T) {
	enableIAST(t)
	_, scopeA, createdA := request.Begin(context.Background())
	require.True(t, createdA)
	_, scopeB, createdB := request.Begin(context.Background())
	require.True(t, createdB)
	t.Cleanup(func() { scopeA.Finish() })
	t.Cleanup(func() { scopeB.Finish() })

	analysisA, ok := scopeA.Analysis()
	require.True(t, ok)
	analysisB, ok := scopeB.Analysis()
	require.True(t, ok)

	managedA, ok := analysisA.TaintBytes(constants.OriginHttpRequestParameter, "a", []byte("attacker"))
	require.True(t, ok)
	managedB, ok := analysisB.TaintBytes(constants.OriginHttpRequestParameter, "b", []byte("victim"))
	require.True(t, ok)

	s := request.ActiveStore()
	require.NotNil(t, s)

	elements := [][]byte{managedA, []byte("-"), managedB}
	result := bytes.Join(elements, []byte("+"))
	out := propagation.JoinBytes(elements, []byte("+"), result)

	key, _ := store.BytesKey(out)
	require.Equal(t, 2, lookupEntryCount(s, key), "two owners must each publish")
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	seen := map[uint8]ranges.SourceID{}
	for i := 0; i < snapshot.Len(); i++ {
		entry, _ := snapshot.At(i)
		r, _ := entry.Ranges.At(0)
		seen[entry.OwnerIndex] = r.SourceID
	}
	require.Len(t, seen, 2)
	for _, id := range seen {
		require.Equal(t, ranges.SourceID(0), id, "source IDs are owner-local")
	}
}

func TestValidUTF8BytesUsesOnlyContributingReplacement(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	replacement, _ := taintBytes(t, owner, []byte("??"), []ranges.Range{{Length: 2, SourceID: 1}})

	validInput := []byte("valid")
	validResult := bytes.ToValidUTF8(validInput, replacement)
	propagation.ValidUTF8Bytes(validInput, replacement, validResult)
	require.Nil(t, lookupByteRanges(s, validResult), "unused replacement must not taint valid input")

	invalidInput, _ := taintBytes(t, owner, []byte{'a', 0xff, 0xfe, 'b'}, []ranges.Range{
		{Length: 1, SourceID: 0},
		{Start: 3, Length: 1, SourceID: 2},
	})
	invalidResult := bytes.ToValidUTF8(invalidInput, replacement)
	out := propagation.ValidUTF8Bytes(invalidInput, replacement, invalidResult)
	require.Equal(t, []byte("a??b"), out)
	require.Equal(t, []ranges.Range{
		{Length: 1, SourceID: 0},
		{Start: 1, Length: 2, SourceID: 1},
		{Start: 3, Length: 1, SourceID: 2},
	}, lookupByteRanges(s, out))
}

func TestCaseBytesExactASCIIAndCoarseUnicode(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	ascii, _ := taintBytes(t, owner, []byte("aBcD"), []ranges.Range{{Start: 1, Length: 2, SourceID: 0}})
	asciiResult := bytes.ToUpper(ascii)
	asciiData := unsafe.SliceData(asciiResult)
	asciiOut := propagation.CaseBytes(ascii, asciiResult)
	require.True(t, unsafe.SliceData(asciiOut) == asciiData, "case bytes must not replace the result")
	require.Equal(t, []ranges.Range{{Start: 1, Length: 2, SourceID: 0}}, lookupByteRanges(s, asciiOut))

	unicodeInput, _ := taintBytes(t, owner, []byte("aé"), []ranges.Range{{Start: 1, Length: 2, SourceID: 1}})
	unicodeResult := bytes.ToUpper(unicodeInput)
	unicodeOut := propagation.CaseBytes(unicodeInput, unicodeResult)
	require.Equal(t, []ranges.Range{{Length: uint32(len(unicodeOut)), SourceID: 1}}, lookupByteRanges(s, unicodeOut))
}

func TestCaseBytesDerivesAliasWithoutReplacement(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintBytes(t, owner, []byte("attacker"), []ranges.Range{{Length: 8, SourceID: 0}})
	// Simulate a no-op case transform that returns the input itself.
	alias := managed
	aliasData := unsafe.SliceData(alias)
	charged := s.ProcessCharged()
	out := propagation.CaseBytes(managed, alias)
	require.True(t, unsafe.SliceData(out) == aliasData, "alias result must not be replaced")
	require.Equal(t, charged, s.ProcessCharged(), "deriving an alias must not charge a new root")
	require.Equal(t, []ranges.Range{{Length: 8, SourceID: 0}}, lookupByteRanges(s, alias))
}

func TestByteExactOpsRejectOversizedAndInteriorAliasResults(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintBytes(t, owner, []byte("attacker"), []ranges.Range{{Length: 8, SourceID: 0}})
	replacement, _ := taintBytes(t, owner, []byte("XY"), []ranges.Range{{Length: 2, SourceID: 1}})

	// An oversized-length result is never adopted.
	oversized := bytes.Repeat([]byte("x"), store.MaxRootBytes+1)
	joinOut := propagation.JoinBytes([][]byte{managed}, []byte(","), oversized)
	require.True(t, unsafe.SliceData(joinOut) == unsafe.SliceData(oversized))
	require.Nil(t, lookupByteRanges(s, oversized))

	replaceOut := propagation.ReplaceBytes(managed, []byte("a"), replacement, oversized, -1)
	require.True(t, unsafe.SliceData(replaceOut) == unsafe.SliceData(oversized))

	// An interior window of a large parent retains the parent capacity, which
	// exceeds the root byte limit, so it must not be adopted or charged.
	parent := make([]byte, 1<<20)
	interior := parent[:8]
	require.Equal(t, 1<<20, cap(interior), "interior must retain the large parent capacity")
	interiorData := unsafe.SliceData(interior)
	charged := s.ProcessCharged()
	caseOut := propagation.CaseBytes(managed, interior)
	require.True(t, unsafe.SliceData(caseOut) == interiorData)
	require.Equal(t, charged, s.ProcessCharged(), "oversized-cap interior alias must not be charged")
	require.Nil(t, lookupByteRanges(s, interior))

	// A result whose visible capacity exceeds the limit is rejected by replace too.
	bigCap := make([]byte, 8, store.MaxRootBytes+1)
	copy(bigCap, managed)
	bigCapData := unsafe.SliceData(bigCap)
	replaceBig := propagation.ReplaceBytes(managed, []byte("a"), replacement, bigCap, 1)
	require.True(t, unsafe.SliceData(replaceBig) == bigCapData)
	require.Nil(t, lookupByteRanges(s, bigCap))
}

func TestByteExactOpsNoActiveAndUntaintedAreAllocationFree(t *testing.T) {
	// No active store: every byte operation is a zero-allocation no-op.
	if request.ActiveStore() != nil {
		t.Fatalf("request.ActiveStore() = non-nil, another test leaked an analysis")
	}
	elements := [][]byte{[]byte("alpha"), []byte("beta")}
	joined := bytes.Join(elements, []byte(","))
	replaced := bytes.ReplaceAll(joined, []byte("alpha"), []byte("delta"))
	cased := bytes.ToUpper(joined)

	require.Zero(t, testing.AllocsPerRun(100, func() {
		if out := propagation.JoinBytes(elements, []byte(","), joined); !equalBytes(out, joined) {
			panic("JoinBytes changed result")
		}
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		if out := propagation.ReplaceBytes(joined, []byte("alpha"), []byte("delta"), replaced, -1); !equalBytes(out, replaced) {
			panic("ReplaceBytes changed result")
		}
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		if out := propagation.CaseBytes(joined, cased); !equalBytes(out, cased) {
			panic("CaseBytes changed result")
		}
	}))

	// Active store but untainted inputs: still zero allocations.
	s, _ := beginScope(t)
	untainted := []byte("not-in-store")
	untaintedJoined := bytes.Join([][]byte{untainted}, []byte(","))
	untaintedReplaced := bytes.ReplaceAll(untainted, []byte("x"), []byte("y"))
	untaintedCased := bytes.ToUpper(untainted)
	require.Zero(t, testing.AllocsPerRun(100, func() {
		propagation.JoinBytes([][]byte{untainted}, []byte(","), untaintedJoined)
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		propagation.ReplaceBytes(untainted, []byte("x"), []byte("y"), untaintedReplaced, -1)
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		propagation.CaseBytes(untainted, untaintedCased)
	}))
	require.Nil(t, lookupByteRanges(s, untaintedJoined))
}

func TestByteExactOpsFinishRaceIsSafe(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintBytes(t, owner, []byte("attacker-value"), []ranges.Range{{Length: 14, SourceID: 0}})
	separator, _ := taintBytes(t, owner, []byte("||"), []ranges.Range{{Length: 2, SourceID: 1}})
	replacement, _ := taintBytes(t, owner, []byte("ZZ"), []ranges.Range{{Length: 2, SourceID: 2}})

	joined := bytes.Join([][]byte{managed, managed}, separator)
	replaced := bytes.ReplaceAll(managed, []byte("a"), replacement)
	cased := bytes.ToUpper(managed)

	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for i := 0; i < 200; i++ {
				propagation.JoinBytes([][]byte{managed, managed}, separator, joined)
				propagation.ReplaceBytes(managed, []byte("aa"), replacement, replaced, -1)
				propagation.CaseBytes(managed, cased)
			}
		}()
	}
	close(start)
	finished := make(chan struct{})
	go func() {
		owner.Finish()
		close(finished)
	}()
	wait.Wait()
	<-finished
	require.Zero(t, s.ProcessValues())
}

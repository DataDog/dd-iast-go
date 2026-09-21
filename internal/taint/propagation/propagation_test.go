// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// enableIAST turns on full sampling for the duration of the test. The global
// configuration is restored on cleanup so shuffled execution stays isolated.
func enableIAST(t *testing.T) {
	t.Helper()
	prevEnabled := config.Enabled
	prevSampling := config.RequestSamplingPct
	prevMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled = prevEnabled
		config.RequestSamplingPct = prevSampling
		config.MaxConcurrentRequests = prevMax
	})
}

// beginScope activates the global manager and returns its store. The scope is
// finished on cleanup, so request.ActiveStore returns nil again afterwards.
func beginScope(t *testing.T) (*store.Store, *request.Scope) {
	t.Helper()
	enableIAST(t)
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(func() { scope.Finish() })
	s := request.ActiveStore()
	require.NotNil(t, s)
	return s, scope
}

// acquireOwner returns a fresh raw store owner and finishes it on cleanup.
func acquireOwner(t *testing.T, s *store.Store) *store.Owner {
	t.Helper()
	owner := s.Acquire()
	require.False(t, owner.Disabled())
	t.Cleanup(func() { owner.Finish() })
	return owner
}

// taintString publishes value as a managed root with the given raw ranges.
func taintString(t *testing.T, owner *store.Owner, value string, rs []ranges.Range) (string, store.RootRef) {
	t.Helper()
	clone := strings.Clone(value)
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, rs, uint32(len(clone))).Valid)
	ref, ok := owner.AdoptString(clone, &set)
	require.True(t, ok)
	return clone, ref
}

// lookupRanges returns the ranges of the first live entry for value, or nil.
func lookupRanges(s *store.Store, value string) []ranges.Range {
	key, ok := store.StringKey(value)
	if !ok {
		return nil
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return nil
	}
	entry, _ := snapshot.At(0)
	out := make([]ranges.Range, entry.Ranges.Len())
	entry.Ranges.CopyTo(out)
	return out
}

func TestPropagationTelemetry(t *testing.T) {
	telemetry.ExecutedPropagation.Store(0)
	telemetry.CoarsenedPropagation.Store(0)
	telemetry.DroppedPropagation.Store(0)
	t.Cleanup(func() {
		telemetry.ExecutedPropagation.Store(0)
		telemetry.CoarsenedPropagation.Store(0)
		telemetry.DroppedPropagation.Store(0)
	})

	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintString(t, owner, "attacker-value", []ranges.Range{{Start: 0, Length: 8, SourceID: 1}})

	result := propagation.CoarseString("prefix:"+input, input)
	require.NotEmpty(t, lookupRanges(s, result))
	outputs := make([]string, 33)
	for index := range outputs {
		outputs[index] = input[:2]
	}
	propagation.StringWindows(input, outputs)

	require.Equal(t, uint64(2), telemetry.ExecutedPropagation.Load())
	require.Equal(t, uint64(1), telemetry.CoarsenedPropagation.Load())
	require.Equal(t, uint64(1), telemetry.DroppedPropagation.Load())
}

func lookupByteRanges(s *store.Store, value []byte) []ranges.Range {
	key, ok := store.BytesKey(value)
	if !ok {
		return nil
	}
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) || snapshot.Len() == 0 {
		return nil
	}
	entry, _ := snapshot.At(0)
	out := make([]ranges.Range, entry.Ranges.Len())
	entry.Ranges.CopyTo(out)
	return out
}

func lookupEntryCount(s *store.Store, key store.Key) int {
	var snapshot store.Snapshot
	if !s.Lookup(key, &snapshot) {
		return 0
	}
	return snapshot.Len()
}

func TestConfiguredSourceRangeLimit(t *testing.T) {
	const replacements = 32
	inputValue := strings.Repeat("a-", replacements) + "a"
	wantAll := make([]ranges.Range, 0, 2*replacements+1)
	for index := 0; index <= replacements; index++ {
		wantAll = append(wantAll, ranges.Range{Start: uint32(3 * index), Length: 1, SourceID: 0})
		if index < replacements {
			wantAll = append(wantAll, ranges.Range{Start: uint32(3*index + 1), Length: 2, SourceID: 1})
		}
	}

	for _, limit := range []uint64{1, ranges.DefaultLimit, ranges.HardLimit} {
		limit := limit
		t.Run(fmt.Sprintf("limit_%d", limit), func(t *testing.T) {
			previous := config.MaxRangeCount
			config.MaxRangeCount = limit
			t.Cleanup(func() { config.MaxRangeCount = previous })
			want := wantAll[:min(int(limit), len(wantAll))]

			t.Run("string", func(t *testing.T) {
				s, scope := beginScope(t)
				analysis, ok := scope.Analysis()
				require.True(t, ok)
				input, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "input", inputValue)
				require.True(t, ok)
				replacement, ok := analysis.TaintString(constants.OriginHttpRequestHeader, "replacement", "bb")
				require.True(t, ok)

				inputSource, ok := analysis.Source(0)
				require.True(t, ok)
				require.Equal(t, constants.OriginHttpRequestParameter, inputSource.Origin)
				require.Equal(t, "input", inputSource.Name)
				require.Equal(t, inputValue, inputSource.Value)
				replacementSource, ok := analysis.Source(1)
				require.True(t, ok)
				require.Equal(t, constants.OriginHttpRequestHeader, replacementSource.Origin)
				require.Equal(t, "replacement", replacementSource.Name)
				require.Equal(t, "bb", replacementSource.Value)

				result := strings.ReplaceAll(input, "-", replacement)
				out := propagation.ReplaceString(input, "-", replacement, result, -1)
				require.Equal(t, want, lookupRanges(s, out))
				copied := propagation.CopyString(out, strings.Clone(out))
				require.Equal(t, want, lookupRanges(s, copied), "exact derived root must retain the source limit")
				coarse := propagation.CoarseString("coarse-string", copied)
				require.Equal(t, []ranges.Range{{Length: uint32(len(coarse)), SourceID: 0}}, lookupRanges(s, coarse))
			})

			t.Run("bytes", func(t *testing.T) {
				s, scope := beginScope(t)
				analysis, ok := scope.Analysis()
				require.True(t, ok)
				input, ok := analysis.TaintBytes(constants.OriginHttpRequestParameter, "input", []byte(inputValue))
				require.True(t, ok)
				replacement, ok := analysis.TaintBytes(constants.OriginHttpRequestHeader, "replacement", []byte("bb"))
				require.True(t, ok)

				inputSource, ok := analysis.Source(0)
				require.True(t, ok)
				require.Equal(t, constants.OriginHttpRequestParameter, inputSource.Origin)
				require.Equal(t, "input", inputSource.Name)
				require.Equal(t, inputValue, inputSource.Value)
				replacementSource, ok := analysis.Source(1)
				require.True(t, ok)
				require.Equal(t, constants.OriginHttpRequestHeader, replacementSource.Origin)
				require.Equal(t, "replacement", replacementSource.Name)
				require.Equal(t, "bb", replacementSource.Value)

				result := bytes.ReplaceAll(input, []byte("-"), replacement)
				out := propagation.ReplaceBytes(input, []byte("-"), replacement, result, -1)
				require.Equal(t, want, lookupByteRanges(s, out))
				copiedResult := append([]byte(nil), out...)
				copied := propagation.CopyBytes(out, copiedResult)
				require.Equal(t, want, lookupByteRanges(s, copied), "exact derived root must retain the source limit")
				coarseResult := []byte("coarse-bytes")
				coarse := propagation.CoarseBytes(coarseResult, copied)
				require.Equal(t, []ranges.Range{{Length: uint32(len(coarse)), SourceID: 0}}, lookupByteRanges(s, coarse))
			})
		})
	}
}

func TestNoActiveStoreIsNoOpAndAllocationFree(t *testing.T) {
	// No scope is active at the start of this test, so the fast gate is nil.
	if request.ActiveStore() != nil {
		t.Fatalf("request.ActiveStore() = non-nil, another test leaked an analysis")
	}
	input := "attacker-input"
	result := strings.Clone(input)
	allocs := testing.AllocsPerRun(100, func() {
		if got := propagation.CopyString(input, result); got != result {
			panic("CopyString changed result")
		}
	})
	require.Zero(t, allocs)

	bytesInput := []byte(input)
	bytesResult := make([]byte, len(bytesInput))
	copy(bytesResult, bytesInput)
	allocs = testing.AllocsPerRun(100, func() {
		if got := propagation.CopyBytes(bytesInput, bytesResult); !equalBytes(got, bytesResult) {
			panic("CopyBytes changed result")
		}
	})
	require.Zero(t, allocs)

	allocs = testing.AllocsPerRun(100, func() {
		propagation.StringWindows(input, []string{input[:3], input[3:]})
	})
	require.Zero(t, allocs)

	allocs = testing.AllocsPerRun(100, func() {
		propagation.CoarseString(result, input)
	})
	require.Zero(t, allocs)
}

func TestUntaintedPathIsAllocationFree(t *testing.T) {
	s, _ := beginScope(t)
	untainted := "not-in-store"
	result := strings.Clone(untainted)
	allocs := testing.AllocsPerRun(100, func() {
		if got := propagation.CopyString(untainted, result); got != result {
			panic("CopyString changed result")
		}
	})
	require.Zero(t, allocs)

	windows := []string{untainted[:2], untainted[2:]}
	allocs = testing.AllocsPerRun(100, func() {
		propagation.StringWindows(untainted, windows)
	})
	require.Zero(t, allocs)
	require.Nil(t, lookupRanges(s, untainted[:2]))
}

func TestCopyStringDerivesAliasAndClonesNonAlias(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "attacker-input", []ranges.Range{{Length: 14, SourceID: 0}})

	// Alias path: an equal-length alias stays on the managed root.
	alias := managed
	allocs := testing.AllocsPerRun(100, func() {
		propagation.CopyString(managed, alias)
	})
	require.Zero(t, allocs)
	require.Equal(t, []ranges.Range{{Length: 14, SourceID: 0}}, lookupRanges(s, alias))

	// Non-alias path: a fresh copy is cloned once and adopted.
	fresh := strings.Clone(managed)
	out := propagation.CopyString(managed, fresh)
	require.True(t, unsafe.StringData(out) != unsafe.StringData(fresh), "result must be a managed clone")
	allocs = testing.AllocsPerRun(100, func() {
		out = propagation.CopyString(managed, fresh)
	})
	require.Equal(t, 1.0, allocs, "non-alias tainted path clones once")
	require.Equal(t, []ranges.Range{{Length: 14, SourceID: 0}}, lookupRanges(s, out))
}

func TestCopyStringRejectsLengthChangesAndOversizedResults(t *testing.T) {
	_, _ = beginScope(t)
	owner := acquireOwner(t, request.ActiveStore())
	managed, _ := taintString(t, owner, "attacker-input", []ranges.Range{{Length: 14, SourceID: 0}})

	for _, result := range []string{"short", strings.Repeat("x", store.MaxRootBytes+1)} {
		allocs := testing.AllocsPerRun(100, func() {
			if got := propagation.CopyString(managed, result); got != result {
				panic("CopyString changed rejected result")
			}
		})
		require.Zero(t, allocs)
	}
	oversized := strings.Repeat("x", store.MaxRootBytes+1)
	allocs := testing.AllocsPerRun(100, func() {
		if got := propagation.CoarseString(oversized, managed); got != oversized {
			panic("CoarseString changed oversized result")
		}
	})
	require.Zero(t, allocs)
}

func TestPropagationGuardAndRejectionPaths(t *testing.T) {
	input := "attacker-input"
	result := strings.Clone(input)
	require.Equal(t, result, propagation.AdoptStringCopy("short", result))
	require.Equal(t, result, propagation.AdoptStringCopy(input, result))
	require.Equal(t, result, propagation.CopyString(input, result))
	require.Equal(t, []byte("result"), propagation.CopyBytes([]byte("input"), []byte("result")))
	require.Equal(t, result, propagation.RepeatString(input, result, 1))
	require.Equal(t, []byte("result"), propagation.RepeatBytes([]byte("input"), []byte("result"), 1))

	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, input, []ranges.Range{{Length: uint32(len(input)), SourceID: 4}})
	managedBytes, _ := taintBytes(t, owner, []byte("bytes"), []ranges.Range{{Length: 5, SourceID: 5}})

	clean := strings.Clone("clean-value")
	require.Equal(t, clean, propagation.AdoptStringCopy("clean-value", clean))
	propagation.StringWindow(managed, "")
	require.Nil(t, lookupRanges(s, ""))
	nonAliasWindow := strings.Clone(managed[:4])
	propagation.StringWindow(managed, nonAliasWindow)
	require.Nil(t, lookupRanges(s, nonAliasWindow))
	cleanWindow := "clean"
	propagation.StringWindow("clean-value", cleanWindow)
	require.Nil(t, lookupRanges(s, cleanWindow))
	propagation.ByteWindow(managedBytes, nil)
	require.Nil(t, lookupByteRanges(s, nil))
	nonAliasByteWindow := append([]byte(nil), managedBytes[:2]...)
	propagation.ByteWindow(managedBytes, nonAliasByteWindow)
	require.Nil(t, lookupByteRanges(s, nonAliasByteWindow))
	cleanByteWindow := []byte("cle")
	propagation.ByteWindow([]byte("clean"), cleanByteWindow)
	require.Nil(t, lookupByteRanges(s, cleanByteWindow))

	adopted := strings.Clone(managed)
	require.Equal(t, adopted, propagation.AdoptStringCopy(managed, adopted))
	require.Equal(t, []ranges.Range{{Length: uint32(len(adopted)), SourceID: 4}}, lookupRanges(s, adopted))

	nonAlias := strings.Clone(managed)
	require.Equal(t, nonAlias, propagation.RepeatString(managed, nonAlias, 1))
	require.Nil(t, lookupRanges(s, nonAlias))
	require.Empty(t, propagation.RepeatString(managed, "", 0))
	oversizedString := strings.Repeat("x", store.MaxRootBytes+1)
	oversizedStringOut := propagation.RepeatString(managed, oversizedString, 2)
	require.True(t, unsafe.StringData(oversizedStringOut) == unsafe.StringData(oversizedString))

	shortBytes := []byte{'x'}
	shortOut := propagation.RepeatBytes(managedBytes, shortBytes, 1)
	require.True(t, unsafe.SliceData(shortOut) == unsafe.SliceData(shortBytes))
	oversizedBytes := make([]byte, len(managedBytes), store.MaxRootBytes+1)
	oversizedOut := propagation.RepeatBytes(managedBytes, oversizedBytes, 1)
	require.True(t, unsafe.SliceData(oversizedOut) == unsafe.SliceData(oversizedBytes))
	invalidRepeat := append([]byte(nil), managedBytes...)
	invalidOut := propagation.RepeatBytes(managedBytes, invalidRepeat, -1)
	require.True(t, unsafe.SliceData(invalidOut) == unsafe.SliceData(invalidRepeat))
	require.Nil(t, lookupByteRanges(s, invalidRepeat))

	require.Equal(t, "x", propagation.CoarseString("x", managed))
	require.Equal(t, "result", propagation.CoarseString("result"))
	require.Equal(t, "result", propagation.CoarseString("result", "clean"))
	inputs := make([]string, 17)
	for index := range inputs {
		inputs[index] = "clean"
	}
	inputs[len(inputs)-1] = managed
	coarseResult := string([]byte("result"))
	coarseOut := propagation.CoarseString(coarseResult, inputs...)
	require.True(t, unsafe.StringData(coarseOut) == unsafe.StringData(coarseResult))

	byteResult := []byte("result")
	require.True(t, unsafe.SliceData(byteResult) == unsafe.SliceData(propagation.CoarseBytes(byteResult)))
	require.True(t, unsafe.SliceData(shortBytes) == unsafe.SliceData(propagation.CoarseBytes(shortBytes, managedBytes)))
	require.True(t, unsafe.SliceData(byteResult) == unsafe.SliceData(propagation.CoarseBytes(byteResult, []byte("clean"))))
}

func TestCopyBytesDerivesAliasAndAdoptsNonAlias(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	value := []byte("attacker-input")
	managed := make([]byte, len(value), 16)
	copy(managed, value)
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(value)), SourceID: 0}}, uint32(cap(managed))).Valid)
	ref, ok := owner.AdoptBytes(managed, &set)
	require.True(t, ok)
	require.NotZero(t, ref.Generation)

	// Alias path: an equal-length alias stays on the managed root.
	alias := managed
	aliasData := unsafe.SliceData(alias)
	allocs := testing.AllocsPerRun(100, func() {
		if got := propagation.CopyBytes(managed, alias); unsafe.SliceData(got) != aliasData {
			panic("alias result was replaced")
		}
	})
	require.Zero(t, allocs)
	require.Equal(t, []ranges.Range{{Length: uint32(len(alias)), SourceID: 0}}, lookupByteRanges(s, alias))

	// A length-changing value is outside the exact-copy contract.
	short := make([]byte, len(value)-1)
	copy(short, value)
	propagation.CopyBytes(managed, short)
	require.Nil(t, lookupByteRanges(s, short))

	// Non-alias path: a fresh copy is adopted as-is, never cloned or replaced.
	fresh := make([]byte, len(value), 24)
	copy(fresh, value)
	freshData := unsafe.SliceData(fresh)
	out := propagation.CopyBytes(managed, fresh)
	require.True(t, unsafe.SliceData(out) == freshData, "byte result must not be replaced")
	allocs = testing.AllocsPerRun(100, func() {
		out = propagation.CopyBytes(managed, fresh)
	})
	require.Zero(t, allocs, "byte adoption never allocates")
	require.Equal(t, []ranges.Range{{Length: uint32(len(fresh)), SourceID: 0}}, lookupByteRanges(s, fresh))
}

func TestStringWindowsPublishesAtMost32NonEmptyWindows(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input := strings.Repeat("0123456789", 4)
	managed, _ := taintString(t, owner, input, []ranges.Range{{Length: 40, SourceID: 0}})

	// Build 40 single-byte windows; only the first 32 non-empty ones publish.
	windows := make([]string, 40)
	for i := range windows {
		windows[i] = managed[i : i+1]
	}
	propagation.StringWindows(managed, windows)
	published := 0
	for _, w := range windows {
		if lookupRanges(s, w) != nil {
			published++
		}
	}
	require.Equal(t, 32, published, "exactly 32 windows must be published")
	// The 33rd window must remain untainted.
	require.Nil(t, lookupRanges(s, windows[32]))

	// Empty outputs remain untainted.
	propagation.StringWindows(managed, []string{"", managed[0:0]})
	require.Nil(t, lookupRanges(s, ""))
}

func TestPartialSlicedRangesPreservedAndSliced(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "0123456789",
		[]ranges.Range{{Start: 0, Length: 3, SourceID: 0}, {Start: 5, Length: 2, SourceID: 1}})

	// Exact copy preserves the partial ranges.
	fresh := strings.Clone(managed)
	out := propagation.CopyString(managed, fresh)
	require.Equal(t, []ranges.Range{{Start: 0, Length: 3, SourceID: 0}, {Start: 5, Length: 2, SourceID: 1}}, lookupRanges(s, out))

	// A sliced window derives only the intersecting range, shifted to the window.
	window := managed[3:6] // bytes 3,4,5; only byte 5 (window offset 2) is tainted.
	propagation.StringWindows(managed, []string{window})
	require.Equal(t, []ranges.Range{{Start: 2, Length: 1, SourceID: 1}}, lookupRanges(s, window))
}

func TestJoinAndReplaceActiveUntaintedAreAllocationFree(t *testing.T) {
	_, _ = beginScope(t)
	elements := []string{"alpha", "beta", "gamma"}
	joined := strings.Join(elements, ",")
	replaced := strings.ReplaceAll(joined, "alpha", "delta")
	require.Zero(t, testing.AllocsPerRun(100, func() {
		if propagation.JoinString(elements, ",", joined) != joined {
			panic("JoinString changed an untainted value")
		}
	}))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		if propagation.ReplaceString(joined, "alpha", "delta", replaced, -1) != replaced {
			panic("ReplaceString changed an untainted value")
		}
	}))
}

func TestJoinStringPreservesElementAndSeparatorRanges(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	left, _ := taintString(t, owner, "left", []ranges.Range{{Length: 4, SourceID: 0}})
	right, _ := taintString(t, owner, "right", []ranges.Range{{Length: 5, SourceID: 1}})
	separator, _ := taintString(t, owner, "::", []ranges.Range{{Length: 2, SourceID: 2}})
	elements := []string{left, "plain", right}
	result := strings.Join(elements, separator)
	out := propagation.JoinString(elements, separator, result)
	require.Equal(t, []ranges.Range{
		{Length: 4, SourceID: 0},
		{Start: 4, Length: 2, SourceID: 2},
		{Start: 11, Length: 2, SourceID: 2},
		{Start: 13, Length: 5, SourceID: 1},
	}, lookupRanges(s, out))
}

func TestJoinStringCoarseFallbackIncludesSeparator(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	separator, _ := taintString(t, owner, "::", []ranges.Range{{Length: 2, SourceID: 7}})
	elements := make([]string, maxTestReplaceMatches)
	for index := range elements {
		elements[index] = "x"
	}
	result := strings.Join(elements, separator)
	out := propagation.JoinString(elements, separator, result)
	require.Equal(t, []ranges.Range{{Length: uint32(len(out)), SourceID: 7}}, lookupRanges(s, out))
}

func TestReplaceStringMapsCopiedAndReplacementSegments(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintString(t, owner, "abc-abc", []ranges.Range{
		{Length: 3, SourceID: 0},
		{Start: 3, Length: 1, SourceID: 2},
	})
	replacement, _ := taintString(t, owner, "XY", []ranges.Range{{Length: 2, SourceID: 1}})
	result := strings.ReplaceAll(input, "abc", replacement)
	out := propagation.ReplaceString(input, "abc", replacement, result, -1)
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 1},
		{Start: 2, Length: 1, SourceID: 2},
		{Start: 3, Length: 2, SourceID: 1},
	}, lookupRanges(s, out))
}

func TestReplaceStringHandlesEmptyPatternAndCoarseLimit(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, _ := taintString(t, owner, "éx", []ranges.Range{{Length: 3, SourceID: 0}})
	replacement, _ := taintString(t, owner, "__", []ranges.Range{{Length: 2, SourceID: 1}})
	result := strings.ReplaceAll(input, "", replacement)
	out := propagation.ReplaceString(input, "", replacement, result, -1)
	require.Equal(t, []ranges.Range{
		{Length: 2, SourceID: 1},
		{Start: 2, Length: 2, SourceID: 0},
		{Start: 4, Length: 2, SourceID: 1},
		{Start: 6, Length: 1, SourceID: 0},
		{Start: 7, Length: 2, SourceID: 1},
	}, lookupRanges(s, out))

	many := strings.Repeat("a", maxTestReplaceMatches+1)
	managed, _ := taintString(t, owner, many, []ranges.Range{{Length: uint32(len(many)), SourceID: 3}})
	coarseResult := strings.ReplaceAll(managed, "a", "b")
	coarse := propagation.ReplaceString(managed, "a", "b", coarseResult, -1)
	require.Equal(t, []ranges.Range{{Length: uint32(len(coarse)), SourceID: 3}}, lookupRanges(s, coarse))
}

const maxTestReplaceMatches = 32

func TestRepeatStringCountOneDerivesAndCountNClones(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "ab", []ranges.Range{{Length: 2, SourceID: 0}})

	// count == 1: strings.Repeat returns the input itself, so derive the alias.
	out := propagation.RepeatString(managed, managed, 1)
	require.True(t, unsafe.StringData(out) == unsafe.StringData(managed), "count-one must derive the alias")
	require.Equal(t, []ranges.Range{{Length: 2, SourceID: 0}}, lookupRanges(s, out))

	// count == 3: a fresh allocation is cloned once and adopted.
	result := strings.Repeat(managed, 3)
	out = propagation.RepeatString(managed, result, 3)
	require.True(t, unsafe.StringData(out) != unsafe.StringData(result), "repeat result must be a managed clone")
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 0}}, lookupRanges(s, out))
}

func TestRepeatStringIsolatesStaticBacking(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	// Two spaces form a tainted value of length 2 (the minimum root size).
	managed, _ := taintString(t, owner, "  ", []ranges.Range{{Length: 2, SourceID: 0}})

	// strings.Repeat fast path returns a window of the static repeatedSpaces buffer.
	result := strings.Repeat("  ", 3)
	require.True(t, len(result) == 6)

	out := propagation.RepeatString(managed, result, 3)
	// The published result must be a managed clone, not the static backing.
	require.True(t, unsafe.StringData(out) != unsafe.StringData(result), "static backing must be isolated by cloning")
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 0}}, lookupRanges(s, out))
}

func TestRepeatBytesAdoptsCountOneAndCountNResults(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	value := []byte("ab")
	managed := make([]byte, len(value), 4)
	copy(managed, value)
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: 2, SourceID: 0}}, uint32(cap(managed))).Valid)
	_, ok := owner.AdoptBytes(managed, &set)
	require.True(t, ok)

	// Go 1.26.6 allocates a fresh result even when count is one.
	one := bytes.Repeat(managed, 1)
	require.True(t, unsafe.SliceData(one) != unsafe.SliceData(managed))
	oneData := unsafe.SliceData(one)
	out := propagation.RepeatBytes(managed, one, 1)
	require.True(t, unsafe.SliceData(out) == oneData, "count-one result must be adopted as-is")
	require.Equal(t, []ranges.Range{{Length: 2, SourceID: 0}}, lookupByteRanges(s, out))

	// count == 3: adopt the fresh result as-is.
	result := bytesRepeat(managed, 3)
	resultData := unsafe.SliceData(result)
	out = propagation.RepeatBytes(managed, result, 3)
	require.True(t, unsafe.SliceData(out) == resultData, "byte repeat result must not be replaced")
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 0}}, lookupByteRanges(s, out))
}

func TestOneByteWindowDerivesButOneByteRootIsRejected(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "ab", []ranges.Range{{Length: 2, SourceID: 0}})

	// A one-byte non-empty window derives from the existing root.
	one := managed[:1]
	propagation.StringWindows(managed, []string{one})
	require.Equal(t, []ranges.Range{{Length: 1, SourceID: 0}}, lookupRanges(s, one), "one-byte windows derive")

	// A one-byte non-alias result cannot create a root and stays untainted.
	fresh := "x"
	out := propagation.CopyString(managed, fresh)
	require.Equal(t, "x", out)
	require.Nil(t, lookupRanges(s, "x"))
}

func TestCaseStringUsesExactASCIIAndCoarseUnicodeRanges(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	ascii, _ := taintString(t, owner, "aBcD", []ranges.Range{{Start: 1, Length: 2, SourceID: 0}})
	asciiResult := strings.ToUpper(ascii)
	asciiOut := propagation.CaseString(ascii, asciiResult)
	require.Equal(t, []ranges.Range{{Start: 1, Length: 2, SourceID: 0}}, lookupRanges(s, asciiOut))

	unicodeInput, _ := taintString(t, owner, "aé", []ranges.Range{{Start: 1, Length: 2, SourceID: 1}})
	unicodeResult := strings.ToUpper(unicodeInput)
	unicodeOut := propagation.CaseString(unicodeInput, unicodeResult)
	require.Equal(t, []ranges.Range{{Length: uint32(len(unicodeOut)), SourceID: 1}}, lookupRanges(s, unicodeOut))
}

func TestCoarseFormatSupportsDefinedStringsAndBytes(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managedString, _ := taintString(t, owner, "attack", []ranges.Range{{Length: 6, SourceID: 0}})
	managedBytes := make([]byte, 5)
	copy(managedBytes, "bytes")
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: 5, SourceID: 1}}, uint32(cap(managedBytes))).Valid)
	_, ok := owner.AdoptBytes(managedBytes, &set)
	require.True(t, ok)
	type namedString string
	type namedBytes []byte
	result := "attack [98 121 116 101 115]"
	out := propagation.CoarseFormatString(result, []any{namedString(managedString), namedBytes(managedBytes)})
	require.Equal(t, []ranges.Range{{Length: uint32(len(out)), SourceID: 0}}, lookupRanges(s, out))
}

func TestCoarseStringPreservesEachOwnerSourceAndMarks(t *testing.T) {
	s, _ := beginScope(t)
	ownerA := acquireOwner(t, s)
	ownerB := acquireOwner(t, s)
	inputA, _ := taintString(t, ownerA, "invalid", []ranges.Range{{Length: 7, SourceID: 3, Marks: 0x4}})
	inputB, _ := taintString(t, ownerB, "repair", []ranges.Range{{Length: 6, SourceID: 7, Marks: 0x8}})

	out := propagation.CoarseString("invalid-repair", inputA, inputB)
	key, ok := store.StringKey(out)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 2, snapshot.Len())

	got := make(map[ranges.SourceID]uint64, 2)
	for index := 0; index < snapshot.Len(); index++ {
		entry, ok := snapshot.At(index)
		require.True(t, ok)
		require.Equal(t, 1, entry.Ranges.Len())
		observed, ok := entry.Ranges.At(0)
		require.True(t, ok)
		require.Equal(t, uint32(len(out)), observed.Length)
		got[observed.SourceID] = observed.Marks
	}
	require.Equal(t, map[ranges.SourceID]uint64{3: 0x4, 7: 0x8}, got)
}

func TestCoarseStringTwoOwnersKeepLocalSourceIDs(t *testing.T) {
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

	managedA, ok := analysisA.TaintString(constants.OriginHttpRequestParameter, "a", "attacker")
	require.True(t, ok)
	managedB, ok := analysisB.TaintString(constants.OriginHttpRequestParameter, "b", "victim")
	require.True(t, ok)

	s := request.ActiveStore()
	require.NotNil(t, s)

	result := "attacker-victim"
	out := propagation.CoarseString(result, managedA, managedB)
	require.True(t, unsafe.StringData(out) != unsafe.StringData(result), "coarse result must be a managed clone")

	// Both owners publish the same clone; source IDs stay owner-local (both 0).
	key, _ := store.StringKey(out)
	require.Equal(t, 2, lookupEntryCount(s, key), "two owners must each publish")
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	seen := map[uint8]ranges.SourceID{}
	for i := 0; i < snapshot.Len(); i++ {
		entry, _ := snapshot.At(i)
		r, _ := entry.Ranges.At(0)
		seen[entry.OwnerIndex] = r.SourceID
		require.Equal(t, uint32(len(out)), r.Length)
	}
	require.Len(t, seen, 2)
	for _, id := range seen {
		require.Equal(t, ranges.SourceID(0), id, "source IDs are owner-local")
	}
}

func TestCoarseBytesAdoptsResultWithVisibleCap(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input := []byte("attacker")
	managed := make([]byte, len(input), 8)
	copy(managed, input)
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(input)), SourceID: 0}}, uint32(cap(managed))).Valid)
	_, ok := owner.AdoptBytes(managed, &set)
	require.True(t, ok)

	result := make([]byte, len(input), 16)
	copy(result, input)
	resultData := unsafe.SliceData(result)
	out := propagation.CoarseBytes(result, managed)
	require.True(t, unsafe.SliceData(out) == resultData, "coarse bytes must not replace the result")
	require.Equal(t, []ranges.Range{{Length: uint32(len(result)), SourceID: 0}}, lookupByteRanges(s, result))
}

func TestCoarseBytesNeverAdoptsAnUntaintedInputWindow(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	tainted := make([]byte, 10)
	copy(tainted, "attacker!!")
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: 10, SourceID: 0}}, uint32(cap(tainted))).Valid)
	_, ok := owner.AdoptBytes(tainted, &set)
	require.True(t, ok)

	parent := make([]byte, 1<<20)
	window := parent[len(parent)-10:]
	charged := s.ProcessCharged()
	out := propagation.CoarseBytes(window, window, tainted)
	require.True(t, unsafe.SliceData(out) == unsafe.SliceData(window))
	require.Equal(t, charged, s.ProcessCharged())
	require.Nil(t, lookupByteRanges(s, window))
}

func TestByteCapBoundRejectsOversizedResult(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input := []byte("attacker")
	managed := make([]byte, len(input), 8)
	copy(managed, input)
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: uint32(len(input)), SourceID: 0}}, uint32(cap(managed))).Valid)
	_, ok := owner.AdoptBytes(managed, &set)
	require.True(t, ok)

	// A result whose visible capacity exceeds the root byte limit is not adopted.
	oversized := make([]byte, len(input), store.MaxRootBytes+1)
	copy(oversized, input)
	out := propagation.CopyBytes(managed, oversized)
	require.True(t, unsafe.SliceData(out) == unsafe.SliceData(oversized))
	require.Nil(t, lookupByteRanges(s, oversized), "oversized cap must not be adopted")

	// A result within bounds is adopted.
	bounded := make([]byte, len(input), 32)
	copy(bounded, input)
	propagation.CopyBytes(managed, bounded)
	require.Equal(t, []ranges.Range{{Length: uint32(len(bounded)), SourceID: 0}}, lookupByteRanges(s, bounded))
}

func TestEntryHandleRejectsFinishedAndReusedOwner(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "attacker-value", []ranges.Range{{Length: 14, SourceID: 0}})

	key, _ := store.StringKey(managed)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	entry, _ := snapshot.At(0)
	handle, valid := entry.Handle(s)
	require.True(t, valid)
	require.Equal(t, owner.ID(), handle.ID())

	// After finish, the stale entry must not produce a handle.
	oldOwnerID := owner.ID()
	owner.Finish()
	_, valid = entry.Handle(s)
	require.False(t, valid)

	// After slot reuse with a new generation and owner ID, the stale entry still fails.
	reused := s.Acquire()
	require.False(t, reused.Disabled())
	require.NotEqual(t, owner.Generation(), reused.Generation())
	require.NotEqual(t, oldOwnerID, reused.ID())
	_, valid = entry.Handle(s)
	require.False(t, valid, "stale entry must not handle a reused slot")

	// Propagation after finish is a safe no-op: the lookup finds nothing live.
	out := propagation.CopyString(managed, strings.Clone(managed))
	require.Nil(t, lookupRanges(s, out))
	reused.Finish()
}

func TestPropagationFinishRaceIsSafe(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	managed, _ := taintString(t, owner, "attacker-value", []ranges.Range{{Length: 14, SourceID: 0}})
	fresh := strings.Clone(managed)

	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for i := 0; i < 200; i++ {
				propagation.CopyString(managed, fresh)
				propagation.StringWindows(managed, []string{managed[:3], managed[3:7]})
			}
		}()
	}
	// Finish concurrently with the propagating workers.
	close(start)
	finished := make(chan struct{})
	go func() {
		owner.Finish()
		close(finished)
	}()
	wait.Wait()
	<-finished
	// The store must remain usable and consistent.
	require.Zero(t, s.ProcessValues())
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// bytesRepeat mirrors bytes.Repeat without importing it from the wrapper package,
// to keep the test dependency closure minimal.
func bytesRepeat(b []byte, count int) []byte {
	if count <= 0 || len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b)*count)
	for i := 0; i < count; i++ {
		copy(out[i*len(b):], b)
	}
	return out
}

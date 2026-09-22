// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

type nativeExpectedRange struct {
	start  uint32
	length uint32
	source taint.SourceValue
	marks  []taint.VulnerabilityType
}

type nativeStringRangeSeed struct {
	source string
	start  uint32
	length uint32
	marks  []taint.VulnerabilityType
}

type nativeByteRangeSeed struct {
	source []byte
	start  uint32
	length uint32
	marks  []taint.VulnerabilityType
}

func beginNativePropagation(t *testing.T) context.Context {
	t.Helper()
	previousEnabled := config.Enabled
	previousSampling := config.RequestSamplingPct
	previousMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(func() {
		scope.Finish()
		config.Enabled = previousEnabled
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousMax
	})
	return ctx
}

func nativeStringSource(t *testing.T, ctx context.Context, name, value string) string {
	t.Helper()
	managed := taint.TaintString(ctx, taint.Source{
		Origin: taint.OriginHttpRequestParameter,
		Name:   name,
	}, value)
	require.True(t, taint.IsTaintedString(managed))
	return managed
}

func nativeByteSource(t *testing.T, ctx context.Context, name string, value []byte) []byte {
	t.Helper()
	managed := taint.TaintBytes(ctx, taint.Source{
		Origin: taint.OriginHttpRequestBody,
		Name:   name,
	}, value)
	require.True(t, taint.IsTaintedBytes(managed))
	return managed
}

func nativeStringWithRanges(t *testing.T, value string, seeds ...nativeStringRangeSeed) string {
	t.Helper()
	require.NotEmpty(t, seeds)
	s := request.ActiveStore()
	require.NotNil(t, s)
	raw := make([]ranges.Range, len(seeds))
	var ownerEntry store.Entry
	for index, seed := range seeds {
		entry, sourceRange := nativeStringEntry(t, s, seed.source)
		if index == 0 {
			ownerEntry = entry
		} else {
			require.Equal(t, ownerEntry.OwnerID, entry.OwnerID)
			require.Equal(t, ownerEntry.OwnerGen, entry.OwnerGen)
			require.Equal(t, ownerEntry.OwnerIndex, entry.OwnerIndex)
		}
		raw[index] = ranges.Range{
			Start:    seed.start,
			Length:   seed.length,
			SourceID: sourceRange.SourceID,
			Marks:    nativeMarkBits(t, seed.marks),
		}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(
		&set,
		ownerEntry.Ranges.Limit(),
		raw,
		uint32(len(value)),
	).Valid)
	owner, ok := ownerEntry.Handle(s)
	require.True(t, ok)
	managed := strings.Clone(value)
	_, ok = owner.AdoptString(managed, &set)
	require.True(t, ok)
	return managed
}

func nativeBytesWithRanges(t *testing.T, value []byte, seeds ...nativeByteRangeSeed) []byte {
	t.Helper()
	require.NotEmpty(t, seeds)
	s := request.ActiveStore()
	require.NotNil(t, s)
	raw := make([]ranges.Range, len(seeds))
	var ownerEntry store.Entry
	for index, seed := range seeds {
		entry, sourceRange := nativeByteEntry(t, s, seed.source)
		if index == 0 {
			ownerEntry = entry
		} else {
			require.Equal(t, ownerEntry.OwnerID, entry.OwnerID)
			require.Equal(t, ownerEntry.OwnerGen, entry.OwnerGen)
			require.Equal(t, ownerEntry.OwnerIndex, entry.OwnerIndex)
		}
		raw[index] = ranges.Range{
			Start:    seed.start,
			Length:   seed.length,
			SourceID: sourceRange.SourceID,
			Marks:    nativeMarkBits(t, seed.marks),
		}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(
		&set,
		ownerEntry.Ranges.Limit(),
		raw,
		uint32(len(value)),
	).Valid)
	owner, ok := ownerEntry.Handle(s)
	require.True(t, ok)
	managed := make([]byte, len(value))
	copy(managed, value)
	_, ok = owner.AdoptBytes(managed, &set)
	require.True(t, ok)
	return managed
}

func nativeStringEntry(t *testing.T, s *store.Store, value string) (store.Entry, ranges.Range) {
	t.Helper()
	key, ok := store.StringKey(value)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	sourceRange, ok := entry.Ranges.At(0)
	require.True(t, ok)
	return *entry, sourceRange
}

func nativeByteEntry(t *testing.T, s *store.Store, value []byte) (store.Entry, ranges.Range) {
	t.Helper()
	key, ok := store.BytesKey(value)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	sourceRange, ok := entry.Ranges.At(0)
	require.True(t, ok)
	return *entry, sourceRange
}

func nativeMarkBits(t *testing.T, vulnerabilities []taint.VulnerabilityType) uint64 {
	t.Helper()
	var result uint64
	for _, vulnerability := range vulnerabilities {
		bit, ok := ranges.MarkBit(vulnerability)
		require.True(t, ok)
		result |= bit
	}
	return result
}

func requireNativeStringRanges(t *testing.T, value string, want ...nativeExpectedRange) {
	t.Helper()
	index := 0
	tainted := taint.VisitString(value, func(got taint.Range) bool {
		require.Less(t, index, len(want))
		requireNativeRange(t, got, want[index])
		index++
		return true
	})
	require.Equal(t, len(want) != 0, tainted)
	require.Equal(t, len(want), index)
}

func requireNativeByteRanges(t *testing.T, value []byte, want ...nativeExpectedRange) {
	t.Helper()
	index := 0
	tainted := taint.VisitBytes(value, func(got taint.Range) bool {
		require.Less(t, index, len(want))
		requireNativeRange(t, got, want[index])
		index++
		return true
	})
	require.Equal(t, len(want) != 0, tainted)
	require.Equal(t, len(want), index)
}

func requireNativeRange(t *testing.T, got taint.Range, want nativeExpectedRange) {
	t.Helper()
	require.Equal(t, want.start, got.Start)
	require.Equal(t, want.length, got.Length)
	require.Equal(t, want.source, got.Source)
	for vulnerability := taint.VulnerabilityType(1); vulnerability <= taint.VulnerabilityType(constants.VulnerabilityTypeCount); vulnerability++ {
		require.Equal(
			t,
			containsVulnerability(want.marks, vulnerability),
			got.Marks.Has(vulnerability),
			"secure mark %d",
			vulnerability,
		)
	}
}

func containsVulnerability(vulnerabilities []taint.VulnerabilityType, target taint.VulnerabilityType) bool {
	for _, vulnerability := range vulnerabilities {
		if vulnerability == target {
			return true
		}
	}
	return false
}

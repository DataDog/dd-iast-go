// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
)

var testOwner = OwnerIdentity{ID: 7, Generation: 3, Index: 2}

func src(name string) Source {
	return Source{Origin: constants.OriginHttpRequestParameter, Name: name, Value: name + "-value"}
}

func attributedSegment(start, length uint32, name string) Segment {
	return Segment{Start: start, Length: length, Source: src(name)}
}

func foreignSegment(start, length uint32) Segment {
	return Segment{Start: start, Length: length, Foreign: true}
}

func parts(snapshot *Snapshot) []Part {
	result := make([]Part, 0, snapshot.PartCount())
	for index := 0; index < snapshot.PartCount(); index++ {
		part, _ := snapshot.PartAt(index)
		result = append(result, part)
	}
	return result
}

func sourceNames(snapshot *Snapshot) []string {
	names := make([]string, 0, snapshot.SourceCount())
	for index := 0; index < snapshot.SourceCount(); index++ {
		source, _ := snapshot.SourceAt(index)
		names = append(names, source.Name)
	}
	return names
}

func build(t *testing.T, value string, segments ...Segment) *Snapshot {
	t.Helper()
	snapshot, status := Build(testOwner, value, segments)
	require.Equal(t, StatusCollected, status)
	require.NotNil(t, snapshot)
	assertSnapshotTiling(t, snapshot)
	return snapshot
}

func setRangeCount(t *testing.T, count uint64) {
	t.Helper()
	previous := config.MaxRangeCount
	config.MaxRangeCount = count
	t.Cleanup(func() { config.MaxRangeCount = previous })
}

func TestBuildOwnsCanonicalEvidence(t *testing.T) {
	value := strings.Clone("SELECT attacker")
	source := Source{Origin: constants.OriginHttpRequestParameter, Name: strings.Clone("query"), Value: strings.Clone("attacker")}
	snapshot := build(t, value, Segment{Start: 7, Length: 8, Source: source})
	require.Equal(t, value, snapshot.Value())
	require.True(t, unsafe.StringData(value) != unsafe.StringData(snapshot.Value()), "the snapshot must own a clone of the value")
	owner, ok := snapshot.Owner()
	require.True(t, ok)
	require.Equal(t, testOwner, owner)
	require.Equal(t, 1, snapshot.SourceCount())
	got, _ := snapshot.SourceAt(0)
	require.Equal(t, source, got)
	require.True(t, unsafe.StringData(source.Value) != unsafe.StringData(got.Value), "the snapshot must own a clone of the source")
	require.Equal(t, uint32(len("query")+len("attacker")), snapshot.SourceBytes())
	require.Equal(t, []Part{
		{Start: 0, Length: 7, Source: -1},
		{Start: 7, Length: 8, Source: 0},
	}, parts(snapshot))
	part, _ := snapshot.PartAt(1)
	partValue, ok := snapshot.PartValue(part)
	require.True(t, ok)
	require.Equal(t, "attacker", partValue)
}

func TestBuildForeignParts(t *testing.T) {
	// "a" and "b" are sources of the owner; [4, 6) are tainted bytes of no
	// source of the owner (for example of a different request).
	snapshot := build(t, "0123456789",
		attributedSegment(0, 2, "a"),
		foreignSegment(4, 2),
		attributedSegment(6, 2, "b"),
	)
	require.Equal(t, []string{"a", "b"}, sourceNames(snapshot))
	require.Equal(t, []Part{
		{Start: 0, Length: 2, Source: 0},
		{Start: 2, Length: 2, Source: -1},
		{Start: 4, Length: 2, Source: -1, Foreign: true},
		{Start: 6, Length: 2, Source: 1},
		{Start: 8, Length: 2, Source: -1},
	}, parts(snapshot))
}

func TestBuildMergesAdjacentParts(t *testing.T) {
	snapshot := build(t, "abcdefgh",
		attributedSegment(0, 2, "same"),
		attributedSegment(2, 2, "same"),
		foreignSegment(4, 1),
		foreignSegment(5, 1),
	)
	require.Equal(t, []Part{
		{Start: 0, Length: 4, Source: 0},
		{Start: 4, Length: 2, Source: -1, Foreign: true},
		{Start: 6, Length: 2, Source: -1},
	}, parts(snapshot))
}

func TestBuildSourcesInOrderOfFirstPart(t *testing.T) {
	snapshot := build(t, "0123456789",
		attributedSegment(0, 2, "z"),
		attributedSegment(2, 2, "a"),
		attributedSegment(4, 2, "z"),
	)
	require.Equal(t, []string{"z", "a"}, sourceNames(snapshot))
	require.Equal(t, []Part{
		{Start: 0, Length: 2, Source: 0},
		{Start: 2, Length: 2, Source: 1},
		{Start: 4, Length: 2, Source: 0},
		{Start: 6, Length: 4, Source: -1},
	}, parts(snapshot))
}

func TestBuildWithoutSourceIsNone(t *testing.T) {
	snapshot, status := Build(testOwner, "0123", []Segment{foreignSegment(0, 4)})
	require.Equal(t, StatusNone, status, "a report needs at least one source of the owner (plan 4.5.2)")
	require.Nil(t, snapshot)
	snapshot, status = Build(testOwner, "", []Segment{attributedSegment(0, 1, "a")})
	require.Equal(t, StatusNone, status)
	require.Nil(t, snapshot)
}

func TestBuildCutsInvalidSegments(t *testing.T) {
	snapshot := build(t, "0123",
		attributedSegment(0, 3, "a"),
		attributedSegment(2, 10, "b"), // overlaps "a" and goes out of value
		attributedSegment(9, 1, "c"),  // out of value
	)
	require.Equal(t, []string{"a", "b"}, sourceNames(snapshot))
	require.Equal(t, []Part{
		{Start: 0, Length: 3, Source: 0},
		{Start: 3, Length: 1, Source: 1},
	}, parts(snapshot))
}

func TestBuildRangeCountOverflowIsForeign(t *testing.T) {
	setRangeCount(t, 2)
	snapshot := build(t, "0123456789",
		attributedSegment(0, 1, "a"),
		attributedSegment(2, 1, "b"),
		attributedSegment(4, 1, "c"),
		attributedSegment(6, 1, "d"),
	)
	require.Equal(t, []string{"a", "b"}, sourceNames(snapshot))
	require.Equal(t, []Part{
		{Start: 0, Length: 1, Source: 0},
		{Start: 1, Length: 1, Source: -1},
		{Start: 2, Length: 1, Source: 1},
		{Start: 3, Length: 1, Source: -1},
		{Start: 4, Length: 1, Source: -1, Foreign: true},
		{Start: 5, Length: 1, Source: -1},
		{Start: 6, Length: 1, Source: -1, Foreign: true},
		{Start: 7, Length: 3, Source: -1},
	}, parts(snapshot), "bytes after the bound are foreign, never clean evidence")
}

func TestBuildPartOverflowIsForeignTail(t *testing.T) {
	setRangeCount(t, MaxAttributedParts)
	value := strings.Repeat("x", 4*MaxTaintedParts)
	segments := make([]Segment, 0, 2*MaxTaintedParts)
	for index := range 2 * MaxTaintedParts {
		segments = append(segments, foreignSegment(uint32(2*index), 1))
	}
	segments = append(segments, attributedSegment(uint32(4*MaxTaintedParts-1), 1, "late"))
	// One attributed part first, so that the report is collected.
	segments = append([]Segment{attributedSegment(0, 0, "none")}, segments...)
	snapshot, status := Build(testOwner, value, segments)
	require.Equal(t, StatusNone, status, "an empty segment is not a source")
	require.Nil(t, snapshot)

	segments[0] = attributedSegment(0, 1, "first")
	segments[1] = foreignSegment(1, 1)
	snapshot = build(t, value, segments...)
	require.LessOrEqual(t, snapshot.PartCount(), MaxParts)
	require.Equal(t, []string{"first"}, sourceNames(snapshot))
	all := parts(snapshot)
	last := all[len(all)-1]
	require.True(t, last.Foreign, "the overflow tail must be foreign: %#v", last)
	require.Equal(t, uint32(len(value)), last.Start+last.Length, "the tail covers the late attributed byte")
}

func TestBuildSourceBytesOverflowIsForeign(t *testing.T) {
	large := strings.Repeat("x", MaxSnapshotBytes/2)
	first := Source{Origin: constants.OriginHttpRequestParameter, Name: "a", Value: large}
	second := Source{Origin: constants.OriginHttpRequestParameter, Name: "b", Value: large}
	snapshot := build(t, "0123", Segment{Start: 0, Length: 1, Source: first}, Segment{Start: 2, Length: 1, Source: second})
	require.Equal(t, []string{"a"}, sourceNames(snapshot))
	require.Equal(t, []Part{
		{Start: 0, Length: 1, Source: 0},
		{Start: 1, Length: 1, Source: -1},
		{Start: 2, Length: 1, Source: -1, Foreign: true},
		{Start: 3, Length: 1, Source: -1},
	}, parts(snapshot))
	require.Equal(t, uint32(1+len(large)), snapshot.SourceBytes())
}

func TestCollectRejectsInvalidVulnerability(t *testing.T) {
	snapshot, status := CollectStringFor(Target{}, "clean-value", constants.VulnerabilityType(255))
	require.Equal(t, StatusDropped, status)
	require.Nil(t, snapshot)
	snapshot, status = CollectJoinedStringsFor(Target{}, []string{"a"}, " ", "a", 0)
	require.Equal(t, StatusDropped, status)
	require.Nil(t, snapshot)
}

func TestCollectJoinedStringsRejectsMismatchedResult(t *testing.T) {
	snapshot, status := CollectJoinedStringsFor(Target{}, []string{"echo", "secret"}, " ", "different", constants.VulnerabilityTypeCommandInjection)
	require.Equal(t, StatusNone, status)
	require.Nil(t, snapshot)
	require.True(t, matchesJoin([]string{"echo", "secret"}, " ", "echo secret"))
	require.False(t, matchesJoin([]string{"echo", "secret"}, " ", "echo secret "))
	require.False(t, matchesJoin([]string{"echo", "secret"}, "--", "echo secret"))
}

func TestCollectStringMissDoesNotAllocate(t *testing.T) {
	value := strings.Repeat("clean-value", 2)
	allocations := testing.AllocsPerRun(1_000, func() {
		if snapshot, status := CollectStringFor(Target{}, value, constants.VulnerabilityTypeSqlInjection); snapshot != nil || status != StatusNone {
			t.Fatalf("miss = (%v, %v)", snapshot, status)
		}
		if MayCollectJoinedStrings([]string{value}, value) {
			t.Fatal("clean values may be collected")
		}
	})
	require.Zero(t, allocations)
}

func BenchmarkCollectStringMiss(b *testing.B) {
	for b.Loop() {
		CollectStringFor(Target{}, "clean-value", constants.VulnerabilityTypeSqlInjection)
	}
}

func TestSnapshotAccessorsRejectInvalidInputs(t *testing.T) {
	var nilSnapshot *Snapshot
	require.Empty(t, nilSnapshot.Value())
	require.Zero(t, nilSnapshot.SourceCount())
	require.Zero(t, nilSnapshot.PartCount())
	require.Zero(t, nilSnapshot.SourceBytes())
	_, ok := nilSnapshot.Owner()
	require.False(t, ok)
	_, ok = nilSnapshot.SourceAt(0)
	require.False(t, ok)
	_, ok = nilSnapshot.PartAt(0)
	require.False(t, ok)
	_, ok = nilSnapshot.PartValue(Part{Length: 1})
	require.False(t, ok)

	value := "attacker"
	snapshot := build(t, value, attributedSegment(0, 8, "query"))
	for _, index := range []int{-1, snapshot.SourceCount()} {
		_, ok = snapshot.SourceAt(index)
		require.False(t, ok)
	}
	for _, index := range []int{-1, snapshot.PartCount()} {
		_, ok = snapshot.PartAt(index)
		require.False(t, ok)
	}
	for _, invalid := range []Part{{}, {Start: uint32(len(value)), Length: 1}, {Start: 1, Length: ^uint32(0)}} {
		_, ok = snapshot.PartValue(invalid)
		require.False(t, ok)
	}
}

func FuzzBuild(f *testing.F) {
	f.Add([]byte{0, 3, 'a', 1, 2, 'b', 4, 3, 'c'})
	f.Add([]byte{2, 8, 'z', 2, 4, 'a', 0, 10, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		const value = "0123456789abcdef"
		count := min(len(data)/3, 64)
		segments := make([]Segment, 0, count)
		for index := 0; index < count; index++ {
			start := uint32(data[3*index] % byte(len(value)))
			length := uint32(data[3*index+1]) % 20
			if data[3*index+2] == 0 {
				segments = append(segments, foreignSegment(start, length))
			} else {
				segments = append(segments, attributedSegment(start, length, string([]byte{data[3*index+2]})))
			}
		}
		snapshot, status := Build(testOwner, value, segments)
		if status != StatusCollected {
			return
		}
		assertSnapshotTiling(t, snapshot)
		for index := 0; index < snapshot.PartCount(); index++ {
			part, _ := snapshot.PartAt(index)
			if part.Source >= int16(snapshot.SourceCount()) || part.Foreign && part.Source >= 0 {
				t.Fatalf("part %d is not valid: %#v", index, part)
			}
		}
	})
}

func assertSnapshotTiling(t *testing.T, snapshot *Snapshot) {
	t.Helper()
	position := uint32(0)
	for index := 0; index < snapshot.PartCount(); index++ {
		part, _ := snapshot.PartAt(index)
		if part.Start != position || part.Length == 0 {
			t.Fatalf("part %d does not tile at %d: %#v", index, position, part)
		}
		if _, ok := snapshot.PartValue(part); !ok {
			t.Fatalf("part %d has invalid value bounds", index)
		}
		position += part.Length
	}
	if position != uint32(len(snapshot.Value())) {
		t.Fatalf("parts end at %d, want %d", position, len(snapshot.Value()))
	}
}

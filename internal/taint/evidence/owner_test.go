// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package evidence

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func ownerOf(owner uint64) OwnerIdentity {
	return OwnerIdentity{ID: owner, Generation: 1, Index: uint8(owner % 4)}
}

func sourceNames(snapshot *Snapshot) []string {
	names := make([]string, 0, snapshot.SourceCount())
	for index := 0; index < snapshot.SourceCount(); index++ {
		source, _ := snapshot.SourceAt(index)
		names = append(names, source.Name)
	}
	return names
}

func TestForOwnerKeepsOverlappedRangesOfSelectedOwner(t *testing.T) {
	// Owner 2 has the same bytes as owner 1. Cross-owner overlap selection
	// keeps source "a" of owner 1 and removes source "b" of owner 2.
	snapshot := snapshotFromResolved(t, "0123456789", []request.ResolvedRange{
		resolved(2, 4, "a", 1),
		resolved(2, 4, "b", 2),
		resolved(7, 2, "c", 2),
	})
	require.Equal(t, 2, snapshot.OwnerCount())
	require.Equal(t, []string{"a", "c"}, sourceNames(snapshot))

	bravo, ok := snapshot.ForOwner(ownerOf(2))
	require.True(t, ok)
	require.Equal(t, 1, bravo.OwnerCount())
	owner, _ := bravo.OwnerAt(0)
	require.Equal(t, ownerOf(2), owner)
	require.Equal(t, []string{"b", "c"}, sourceNames(bravo))
	require.Equal(t, snapshot.Value(), bravo.Value())
	var parts []Part
	for index := 0; index < bravo.PartCount(); index++ {
		part, _ := bravo.PartAt(index)
		parts = append(parts, part)
	}
	// The bytes of owner 1 are in a range of owner 2: they keep the
	// evidence of owner 2 (see buildParts). No other byte has an owner.
	require.Equal(t, []Part{
		{Start: 0, Length: 2, Source: -1},
		{Start: 2, Length: 4, Source: 0},
		{Start: 6, Length: 1, Source: -1},
		{Start: 7, Length: 2, Source: 1},
		{Start: 9, Length: 1, Source: -1},
	}, parts)
	require.Equal(t, uint32(4), bravo.SourceBytes())

	alpha, ok := snapshot.ForOwner(ownerOf(1))
	require.True(t, ok)
	require.Equal(t, []string{"a"}, sourceNames(alpha))
	// The range [7, 9) of owner 2 is foreign for owner 1.
	require.Equal(t, []Part{
		{Start: 0, Length: 2, Source: -1},
		{Start: 2, Length: 4, Source: 0},
		{Start: 6, Length: 1, Source: -1},
		{Start: 7, Length: 2, Source: -1, Foreign: true},
		{Start: 9, Length: 1, Source: -1},
	}, snapshotParts(alpha))

	// The multi-owner snapshot does not change.
	require.Equal(t, []string{"a", "c"}, sourceNames(snapshot))
	again, ok := snapshot.ForOwner(ownerOf(2))
	require.True(t, ok)
	require.Equal(t, []string{"b", "c"}, sourceNames(again))
}

func TestForOwnerRejectsMissingOwner(t *testing.T) {
	snapshot := snapshotFromResolved(t, "abcdef", []request.ResolvedRange{
		resolved(0, 2, "a", 1),
		resolved(2, 2, "b", 2),
	})
	for _, owner := range []OwnerIdentity{
		ownerOf(3),
		{ID: 1, Generation: 2, Index: 1},
		{ID: 1, Generation: 1, Index: 2},
		{},
	} {
		restricted, ok := snapshot.ForOwner(owner)
		require.False(t, ok, "%#v", owner)
		require.Nil(t, restricted)
		require.False(t, snapshot.HasOwner(owner))
	}
	var nilSnapshot *Snapshot
	restricted, ok := nilSnapshot.ForOwner(ownerOf(1))
	require.False(t, ok)
	require.Nil(t, restricted)
}

func TestForOwnerReturnsSingleOwnerSnapshot(t *testing.T) {
	snapshot := snapshotFromResolved(t, "abcdef", []request.ResolvedRange{
		resolved(0, 2, "a", 1),
		resolved(3, 2, "b", 1),
	})
	restricted, ok := snapshot.ForOwner(ownerOf(1))
	require.True(t, ok)
	require.Same(t, snapshot, restricted, "a single-owner snapshot needs no copy")
	require.Nil(t, snapshot.admitted, "a single-owner snapshot keeps no admitted copy")
}

func TestCollectJoinedStringsForOwnerKeepsOneOwnerArguments(t *testing.T) {
	alphaCtx := withScope(t)
	bravoCtx := withScope(t)
	alpha := taint.TaintString(alphaCtx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "alpha"}, "alpha-arg")
	bravo := taint.TaintString(bravoCtx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "bravo"}, "bravo-arg")
	argv := []string{"run", alpha, bravo}
	snapshot, status := CollectJoinedStrings(argv, " ", "run alpha-arg bravo-arg", constants.VulnerabilityTypeCommandInjection)
	require.Equal(t, StatusCollected, status)
	require.Equal(t, 2, snapshot.OwnerCount())
	for index, name := range []string{"alpha", "bravo"} {
		owner, ok := snapshot.OwnerAt(index)
		require.True(t, ok)
		restricted, ok := snapshot.ForOwner(owner)
		require.True(t, ok)
		require.Equal(t, []string{name}, sourceNames(restricted))
		require.Equal(t, 1, restricted.OwnerCount())
	}
}

// scopedOwner is one active request scope and its store owner.
type scopedOwner struct {
	ctx   context.Context
	owner OwnerIdentity
}

func beginScopedOwner(t *testing.T) scopedOwner {
	t.Helper()
	ctx := withScope(t)
	analysis, ok := request.FromContext(ctx).Analysis()
	require.True(t, ok)
	owner, ok := analysis.Owner()
	require.True(t, ok)
	return scopedOwner{ctx: ctx, owner: owner}
}

func (o scopedOwner) taint(t *testing.T, name, value string) string {
	t.Helper()
	managed := taint.TaintString(o.ctx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: name}, value)
	require.True(t, taint.IsTaintedString(managed))
	return managed
}

// markString returns a copy of input with every range marked secure for mark.
func markString(t *testing.T, input string, mark constants.VulnerabilityType) string {
	t.Helper()
	active := request.ActiveStore()
	require.NotNil(t, active)
	key, ok := store.StringKey(input)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, active.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	owner, ok := entry.Handle(active)
	require.True(t, ok)
	var marked ranges.Set
	require.True(t, ranges.MarkAll(&marked, &entry.Ranges, mark).Valid)
	input = strings.Clone(input)
	_, ok = owner.AdoptString(input, &marked)
	require.True(t, ok)
	return input
}

func join(parts ...string) string {
	return propagation.JoinString(parts, "", strings.Join(parts, ""))
}

func snapshotParts(snapshot *Snapshot) []Part {
	parts := make([]Part, 0, snapshot.PartCount())
	for index := 0; index < snapshot.PartCount(); index++ {
		part, _ := snapshot.PartAt(index)
		parts = append(parts, part)
	}
	return parts
}

func TestCollectStringForMasksForeignBytes(t *testing.T) {
	alpha, bravo := beginScopedOwner(t), beginScopedOwner(t)
	secretA := alpha.taint(t, "id", "alpha-secret")
	// Bravo has a source with the same name and a different value.
	secretB := bravo.taint(t, "id", "bravo-secret")
	query := join("SELECT '", secretA, "' /* ", secretB, " */")

	snapshot, status := CollectStringFor(Target{Owner: alpha.owner, Known: true}, query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	require.Equal(t, 1, snapshot.OwnerCount())
	require.True(t, snapshot.HasOwner(alpha.owner))
	source, _ := snapshot.SourceAt(0)
	require.Equal(t, Source{Origin: constants.OriginHttpRequestParameter, Name: "id", Value: "alpha-secret"}, source)
	require.Equal(t, 1, snapshot.SourceCount())
	start := uint32(len("SELECT 'alpha-secret' /* "))
	require.Equal(t, []Part{
		{Start: 0, Length: 8, Source: -1},
		{Start: 8, Length: 12, Source: 0},
		{Start: 20, Length: 5, Source: -1},
		{Start: start, Length: 12, Source: -1, Foreign: true},
		{Start: start + 12, Length: 3, Source: -1},
	}, snapshotParts(snapshot))

	// The owner of the context is bravo: the bytes of alpha are foreign.
	snapshot, status = CollectStringFor(Target{Owner: bravo.owner, Known: true}, query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	require.Equal(t, []string{"id"}, sourceNames(snapshot))
	source, _ = snapshot.SourceAt(0)
	require.Equal(t, "bravo-secret", source.Value)
	require.Equal(t, Part{Start: 8, Length: 12, Source: -1, Foreign: true}, snapshotParts(snapshot)[1])
}

func TestCollectStringForMasksForeignMarkedBytes(t *testing.T) {
	alpha, bravo := beginScopedOwner(t), beginScopedOwner(t)
	secretA := alpha.taint(t, "a", "alpha-secret")
	// The range of bravo is safe for SQL injection. It is not evidence, but
	// its bytes are still data of bravo.
	secretB := markString(t, bravo.taint(t, "b", "bravo-secret"), constants.VulnerabilityTypeSqlInjection)
	query := join(secretA, "|", secretB)

	for name, target := range map[string]Target{
		"known owner":    {Owner: alpha.owner, Known: true},
		"selected owner": {},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot, status := CollectStringFor(target, query, constants.VulnerabilityTypeSqlInjection)
			require.Equal(t, StatusCollected, status)
			require.Equal(t, []string{"a"}, sourceNames(snapshot))
			require.Equal(t, []Part{
				{Start: 0, Length: 12, Source: 0},
				{Start: 12, Length: 1, Source: -1},
				{Start: 13, Length: 12, Source: -1, Foreign: true},
			}, snapshotParts(snapshot))
		})
	}
	// A value with no unsafe range of the known owner is not collected.
	snapshot, status := CollectStringFor(Target{Owner: bravo.owner, Known: true}, query, constants.VulnerabilityTypeSqlInjection)
	require.Nil(t, snapshot)
	require.Equal(t, StatusSuppressed, status)
}

func TestCollectStringForKeepsSingleOwnerEvidence(t *testing.T) {
	alpha := beginScopedOwner(t)
	query := join("SELECT '", alpha.taint(t, "a", "alpha-secret"), "'")
	legacy, status := CollectString(query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	for _, target := range []Target{{Owner: alpha.owner, Known: true}, {}} {
		snapshot, status := CollectStringFor(target, query, constants.VulnerabilityTypeSqlInjection)
		require.Equal(t, StatusCollected, status)
		require.Equal(t, snapshotParts(legacy), snapshotParts(snapshot), "a query of one owner has no foreign part")
		for _, part := range snapshotParts(snapshot) {
			require.False(t, part.Foreign)
		}
	}
	restricted, ok := legacy.ForOwner(alpha.owner)
	require.True(t, ok)
	require.Zero(t, testing.AllocsPerRun(100, func() {
		restricted, ok = legacy.ForOwner(alpha.owner)
	}), "ForOwner of a single-owner snapshot does not allocate")
	require.Same(t, legacy, restricted)
}

func TestCollectStringForFourOwners(t *testing.T) {
	owners := make([]scopedOwner, 4)
	parts := make([]string, 0, 8)
	for index := range owners {
		owners[index] = beginScopedOwner(t)
		name := string(rune('a' + index))
		parts = append(parts, owners[index].taint(t, name, name+"-value"), ",")
	}
	query := join(parts...)
	all, status := CollectString(query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	require.Equal(t, 4, all.OwnerCount(), "four owners must adopt the shared value")

	for index, current := range owners {
		name := string(rune('a' + index))
		snapshot, status := CollectStringFor(Target{Owner: current.owner, Known: true}, query, constants.VulnerabilityTypeSqlInjection)
		require.Equal(t, StatusCollected, status)
		require.Equal(t, []string{name}, sourceNames(snapshot))
		foreign := 0
		for _, part := range snapshotParts(snapshot) {
			value, _ := snapshot.PartValue(part)
			switch {
			case part.Source >= 0:
				require.Equal(t, name+"-value", value)
			case part.Foreign:
				foreign++
				require.Contains(t, value, "-value")
			default:
				require.Equal(t, ",", value)
			}
		}
		require.Equal(t, 3, foreign, "the bytes of the three other owners are foreign")

		// ForOwner of the snapshot of every owner has the same sources.
		restricted, ok := all.ForOwner(current.owner)
		require.True(t, ok)
		require.Equal(t, []string{name}, sourceNames(restricted))
	}

	// With no known owner, Select gets the sorted owners and selects one.
	var offered []OwnerIdentity
	selected, status := CollectStringFor(Target{Select: func(candidates []OwnerIdentity) (OwnerIdentity, bool) {
		offered = append(offered, candidates...)
		return candidates[2], true
	}}, query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	require.Len(t, offered, 4)
	require.True(t, slices.IsSortedFunc(offered, compareOwners))
	require.Equal(t, 1, selected.OwnerCount())
	owner, _ := selected.OwnerAt(0)
	require.Equal(t, offered[2], owner)

	// A Select result that is not an owner of the value selects the first
	// owner.
	selected, status = CollectStringFor(Target{Select: func([]OwnerIdentity) (OwnerIdentity, bool) {
		return OwnerIdentity{ID: 1 << 60, Generation: 1}, true
	}}, query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	owner, _ = selected.OwnerAt(0)
	require.Equal(t, offered[0], owner)
}

func TestCollectStringForWindowOfSharedRoot(t *testing.T) {
	alpha, bravo := beginScopedOwner(t), beginScopedOwner(t)
	secretA := alpha.taint(t, "a", "alpha-secret")
	secretB := bravo.taint(t, "b", "bravo-secret")
	shared := join(secretA, "|", secretB)
	// The window starts in the value of alpha and ends in the value of bravo.
	window := shared[6:18]
	require.Equal(t, "secret|bravo", window)

	snapshot, status := CollectStringFor(Target{Owner: alpha.owner, Known: true}, window, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, StatusCollected, status)
	require.Equal(t, []string{"a"}, sourceNames(snapshot))
	require.Equal(t, []Part{
		{Start: 0, Length: 6, Source: 0},
		{Start: 6, Length: 1, Source: -1},
		{Start: 7, Length: 5, Source: -1, Foreign: true},
	}, snapshotParts(snapshot))

	// A window with only bytes of bravo is not tainted for alpha.
	snapshot, status = CollectStringFor(Target{Owner: alpha.owner, Known: true}, shared[13:], constants.VulnerabilityTypeSqlInjection)
	require.Nil(t, snapshot)
	require.Equal(t, StatusNone, status)
}

func TestCollectJoinedStringsForBoundsApplyToSelectedOwner(t *testing.T) {
	alpha, bravo := beginScopedOwner(t), beginScopedOwner(t)
	first, second := bravo.taint(t, "b1", "b1"), bravo.taint(t, "b2", "b2")
	// Each argument of bravo has two ranges. Together they have more ranges
	// than MaxCollectedRanges.
	argv := []string{"run", alpha.taint(t, "a", "alpha-arg")}
	for len(argv) < MaxJoinedValues {
		argv = append(argv, join(first, second))
	}
	require.Greater(t, 2*(len(argv)-2), MaxCollectedRanges)
	result := strings.Join(argv, " ")

	snapshot, status := CollectJoinedStrings(argv, " ", result, constants.VulnerabilityTypeCommandInjection)
	require.Nil(t, snapshot)
	require.Equal(t, StatusDropped, status, "the ranges of bravo fill the collection of every owner")

	for name, target := range map[string]Target{
		"known owner": {Owner: alpha.owner, Known: true},
		"selected owner": {Select: func(owners []OwnerIdentity) (OwnerIdentity, bool) {
			require.Len(t, owners, 2)
			return alpha.owner, true
		}},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot, status := CollectJoinedStringsFor(target, argv, " ", result, constants.VulnerabilityTypeCommandInjection)
			require.Equal(t, StatusCollected, status)
			require.Equal(t, []string{"a"}, sourceNames(snapshot))
			require.True(t, snapshot.HasOwner(alpha.owner))
			// Bravo has more foreign intervals than the bound: every part
			// without a source is foreign.
			require.LessOrEqual(t, snapshot.PartCount(), MaxParts)
			for _, part := range snapshotParts(snapshot) {
				require.Equal(t, part.Source < 0, part.Foreign)
			}
		})
	}

	// Bravo exceeds the bounds with its own ranges: its collection drops.
	snapshot, status = CollectJoinedStringsFor(Target{Owner: bravo.owner, Known: true}, argv, " ", result, constants.VulnerabilityTypeCommandInjection)
	require.Nil(t, snapshot)
	require.Equal(t, StatusDropped, status)
}

func TestForeignPartsStayInPartBound(t *testing.T) {
	owner := ownerOf(1)
	const ranges = 200
	value := strings.Repeat("abcd", ranges)
	collector := newCollector(&owner)
	for index := range ranges {
		require.True(t, collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(uint32(4*index), 1, "a", 1)))
	}
	// A foreign interval in each second gap: 200 ranges and 100 masks are
	// more than MaxCollectedRanges, so a gap is not split.
	for index := 0; index < ranges; index += 2 {
		collector.addForeign(uint32(len(value)), 0, uint32(4*index+2), 1)
	}
	snapshot := collector.finish(value)
	require.LessOrEqual(t, snapshot.PartCount(), MaxParts)
	parts := snapshotParts(snapshot)
	require.Len(t, parts, 2*ranges)
	for index, part := range parts {
		if index%2 == 0 {
			require.Equal(t, int16(0), part.Source)
			continue
		}
		require.Equal(t, int16(-1), part.Source)
		require.Equal(t, uint32(3), part.Length)
		require.Equal(t, (index/2)%2 == 0, part.Foreign, "part %d", index)
	}

	// Few masks split the gap: only the foreign bytes are foreign.
	collector = newCollector(&owner)
	require.True(t, collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(0, 1, "a", 1)))
	collector.addForeign(uint32(len(value)), 0, 2, 1)
	collector.addForeign(uint32(len(value)), 0, 3, 2) // It touches the first mask.
	collector.addForeign(uint32(len(value)), 0, 9, 100)
	collector.addForeign(uint32(len(value)), 0, uint32(len(value)), 1) // Empty after the clip.
	snapshot = collector.finish(value)
	require.Equal(t, []Part{
		{Start: 0, Length: 1, Source: 0},
		{Start: 1, Length: 1, Source: -1},
		{Start: 2, Length: 3, Source: -1, Foreign: true},
		{Start: 5, Length: 4, Source: -1},
		{Start: 9, Length: 100, Source: -1, Foreign: true},
		{Start: 109, Length: uint32(len(value)) - 109, Source: -1},
	}, snapshotParts(snapshot))
}

func TestForOwnerMasksSecureRangesOfOtherOwner(t *testing.T) {
	mark, ok := ranges.MarkBit(constants.VulnerabilityTypeSqlInjection)
	require.True(t, ok)
	secure := resolved(6, 3, "b", 2)
	secure.Marks = mark
	snapshot := snapshotFromResolved(t, "0123456789", []request.ResolvedRange{
		resolved(1, 3, "a", 1),
		secure,
	})
	// Owner 2 has only a range with a secure mark. It is not an owner of
	// the snapshot, but its bytes are foreign.
	require.Equal(t, 1, snapshot.OwnerCount())
	want := []Part{
		{Start: 0, Length: 1, Source: -1},
		{Start: 1, Length: 3, Source: 0},
		{Start: 4, Length: 2, Source: -1},
		{Start: 6, Length: 3, Source: -1, Foreign: true},
		{Start: 9, Length: 1, Source: -1},
	}
	require.Equal(t, want, snapshotParts(snapshot))
	restricted, ok := snapshot.ForOwner(ownerOf(1))
	require.True(t, ok)
	require.NotSame(t, snapshot, restricted, "a mixed snapshot is built again")
	require.Equal(t, want, snapshotParts(restricted))
	_, ok = snapshot.ForOwner(ownerOf(2))
	require.False(t, ok, "owner 2 has no unsafe range")
}

func TestForOwnerMasksBytesWithNoKnownOwner(t *testing.T) {
	value := "0123456789"
	collector := newCollector(nil)
	require.True(t, collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(0, 2, "a", 1)))
	// The lookup skipped an owner, or could not copy its sources.
	collector.addHidden(uint32(len(value)), 0, 5, 3)
	snapshot := collector.finish(value)
	require.Equal(t, 1, snapshot.OwnerCount())
	want := []Part{
		{Start: 0, Length: 2, Source: 0},
		{Start: 2, Length: 3, Source: -1},
		{Start: 5, Length: 3, Source: -1, Foreign: true},
		{Start: 8, Length: 2, Source: -1},
	}
	require.Equal(t, want, snapshotParts(snapshot))
	restricted, ok := snapshot.ForOwner(ownerOf(1))
	require.True(t, ok)
	require.Equal(t, want, snapshotParts(restricted))

	// When the covers had no space, every byte that is not in a range of
	// the owner is foreign.
	collector = newCollector(nil)
	require.True(t, collector.add(value, constants.VulnerabilityTypeSqlInjection, resolved(0, 2, "a", 1)))
	for range MaxCollectedRanges {
		collector.addHidden(uint32(len(value)), 0, 5, 1)
	}
	require.True(t, collector.foreignOverflow)
	restricted, ok = collector.finish(value).ForOwner(ownerOf(1))
	require.True(t, ok)
	for _, part := range snapshotParts(restricted) {
		require.Equal(t, part.Source < 0, part.Foreign)
	}
}

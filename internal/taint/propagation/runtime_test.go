// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"runtime"
	"strings"
	"testing"
	"unsafe"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge/bridgetest"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

// These tests call the runtime bridge through its linker symbols, as the woven
// runtime does after the runtime function returned (plan runtime-operator-hooks,
// step 4). The results are fresh heap allocations that start at their base,
// as the runtime results are.

// runtimeScope begins a request scope, which binds the process store to the
// runtime bridge, and returns the bound store.
func runtimeScope(t *testing.T) *store.Store {
	t.Helper()
	s, _ := beginScope(t)
	require.True(t, runtimebridge.Bound())
	require.Same(t, s, store.RuntimeStore(), "the process store is the runtime store")
	return s
}

// freshString returns a new heap string with the concatenation of parts, as
// concatstrings does with a nil buffer.
//
//go:noinline
func freshString(parts ...string) string {
	b := freshBytes(parts...)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// freshBytes returns a new heap []byte with the concatenation of parts.
//
//go:noinline
func freshBytes(parts ...string) []byte {
	n := 0
	for _, part := range parts {
		n += len(part)
	}
	b := make([]byte, n)
	offset := 0
	for _, part := range parts {
		offset += copy(b[offset:], part)
	}
	return b
}

//go:noinline
func freshRunes(value string) []rune { return []rune(value) }

func rng(start, length uint32, source ranges.SourceID) ranges.Range {
	return ranges.Range{Start: start, Length: length, SourceID: source}
}

func lookupRunesRanges(s *store.Store, value []rune) []ranges.Range {
	key, ok := store.RunesKey(value)
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

// concat runs the result hook of concatstrings on a fresh result.
func concat(operands ...string) string {
	result := freshString(operands...)
	bridgetest.ConcatHook(result, operands)
	return result
}

func TestRuntimeConcatExactRanges(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	tainted, _ := taintString(t, owner, "attacker", []ranges.Range{rng(0, 8, 1)})
	other, _ := taintString(t, owner, "second-value", []ranges.Range{rng(0, 6, 2)})

	require.Equal(t, []ranges.Range{rng(4, 8, 1)}, lookupRanges(s, concat("id: ", tainted)), "a+b")
	require.Equal(t, []ranges.Range{rng(1, 8, 1)}, lookupRanges(s, concat("'", tainted, "'")), "a+b+c")
	result := concat("a", tainted, "b", other, "c", tainted)
	require.Equal(t, []ranges.Range{rng(1, 8, 1), rng(10, 6, 2), rng(23, 8, 1)}, lookupRanges(s, result), "6 operands")
	require.Equal(t, []ranges.Range{rng(0, 8, 1)}, lookupRanges(s, concat(tainted, "")), "s += \"\" keeps ranges")
	require.Equal(t, []ranges.Range{rng(0, 16, 1)}, lookupRanges(s, concat(tainted, tainted)), "adjacent ranges of one source merge")
	require.Nil(t, lookupRanges(s, concat("clean", "-value")), "clean operands")
}

func TestRuntimeConcatIdentityIsNotAdopted(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	tainted, _ := taintString(t, owner, "identity-value", []ranges.Range{rng(0, 5, 1)})
	window := tainted[3:10]
	roots := s.Stats().IndexedRoots
	// concatstrings returns the only non-empty operand.
	bridgetest.ConcatHook(tainted, []string{"", tainted})
	bridgetest.ConcatHook(window, []string{window, ""})
	require.Equal(t, roots, s.Stats().IndexedRoots, "the identity result is not a new root")
	require.Equal(t, []ranges.Range{rng(0, 2, 1)}, lookupRanges(s, window))
}

func TestRuntimeConcatScansEveryOperand(t *testing.T) {
	s := runtimeScope(t)
	for _, count := range []int{17, 40} {
		owner := acquireOwner(t, s)
		tainted, _ := taintString(t, owner, "late-operand", []ranges.Range{rng(0, 4, 7)})
		operands := make([]string, count)
		for i := range operands {
			operands[i] = "ab"
		}
		operands[count-1] = tainted
		result := concat(operands...)
		require.Equal(t, []ranges.Range{rng(uint32(2*(count-1)), 4, 7)}, lookupRanges(s, result), "a coarse range for %d operands", count)
		require.Equal(t, uint64(1), owner.Counters().Ranges, "the coarse range is a ranges drop")
	}
}

// ownerRanges returns the ranges of each owner of value, by owner ID.
func ownerRanges(t *testing.T, s *store.Store, value string) map[uint64][]ranges.Range {
	t.Helper()
	key, ok := store.StringKey(value)
	require.True(t, ok)
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	out := map[uint64][]ranges.Range{}
	for i := 0; i < snapshot.Len(); i++ {
		entry, ok := snapshot.At(i)
		require.True(t, ok)
		set := make([]ranges.Range, entry.Ranges.Len())
		entry.Ranges.CopyTo(set)
		out[entry.OwnerID] = set
	}
	return out
}

// TestRuntimeConcatCoarseKeepsOwnersApart checks that a coarse range of one
// owner never covers a byte that the owner does not taint (more than 16
// operands): not in an operand of a different owner, and not in a gap between
// two ranges of the owner in one operand.
func TestRuntimeConcatCoarseKeepsOwnersApart(t *testing.T) {
	s := runtimeScope(t)
	alpha, bravo := acquireOwner(t, s), acquireOwner(t, s)
	a, _ := taintString(t, alpha, "alpha-value", []ranges.Range{rng(1, 3, 1), rng(6, 2, 2)})
	b, _ := taintString(t, bravo, "bravo-value", []ranges.Range{rng(0, 5, 3)})
	var operands []string
	var wantA, wantB []ranges.Range
	offset := uint32(0)
	for range 5 {
		// The coarse ranges of an operand are the ranges of the owner in
		// the operand, with the source of the first range of the owner.
		wantA = append(wantA, rng(offset+1, 3, 1), rng(offset+6, 2, 1))
		wantB = append(wantB, rng(offset+uint32(len(a))+1, 5, 3))
		operands = append(operands, a, "|", b, "|")
		offset += uint32(len(a) + 1 + len(b) + 1)
	}
	require.Greater(t, len(operands), 16)
	result := concat(operands...)
	got := ownerRanges(t, s, result)
	require.Equal(t, map[uint64][]ranges.Range{alpha.ID(): wantA, bravo.ID(): wantB}, got)
	require.Equal(t, uint64(1), alpha.Counters().Ranges)
	require.Equal(t, uint64(1), bravo.Counters().Ranges)

	// Adjacent operands of one owner give one range.
	full, _ := taintString(t, bravo, "full", []ranges.Range{rng(0, 4, 4)})
	adjacent := make([]string, 17)
	for i := range adjacent {
		adjacent[i] = full
	}
	result = concat(adjacent...)
	require.Equal(t, []ranges.Range{rng(0, uint32(len(result)), 4)}, lookupRanges(s, result))

	// In a shared operand, alpha taints the two ends and bravo taints the
	// bytes between them. The ranges of alpha do not cover the bytes of bravo.
	ends, _ := taintString(t, alpha, "ends", []ranges.Range{rng(0, 4, 5)})
	middle, _ := taintString(t, bravo, "middle", []ranges.Range{rng(0, 6, 6)})
	shared := concat(ends, middle, ends)
	require.Equal(t, map[uint64][]ranges.Range{
		alpha.ID(): {rng(0, 4, 5), rng(10, 4, 5)},
		bravo.ID(): {rng(4, 6, 6)},
	}, ownerRanges(t, s, shared), "the exact shared operand")
	operands = []string{shared}
	for range 16 {
		operands = append(operands, "-")
	}
	require.Greater(t, len(operands), 16)
	result = concat(operands...)
	require.Equal(t, map[uint64][]ranges.Range{
		alpha.ID(): {rng(0, 4, 5), rng(10, 4, 5)},
		bravo.ID(): {rng(4, 6, 6)},
	}, ownerRanges(t, s, result), "the coarse ranges of the shared operand")
}

// TestRuntimeConcatCoarseRangeLimit checks that the coarse ranges of an owner
// stop at its range limit, with one ranges drop.
func TestRuntimeConcatCoarseRangeLimit(t *testing.T) {
	s := runtimeScope(t)
	for _, count := range []int{ranges.DefaultLimit, ranges.DefaultLimit + 1} {
		owner := acquireOwner(t, s)
		tainted, _ := taintString(t, owner, "tv", []ranges.Range{rng(0, 2, 1)})
		var operands []string
		var want []ranges.Range
		for i := range count {
			operands = append(operands, tainted, "-")
			if i < ranges.DefaultLimit {
				want = append(want, rng(uint32(3*i), 2, 1))
			}
		}
		require.Greater(t, len(operands), 16)
		result := concat(operands...)
		require.Equal(t, want, lookupRanges(s, result), "%d tainted operands", count)
		require.Equal(t, uint64(1), owner.Counters().Ranges, "%d tainted operands", count)
	}
}

// TestRuntimeConcatExactRangeLimit checks that an exact concatenation with
// more ranges than the range limit keeps the first ranges and records one
// ranges drop.
func TestRuntimeConcatExactRangeLimit(t *testing.T) {
	s := runtimeScope(t)
	sparse := func(n int) []ranges.Range {
		out := make([]ranges.Range, n)
		for i := range out {
			out[i] = rng(uint32(2*i), 1, 1)
		}
		return out
	}
	for _, test := range []struct {
		right int
		drop  uint64
	}{{4, 0}, {5, 1}} {
		owner := acquireOwner(t, s)
		left, _ := taintString(t, owner, "a.b.c.d.e.f.", sparse(6))
		right, _ := taintString(t, owner, "g.h.i.j.k.", sparse(test.right))
		result := concat(left, "|", right)
		got := lookupRanges(s, result)
		require.Len(t, got, ranges.DefaultLimit, "%d ranges", 6+test.right)
		require.Equal(t, rng(0, 1, 1), got[0])
		require.Equal(t, rng(uint32(len(left))+1+6, 1, 1), got[ranges.DefaultLimit-1])
		require.Equal(t, test.drop, owner.Counters().Ranges, "%d ranges", 6+test.right)
	}
}

// TestRuntimeResultAfterRefusedSecondBind checks the result part of plan
// section 9.1 item 6b: after a refused second binding, the result callbacks
// adopt results in the first store only.
func TestRuntimeResultAfterRefusedSecondBind(t *testing.T) {
	s := runtimeScope(t)
	second := store.New()
	require.False(t, second.BindRuntimeBridge(runtimebridge.Options{StringToSlice: true}), "a second binding is refused")
	require.Same(t, s, store.RuntimeStore())

	firstOwner := acquireOwner(t, s)
	tainted, _ := taintString(t, firstOwner, "first-store-value", []ranges.Range{rng(0, 5, 1)})
	result := concat("x", tainted)
	require.Equal(t, []ranges.Range{rng(1, 5, 1)}, lookupRanges(s, result), "the first store adopts the result")
	require.Nil(t, lookupRanges(second, result), "the second store does not adopt the result")
	bytesResult := freshBytes(tainted)
	bridgetest.ToBytes(bytesResult, tainted)
	require.Equal(t, []ranges.Range{rng(0, 5, 1)}, lookupByteRanges(s, bytesResult))
	require.Nil(t, lookupByteRanges(second, bytesResult), "the second store does not adopt the bytes result")

	secondOwner := second.Acquire()
	t.Cleanup(secondOwner.Finish)
	foreign, _, ok := secondOwner.TaintString(strings.Clone("second-store-value"), 1)
	require.True(t, ok)
	foreignResult := concat("x", foreign)
	require.Nil(t, lookupRanges(s, foreignResult), "the first store does not adopt it")
	require.Nil(t, lookupRanges(second, foreignResult), "the second store does not adopt it")
	foreignBytes := freshBytes(foreign)
	bridgetest.ToBytes(foreignBytes, foreign)
	require.Nil(t, lookupByteRanges(s, foreignBytes), "the first store does not adopt the bytes result")
	require.Nil(t, lookupByteRanges(second, foreignBytes), "the second store does not adopt the bytes result")
}

func TestRuntimeCallbacksAreRegistered(t *testing.T) {
	// The propagation package registers the callbacks in its init function.
	// Step 5 links it with the runtime aspect (plan section 3.2 rule 6).
	registered := runtimebridge.Register(nil)
	runtimebridge.Register(registered)
	require.NotNil(t, registered)
	require.NotNil(t, registered.Concat)
	require.NotNil(t, registered.ConcatBytes)
	require.NotNil(t, registered.FromBytes)
	require.NotNil(t, registered.ToBytes)
	require.NotNil(t, registered.FromRunes)
	require.NotNil(t, registered.ToRunes)
}

func TestRuntimeConcatFanout(t *testing.T) {
	s := runtimeScope(t)
	for _, extra := range []int{0, 17} {
		var owners [store.MaxSnapshotOwners + 1]*store.Owner
		operands := make([]string, 0, len(owners)+extra)
		for i := range owners {
			owners[i] = acquireOwner(t, s)
			value, _ := taintString(t, owners[i], "owner-value", []ranges.Range{rng(0, 5, ranges.SourceID(i+1))})
			operands = append(operands, value)
		}
		for range extra {
			operands = append(operands, "x")
		}
		result := concat(operands...)
		key, ok := store.StringKey(result)
		require.True(t, ok)
		var snapshot store.Snapshot
		require.True(t, s.Lookup(key, &snapshot))
		require.Equal(t, store.MaxSnapshotOwners, snapshot.Len(), "the result is shared by at most %d owners", store.MaxSnapshotOwners)
		require.Equal(t, uint64(1), owners[store.MaxSnapshotOwners].Counters().Fanout, "the fifth owner is a fanout drop")
	}
}

func TestRuntimeConcatTooLargeIsABytesDrop(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	tainted, _ := taintString(t, owner, "large-operand", []ranges.Range{rng(0, 5, 1)})
	padding := strings.Repeat("p", store.MaxRootBytes)
	result := concat(tainted, padding)
	require.Nil(t, lookupRanges(s, result))
	require.Equal(t, uint64(1), owner.Counters().Bytes)
}

func TestRuntimeConcatBytes(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	tainted, _ := taintString(t, owner, "bytes-operand", []ranges.Range{rng(0, 5, 1)})
	operands := []string{"[", tainted, "]"}
	result := freshBytes(operands...)
	bridgetest.ConcatBytesHook(result, operands)
	require.Equal(t, []ranges.Range{rng(1, 5, 1)}, lookupByteRanges(s, result), "[]byte(a+b)")
}

func TestRuntimeBytesToString(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	input := make([]byte, 16)
	copy(input, "0123456789abcdef")
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{rng(2, 4, 1)}, 16).Valid)
	_, ok := owner.AdoptBytes(input, &set)
	require.True(t, ok)

	result := freshString(string(input))
	bridgetest.BytesToString(result, input)
	require.Equal(t, []ranges.Range{rng(2, 4, 1)}, lookupRanges(s, result), "string(b)")

	window := input[4:10]
	result = freshString(string(window))
	bridgetest.BytesToString(result, window)
	require.Equal(t, []ranges.Range{rng(0, 2, 1)}, lookupRanges(s, result), "string(b[i:j])")

	one := freshString("2")
	bridgetest.BytesToString(one, input[2:3])
	require.Nil(t, lookupRanges(s, one), "a one-byte result is not tainted")
}

func TestRuntimeStringToBytes(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	tainted, _ := taintString(t, owner, "to-bytes-value", []ranges.Range{rng(3, 5, 1)})
	result := freshBytes(tainted)
	require.True(t, bridgetest.StrPre(tainted))
	bridgetest.ToBytes(result, tainted)
	require.Equal(t, []ranges.Range{rng(3, 5, 1)}, lookupByteRanges(s, result), "[]byte(s)")

	// The Q2 switch off (plan section 4.4): no pre-check hit and no taint.
	previous := bridgetest.SetS2SGate(0)
	t.Cleanup(func() { bridgetest.SetS2SGate(previous) })
	require.False(t, bridgetest.StrPre(tainted))
	off := freshBytes(tainted)
	bridgetest.ToBytes(off, tainted)
	require.Nil(t, lookupByteRanges(s, off))
	offRunes := freshRunes(tainted)
	bridgetest.ToRunes(offRunes, tainted)
	require.Nil(t, lookupRunesRanges(s, offRunes))
	// string(b) and concat still propagate.
	fromBytes := freshString(string(result))
	bridgetest.BytesToString(fromBytes, result)
	require.Equal(t, []ranges.Range{rng(3, 5, 1)}, lookupRanges(s, fromBytes))
	require.Equal(t, []ranges.Range{rng(4, 5, 1)}, lookupRanges(s, concat("x", tainted)))
}

func TestRuntimeRuneConversions(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	for _, test := range []struct {
		name      string
		value     string
		in        []ranges.Range
		runes     []ranges.Range
		roundTrip []ranges.Range
	}{
		{"ascii", "plain-ascii", []ranges.Range{rng(6, 5, 1)}, []ranges.Range{rng(24, 20, 1)}, []ranges.Range{rng(6, 5, 1)}},
		{"multi-byte", "héllo 世界", []ranges.Range{rng(7, 6, 1)}, []ranges.Range{rng(24, 8, 1)}, []ranges.Range{rng(7, 6, 1)}},
		{"inside a rune", "éé", []ranges.Range{rng(1, 2, 1)}, []ranges.Range{rng(0, 8, 1)}, []ranges.Range{rng(0, 4, 1)}},
		{"invalid", "a\xffb", []ranges.Range{rng(1, 1, 1)}, []ranges.Range{rng(4, 4, 1)}, []ranges.Range{rng(1, 3, 1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tainted, _ := taintString(t, owner, test.value, test.in)
			runes := freshRunes(tainted)
			bridgetest.ToRunes(runes, tainted)
			require.Equal(t, test.runes, lookupRunesRanges(s, runes), "[]rune(s)")
			result := freshString(string(runes))
			require.True(t, bridgetest.RunesPre(runes))
			bridgetest.FromRunes(result, runes)
			require.Equal(t, test.roundTrip, lookupRanges(s, result), "string([]rune(s))")
		})
	}

	// An interior window of a []rune root: string(rs[2:5]).
	tainted, _ := taintString(t, owner, "abcdefgh", []ranges.Range{rng(3, 2, 1)})
	runes := freshRunes(tainted)
	bridgetest.ToRunes(runes, tainted)
	window := runes[2:5]
	result := freshString(string(window))
	bridgetest.FromRunes(result, window)
	require.Equal(t, []ranges.Range{rng(1, 2, 1)}, lookupRanges(s, result))

	// Surrogates are encoded as utf8.RuneError (3 bytes).
	surrogates := []rune{'a', 0xD800, 'b'}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{rng(4, 4, 2)}, 12).Valid)
	_, ok := owner.AdoptRunes(surrogates, &set)
	require.True(t, ok)
	result = freshString(string(surrogates))
	bridgetest.FromRunes(result, surrogates)
	require.Equal(t, []ranges.Range{rng(1, 3, 2)}, lookupRanges(s, result))

	// 32 and 33 runes: the stack boundary of the runtime changes nothing here.
	for _, n := range []int{32, 33} {
		tainted, _ := taintString(t, owner, strings.Repeat("r", n), []ranges.Range{rng(0, uint32(n), 3)})
		runes := freshRunes(tainted)
		bridgetest.ToRunes(runes, tainted)
		require.Equal(t, []ranges.Range{rng(0, uint32(4*n), 3)}, lookupRunesRanges(s, runes))
	}
}

func TestRuntimeRuneLimitsAndCharge(t *testing.T) {
	s := runtimeScope(t)

	// []rune(s): 16 384 runes is the largest root (4*16 384 = MaxRootBytes).
	for _, test := range []struct {
		n    int
		want bool
	}{{16384, true}, {16385, false}} {
		owner := acquireOwner(t, s)
		tainted, _ := taintString(t, owner, strings.Repeat("a", 32), []ranges.Range{rng(0, 32, 1)})
		// A long input taints only its first bytes; the input need not be a root
		// of the same size.
		input := freshString(tainted, strings.Repeat("b", test.n-32))
		bridgetest.ConcatHook(input, []string{tainted, strings.Repeat("b", test.n-32)})
		if test.n > store.MaxRootBytes {
			continue
		}
		runes := freshRunes(input)
		bridgetest.ToRunes(runes, input)
		require.Equal(t, test.want, lookupRunesRanges(s, runes) != nil, "%d runes", test.n)
	}

	// string(rs): the charge is sizeClass(4*len(rs)+3), also when the result
	// is shorter than the encoded runes (the runes changed during the
	// conversion, plan section 4.5).
	owner := acquireOwner(t, s)
	runes := make([]rune, 1000)
	for i := range runes {
		runes[i] = 'a'
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{rng(0, 4000, 1)}, 4000).Valid)
	_, ok := owner.AdoptRunes(runes, &set)
	require.True(t, ok)
	before := owner.Charged()
	result := freshString(strings.Repeat("a", 900))
	bridgetest.FromRunes(result, runes)
	require.Equal(t, []ranges.Range{rng(0, 900, 1)}, lookupRanges(s, result))
	require.Equal(t, int64(4096), owner.Charged()-before, "sizeClass(4*1000+3)")

	// 16 383 runes is the largest string(rs) input: 4*16 383+3 <= MaxRootBytes.
	for _, test := range []struct {
		n    int
		want bool
	}{{16383, true}, {16384, false}} {
		owner := acquireOwner(t, s)
		runes := make([]rune, test.n)
		for i := range runes {
			runes[i] = 'z'
		}
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{rng(0, 8, 1)}, uint32(4*test.n)).Valid)
		_, ok := owner.AdoptRunes(runes, &set)
		require.True(t, ok)
		// strings.Repeat, not string(runes): a woven runtime hook would
		// also count a bytes drop for string(runes).
		result := freshString(strings.Repeat("z", test.n))
		bridgetest.FromRunes(result, runes)
		require.Equal(t, test.want, lookupRanges(s, result) != nil, "%d runes", test.n)
		if !test.want {
			require.Equal(t, uint64(1), owner.Counters().Bytes)
		}
	}

	// string(r) of one rune gives at most a 1-byte result from a one-rune
	// input here: not tainted (documented miss).
	one := freshString("a")
	bridgetest.FromRunes(one, runes[:1])
	require.Nil(t, lookupRanges(s, one))
}

func TestRuntimeCallbacksKeepResultsLive(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	tainted, _ := taintString(t, owner, "heap-retention", []ranges.Range{rng(0, 4, 1)})
	operands := []string{"<", tainted, ">"}
	backing := freshBytes(operands...)
	alive := weak.Make(&backing[0])
	result := unsafe.String(&backing[0], len(backing))
	bridgetest.ConcatHook(result, operands)
	key, ok := store.StringKey(result)
	require.True(t, ok)
	want := strings.Clone(result)
	backing, result = nil, "" // drop the last references
	runtime.GC()
	runtime.GC()
	data := alive.Value()
	require.NotNil(t, data, "the adopted root keeps the result allocation")
	require.Equal(t, want, unsafe.String(data, len(want)), "the root keeps the result data")
	var snapshot store.Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	entry, _ := snapshot.At(0)
	require.True(t, entry.WholeRoot)
	require.Equal(t, []ranges.Range{rng(1, 4, 1)}, func() []ranges.Range {
		out := make([]ranges.Range, entry.Ranges.Len())
		entry.Ranges.CopyTo(out)
		return out
	}())
}

func TestRuntimeCallbackPanicIsRecovered(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	tainted, _ := taintString(t, owner, "panic-value", []ranges.Range{rng(0, 5, 1)})
	panicking := &runtimebridge.Callbacks{
		Concat: func(string, []string) { panic("callback failure") },
	}
	previous := runtimebridge.Register(panicking)
	before := runtimebridge.Snapshot().HookPanics
	result := concat("x", tainted)
	runtimebridge.Register(previous)
	require.Equal(t, before+1, runtimebridge.Snapshot().HookPanics)
	require.Nil(t, lookupRanges(s, result))
	require.Equal(t, []ranges.Range{rng(1, 5, 1)}, lookupRanges(s, concat("x", tainted)), "the next call runs normally")
}

func TestRuntimeCleanPathsDoNotAllocate(t *testing.T) {
	s := runtimeScope(t)
	owner := acquireOwner(t, s)
	taintString(t, owner, "unrelated-root", []ranges.Range{rng(0, 5, 1)})
	clean := freshString("clean-operand")
	operands := []string{"a", clean, "b"}
	result := freshString("a", clean, "b")
	bytesResult := freshBytes("a", clean, "b")
	runes := freshRunes(clean)
	require.Zero(t, testing.AllocsPerRun(1000, func() {
		bridgetest.ConcatPre(operands)
		bridgetest.ConcatHook(result, operands)
		bridgetest.ConcatBytesHook(bytesResult, operands)
		bridgetest.StrPre(clean)
		bridgetest.ToBytes(bytesResult, clean)
		bridgetest.BytesToString(result, bytesResult)
		bridgetest.RunesPre(runes)
		bridgetest.FromRunes(result, runes)
		bridgetest.ToRunes(runes, clean)
	}))
}

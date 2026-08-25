// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestLayoutBounds(t *testing.T) {
	t.Logf("slot=%d root=%d owner=%d store=%d binding=%d", unsafe.Sizeof(valueSlot{}), unsafe.Sizeof(rootRecord{}), unsafe.Sizeof(owner{}), unsafe.Sizeof(Store{}), unsafe.Sizeof(binding{}))
	require.Equal(t, uintptr(32), unsafe.Sizeof(valueSlot{}))
	require.LessOrEqual(t, unsafe.Sizeof(rootRecord{}), uintptr(320))
	require.LessOrEqual(t, unsafe.Sizeof(Store{}), uintptr(14<<20), "fixed store must leave room for 8 MiB roots under the 24 MiB ceiling")
}

func TestTaintLookupFinish(t *testing.T) {
	store := New()
	owner := store.Acquire()
	require.False(t, owner.Disabled())
	managed, root, ok := owner.TaintString("attacker-input", 0)
	require.True(t, ok)
	require.NotEqual(t, "", managed)
	require.NotZero(t, root.Generation)

	key, ok := StringKey(managed)
	require.True(t, ok)
	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	require.Equal(t, 1, snapshot.Len())
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: uint32(len(managed)), SourceID: 0}}, rangeSlice(&entry.Ranges))

	owner.Finish()
	require.Zero(t, owner.Charged())
	require.Zero(t, store.ProcessCharged())
	require.Zero(t, store.ProcessValues())
	require.True(t, store.Lookup(key, &snapshot))
	require.Zero(t, snapshot.Len())
}

func TestDerivedSubstringUsesOneRoot(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintString("0123456789abcdef", 0)
	require.True(t, ok)
	charged := owner.Charged()

	substring := managed[4:12]
	key, ok := StringKey(substring)
	require.True(t, ok)
	require.True(t, owner.Derive(key, root))
	require.Equal(t, charged, owner.Charged())

	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 8, SourceID: 0}}, rangeSlice(&entry.Ranges))
	owner.Finish()
}

func TestOneByteValuesAreExcluded(t *testing.T) {
	store := New()
	owner := store.Acquire()
	value := "x"
	managed, _, ok := owner.TaintString(value, 0)
	require.False(t, ok)
	require.Equal(t, value, managed)
	managedBytes, _, ok := owner.TaintBytes([]byte{'x'}, 0)
	require.False(t, ok)
	require.Equal(t, []byte{'x'}, managedBytes)
	require.Equal(t, uint64(2), owner.Counters().OneByte)
	owner.Finish()
}

func TestOwnerCapacityAndStaleHandle(t *testing.T) {
	store := New()
	owners := make([]*Owner, MaxOwners)
	for i := range owners {
		owners[i] = store.Acquire()
		require.False(t, owners[i].Disabled())
	}
	require.True(t, store.Acquire().Disabled())
	require.Equal(t, uint64(1), store.AcquireDrops())
	stale := owners[0]
	oldGeneration := stale.Generation()
	stale.Finish()
	reused := store.Acquire()
	require.False(t, reused.Disabled())
	require.NotEqual(t, oldGeneration, reused.Generation())
	_, _, ok := stale.TaintString("must-not-write", 0)
	require.False(t, ok)
	stale.Finish()
	_, _, ok = reused.TaintString("new-generation", 0)
	require.True(t, ok)
	for _, owner := range owners[1:] {
		owner.Finish()
	}
	reused.Finish()
}

func TestTenRangesGuaranteedAndOverflowBestEffort(t *testing.T) {
	store := New()
	owner := store.Acquire()
	makeSet := func(count int) (string, ranges.Set) {
		value := strings.Clone(strings.Repeat("ab", count))
		raw := make([]ranges.Range, count)
		for i := range raw {
			raw[i] = ranges.Range{Start: uint32(i * 2), Length: 1, SourceID: ranges.SourceID(i)}
		}
		var set ranges.Set
		require.True(t, ranges.AdoptCanonical(&set, 64, raw, uint32(len(value))).Valid)
		return value, set
	}

	for i := 0; i < OverflowBlocks; i++ {
		value, set := makeSet(11)
		value = strings.Clone(fmt.Sprintf("%04d", i) + value)
		shifted := make([]ranges.Range, set.Len())
		set.CopyTo(shifted)
		for j := range shifted {
			shifted[j].Start += 4
		}
		require.True(t, ranges.AdoptCanonical(&set, 64, shifted, uint32(len(value))).Valid)
		_, ok := owner.AdoptString(value, &set)
		require.True(t, ok)
	}
	value, set := makeSet(11)
	root, ok := owner.AdoptString(value, &set)
	require.True(t, ok)
	key, _ := StringKey(value)
	var snapshot Snapshot
	require.True(t, store.Lookup(key, &snapshot))
	entry, ok := snapshot.At(0)
	require.True(t, ok)
	require.Equal(t, GuaranteedRanges, entry.Ranges.Len(), "overflow exhaustion must still preserve ten ranges")
	require.NotZero(t, root.Generation)
	require.Greater(t, owner.Counters().Ranges, uint64(0))
	owner.Finish()
	require.Equal(t, uint16(OverflowBlocks), store.overflowN)
}

func TestTypedObjectBinding(t *testing.T) {
	type object struct{ value int }
	store := New()
	owner := store.Acquire()
	objectValue := &object{value: 42}
	require.True(t, BindObject(owner, objectValue, BindingReader))
	var refs [2]OwnerRef
	n := LookupObject(store, objectValue, refs[:])
	require.Equal(t, 1, n)
	handle, valid := refs[0].Handle()
	require.True(t, valid)
	require.Equal(t, owner.ID(), handle.ID())
	require.Equal(t, BindingReader, refs[0].Kind)
	allocations := testing.AllocsPerRun(100, func() {
		if LookupObject(store, objectValue, refs[:]) != 1 {
			panic("binding disappeared")
		}
	})
	require.Zero(t, allocations)
	owner.Finish()
	_, valid = refs[0].Handle()
	require.False(t, valid)
	require.Zero(t, LookupObject(store, objectValue, refs[:]))
}

func rangeSlice(set *ranges.Set) []ranges.Range {
	result := make([]ranges.Range, set.Len())
	set.CopyTo(result)
	return result
}

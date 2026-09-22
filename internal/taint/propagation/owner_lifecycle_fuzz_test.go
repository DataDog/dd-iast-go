// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

func FuzzOwnerLifecycle(f *testing.F) {
	f.Add([]byte("finish-reuse-admit-drop"))
	f.Add([]byte{0xff, 0x80, 'a', 'a', 0xc3, 0xa9})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > sequenceMaxInput {
			encoded = encoded[:sequenceMaxInput]
		}
		taintStore, _ := beginScope(t)
		cursor := newSequenceCursor(encoded)
		baselineCharge := taintStore.ProcessCharged()
		baselineValues := taintStore.ProcessValues()
		cycles := 1 + cursor.indexOf(sequenceSteps)
		for cycle := 0; cycle < cycles; cycle++ {
			runOwnerLifecycleCycle(t, taintStore, cursor, cycle)
			if got := taintStore.ProcessCharged(); got != baselineCharge {
				t.Fatalf("cycle %d retained charge: got=%d want=%d", cycle, got, baselineCharge)
			}
			if got := taintStore.ProcessValues(); got != baselineValues {
				t.Fatalf("cycle %d retained values: got=%d want=%d", cycle, got, baselineValues)
			}
		}
	})
}

func runOwnerLifecycleCycle(t *testing.T, taintStore *store.Store, cursor *sequenceCursor, cycle int) {
	t.Helper()
	owner := taintStore.Acquire()
	if owner.Disabled() {
		t.Fatal("primary lifecycle owner admission unexpectedly failed")
	}
	t.Cleanup(owner.Finish)
	oldIndex, ok := owner.Index()
	if !ok {
		t.Fatal("primary lifecycle owner has no slot index")
	}
	oldID, oldGeneration := owner.ID(), owner.Generation()

	managed, expected := admitLifecycleString(t, owner, cursor, cycle, 1)
	assertLifecycleRanges(t, taintStore, owner, managed, expected)
	nativeCopy := strings.Clone(managed)
	copied := propagation.CopyString(managed, nativeCopy)
	if copied != nativeCopy {
		t.Fatalf("lifecycle copy changed native value: got=%q want=%q", copied, nativeCopy)
	}
	assertLifecycleRanges(t, taintStore, owner, copied, expected)

	beforeDrop := owner.Counters().OneByte
	oneByte, reference, admitted := owner.TaintString("x", 2)
	if admitted || oneByte != "x" || reference != (store.RootRef{}) {
		t.Fatalf("one-byte root was not deterministically dropped: admitted=%v value=%q ref=%v", admitted, oneByte, reference)
	}
	if got := owner.Counters().OneByte; got != beforeDrop+1 {
		t.Fatalf("one-byte drop counter differs: got=%d want=%d", got, beforeDrop+1)
	}

	var sibling *store.Owner
	if cursor.next()&1 != 0 {
		sibling = taintStore.Acquire()
		if sibling.Disabled() {
			t.Fatal("secondary lifecycle owner admission unexpectedly failed")
		}
		t.Cleanup(sibling.Finish)
		siblingValue, siblingRanges := admitLifecycleString(t, sibling, cursor, cycle, 17)
		assertLifecycleRanges(t, taintStore, sibling, siblingValue, siblingRanges)
	}

	owner.Finish()
	assertLifecycleValueReleased(t, taintStore, managed)
	var staleSet ranges.Set
	if !ranges.AdoptCanonical(&staleSet, ranges.DefaultLimit, expected, uint32(len(managed))).Valid {
		t.Fatalf("stale admission fixture is invalid: %v", expected)
	}
	if _, admitted = owner.AdoptString(strings.Clone(managed), &staleSet); admitted {
		t.Fatal("finished owner admitted a new root")
	}

	reused := taintStore.Acquire()
	if reused.Disabled() {
		t.Fatal("reused lifecycle owner admission unexpectedly failed")
	}
	t.Cleanup(reused.Finish)
	reusedIndex, ok := reused.Index()
	if !ok {
		t.Fatal("reused lifecycle owner has no slot index")
	}
	if reusedIndex != oldIndex {
		t.Fatalf("finished slot was not reused: got=%d want=%d", reusedIndex, oldIndex)
	}
	if reused.ID() == oldID || reused.Generation() == oldGeneration {
		t.Fatalf(
			"slot reuse did not advance identity: old=(%d,%d) new=(%d,%d)",
			oldID,
			oldGeneration,
			reused.ID(),
			reused.Generation(),
		)
	}

	reusedValue, reusedRanges := admitLifecycleString(t, reused, cursor, cycle, 33)
	assertLifecycleRanges(t, taintStore, reused, reusedValue, reusedRanges)
	staleNative := strings.Clone(managed)
	staleOut := propagation.CopyString(managed, staleNative)
	if staleOut != staleNative {
		t.Fatalf("stale copy changed native value: got=%q want=%q", staleOut, staleNative)
	}
	assertLifecycleValueReleased(t, taintStore, staleOut)

	reused.Finish()
	if sibling != nil {
		sibling.Finish()
	}
}

func admitLifecycleString(
	t *testing.T,
	owner *store.Owner,
	cursor *sequenceCursor,
	cycle int,
	sourceOffset int,
) (string, []ranges.Range) {
	t.Helper()
	raw := make([]byte, 2+cursor.indexOf(63))
	for index := range raw {
		raw[index] = cursor.next()
	}
	raw[0] = byte(cycle)
	raw[1] = 0xff
	managed := strings.Clone(string(raw))
	start := cursor.indexOf(len(managed))
	length := 1 + cursor.indexOf(len(managed)-start)
	expected := []ranges.Range{{
		Start:    uint32(start),
		Length:   uint32(length),
		SourceID: ranges.SourceID((sourceOffset + cycle) % 64),
		Marks:    []uint64{0xe, 0xc, 0xa, 0x6}[cursor.indexOf(4)],
	}}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.DefaultLimit, expected, uint32(len(managed))).Valid {
		t.Fatalf("lifecycle admission ranges are invalid: %v", expected)
	}
	if _, ok := owner.AdoptString(managed, &set); !ok {
		t.Fatal("valid lifecycle root admission failed")
	}
	return managed, expected
}

func assertLifecycleRanges(
	t *testing.T,
	taintStore *store.Store,
	owner *store.Owner,
	value string,
	expected []ranges.Range,
) {
	t.Helper()
	key, ok := store.StringKey(value)
	if !ok {
		t.Fatalf("lifecycle value has no store key: %q", value)
	}
	var snapshot store.Snapshot
	if !taintStore.Lookup(key, &snapshot) {
		t.Fatal("lifecycle lookup unexpectedly contended")
	}
	ownerIndex, ok := owner.Index()
	if !ok {
		t.Fatal("lifecycle owner has no slot index")
	}
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, available := snapshot.At(entryIndex)
		if !available {
			t.Fatalf("lifecycle snapshot entry %d is unavailable", entryIndex)
		}
		if entry.OwnerIndex != ownerIndex || entry.OwnerGen != owner.Generation() || entry.OwnerID != owner.ID() {
			continue
		}
		actual := make([]ranges.Range, entry.Ranges.Len())
		entry.Ranges.CopyTo(actual)
		if !slices.Equal(expected, actual) {
			t.Fatalf("lifecycle ranges differ: expected=%v actual=%v", expected, actual)
		}
		return
	}
	t.Fatalf("lifecycle value is missing owner contribution: expected=%v", expected)
}

func assertLifecycleValueReleased(t *testing.T, taintStore *store.Store, value string) {
	t.Helper()
	key, ok := store.StringKey(value)
	if !ok {
		return
	}
	var snapshot store.Snapshot
	if !taintStore.Lookup(key, &snapshot) {
		t.Fatal("released-value lookup unexpectedly contended")
	}
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, available := snapshot.At(entryIndex)
		if available && entry.Ranges.Len() != 0 {
			t.Fatalf("released lifecycle value retained ranges at entry %d", entryIndex)
		}
	}
}

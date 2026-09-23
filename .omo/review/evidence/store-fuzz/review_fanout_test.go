// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// Review reproducer (store-fuzz-F1): stale same-key slots are counted against
// MaxSnapshotOwners before they are validated, so a live owner can be hidden
// even when no more than MaxSnapshotOwners live owners hold the key.
func TestReviewStaleSlotsConsumeLookupFanout(t *testing.T) {
	s := New()
	buf := make([]byte, 32)
	owners := make([]*Owner, 5)
	for i := range owners {
		owners[i] = s.Acquire()
		var set ranges.Set
		if !ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: 32, SourceID: ranges.SourceID(i)}}, 32).Valid {
			t.Fatal("set")
		}
		if _, ok := owners[i].AdoptBytes(buf, &set); !ok {
			t.Fatalf("adopt %d", i)
		}
	}
	key, _ := BytesKey(buf)
	var snap Snapshot
	s.Lookup(key, &snap)
	t.Logf("5 live owners: visible=%d (documented fanout cap %d)", snap.Len(), MaxSnapshotOwners)
	owners[0].Finish()
	s.Lookup(key, &snap)
	live := make([]uint64, 0, 4)
	for _, o := range owners[1:] {
		live = append(live, o.ID())
	}
	visible := make([]uint64, 0, 4)
	for i := 0; i < snap.Len(); i++ {
		e, _ := snap.At(i)
		visible = append(visible, e.OwnerID)
	}
	t.Logf("after finishing owner 1: live owners=%v visible=%v", live, visible)
	if snap.Len() != 4 {
		t.Errorf("BUG: %d live owners (<= MaxSnapshotOwners) hold the key but Lookup returned %d; the stale slot consumed a fanout window", len(live), snap.Len())
	}
	for _, o := range owners[1:] {
		o.Finish()
	}
}

// Review reproducer (store-fuzz-F2): a window that falls entirely in an
// untainted gap of its root still yields a Lookup entry with zero ranges.
func TestReviewEmptyRangeEntry(t *testing.T) {
	s := New()
	o := s.Acquire()
	defer o.Finish()
	value := string([]byte("0123456789"))
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, 10, []ranges.Range{{Start: 0, Length: 2, SourceID: 1}}, 10).Valid {
		t.Fatal("set")
	}
	root, ok := o.AdoptString(value, &set)
	if !ok {
		t.Fatal("adopt")
	}
	gap := value[5:8]
	key, _ := StringKey(gap)
	if !o.Derive(key, root) {
		t.Fatal("derive")
	}
	var snap Snapshot
	s.Lookup(key, &snap)
	if snap.Len() == 0 {
		t.Fatal("no entry")
	}
	e, _ := snap.At(0)
	t.Logf("untainted gap window: snapshot.Len()=%d entry.Ranges.Len()=%d MayContain=%v", snap.Len(), e.Ranges.Len(), s.MayContain(key))
	if e.Ranges.Len() == 0 {
		t.Errorf("OBSERVED: Lookup returns an owner entry with zero ranges; propagation callers gate on snapshot.Len() and will clone/charge a zero-provenance root")
	}
}

package store

import "testing"

func independentWindowForSlot(buf []byte, wanted uint8) (Key, bool) {
	for length := 2; length <= 64; length++ {
		for offset := 0; offset+length <= len(buf); offset++ {
			key, ok := BytesKey(buf[offset : offset+length])
			if !ok {
				continue
			}
			hash := keyHash(key)
			if shardIndex(hash) == 0 && initialSlot(hash) == wanted {
				return key, true
			}
		}
	}
	return Key{}, false
}

func independentShardState(store *Store) (live, tombstones, empty int) {
	shard := &store.shards[0]
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	for _, slot := range shard.slots {
		switch slot.pointer {
		case 0:
			empty++
		case tombstone:
			tombstones++
		default:
			live++
		}
	}
	return
}

// TestIndependentShardWedge verifies the observable store behavior using only
// TaintBytes and Derive: stale entries are reclaimed but never create an empty
// slot, so no later shard-0 key can be inserted or trigger compaction.
func TestIndependentShardWedge(t *testing.T) {
	store := New()
	first := store.Acquire()
	firstBytes, firstRoot, ok := first.TaintBytes(make([]byte, MaxRootBytes), 1)
	if !ok {
		t.Fatal("first root was not tainted")
	}

	for slot := uint8(0); ; slot++ {
		key, found := independentWindowForSlot(firstBytes, slot)
		if !found {
			t.Fatalf("no shard-0 window found for initial slot %d", slot)
		}
		if !first.Derive(key, firstRoot) {
			t.Fatalf("failed to populate initial slot %d", slot)
		}
		if slot == SlotsPerShard-1 {
			break
		}
	}
	_, _, empty := independentShardState(store)
	if empty != 0 {
		t.Fatalf("shard 0 was not full: empty=%d", empty)
	}
	first.Finish()

	second := store.Acquire()
	var secondBytes []byte
	var secondRoot RootRef
	for attempts := 0; attempts < MaxRootsPerOwner; attempts++ {
		secondBytes, secondRoot, ok = second.TaintBytes(make([]byte, MaxRootBytes), 2)
		if ok {
			break
		}
	}
	if !ok {
		t.Fatal("could not create a control root outside the wedged shard")
	}

	attemptedSlots := [...]uint8{0, 64, 32}
	accepted := make([]bool, 0, len(attemptedSlots))
	for _, slot := range attemptedSlots {
		key, found := independentWindowForSlot(secondBytes, slot)
		if !found {
			t.Fatalf("no new-owner shard-0 window found for initial slot %d", slot)
		}
		accepted = append(accepted, second.Derive(key, secondRoot))
	}
	live, tombstones, empty := independentShardState(store)
	t.Logf("independent wedge: attempted initial slots %v accepted=%v; shard0 live=%d tombstones=%d empty=%d compactions=%d",
		attemptedSlots, accepted, live, tombstones, empty, store.Stats().Compactions)
	if accepted[0] || accepted[1] || accepted[2] {
		t.Fatalf("a post-finish shard-0 window unexpectedly published: accepted=%v", accepted)
	}
	t.Fatalf("shard 0 remains permanently wedged after finished owners")
}

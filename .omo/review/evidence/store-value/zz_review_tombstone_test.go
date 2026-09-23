package store

import (
	"testing"
)

// findKeys returns up to n distinct 2..40-byte window keys inside value whose
// real (non-forced) hash lands on shard 0 and initial slot == wantStart.
func reviewFindKeys(value []byte, wantStart uint8, n int) []Key {
	var out []Key
	for length := 2; length <= 40 && len(out) < n; length++ {
		for offset := 0; offset+length <= len(value) && len(out) < n; offset++ {
			key, ok := BytesKey(value[offset : offset+length])
			if !ok {
				continue
			}
			h := keyHash(key)
			if shardIndex(h) == 0 && initialSlot(h) == wantStart {
				out = append(out, key)
			}
		}
	}
	return out
}

func TestReviewTombstonedProbeWindowDropsWithFreeCapacity(t *testing.T) {
	s := New()

	// Owner A fills slots 0..63 of shard 0 with windows whose real hash starts at slot 0.
	a := s.Acquire()
	aManaged, aRoot, ok := a.TaintBytes(make([]byte, 60000), 1)
	if !ok {
		t.Fatal("A root")
	}
	aKeys := reviewFindKeys(aManaged, 0, ProbeLimit+1)
	if len(aKeys) < ProbeLimit+1 {
		t.Skipf("only %d keys found", len(aKeys))
	}
	derived := 0
	for _, key := range aKeys[:ProbeLimit] {
		if a.Derive(key, aRoot) {
			derived++
		}
	}
	t.Logf("owner A derived %d/%d start-0 windows in shard 0", derived, ProbeLimit)
	t.Logf("owner A 65th start-0 window accepted=%v (expected false: window genuinely full of live slots)", a.Derive(aKeys[ProbeLimit], aRoot))
	a.Finish()
	t.Logf("after A.Finish: ProcessValues=%d", s.ProcessValues())

	// Owner B: the store holds no live values in shard 0, yet B cannot insert.
	b := s.Acquire()
	bManaged, bRoot, ok := b.TaintBytes(make([]byte, 60000), 2)
	if !ok {
		t.Fatal("B root")
	}
	bKeys := reviewFindKeys(bManaged, 0, 3)
	before := b.Counters().Full
	results := []bool{}
	for _, key := range bKeys {
		results = append(results, b.Derive(key, bRoot))
	}
	stats := s.Stats()
	t.Logf("owner B start-0 derives=%v fullDrops=%d tombstones=%d maxTombstones=%d processValues=%d",
		results, b.Counters().Full-before, stats.Tombstones, stats.MaxTombstones, s.ProcessValues())

	// Healing only happens when an unrelated key in the same shard reaches an empty slot.
	heal := reviewFindKeys(bManaged, 100, 1)
	if len(heal) == 1 {
		t.Logf("unrelated start-100 derive=%v compactions=%d", b.Derive(heal[0], bRoot), s.Stats().Compactions)
		t.Logf("retry start-0 derive after compaction=%v", b.Derive(bKeys[0], bRoot))
	}
	b.Finish()
	for _, ok := range results {
		if !ok {
			t.Errorf("BUG: window insert dropped as full although every slot in its probe window is a tombstone")
			break
		}
	}
}

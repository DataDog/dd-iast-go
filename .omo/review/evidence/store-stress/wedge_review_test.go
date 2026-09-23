package store

import (
	"fmt"
	"os"
	"strconv"
	"testing"
)

// shard0Windows returns derived windows of buf whose keys land in shard 0, one
// per initial slot when possible (bySlot[j] has initialSlot == j).
func shard0Windows(buf []byte) (bySlot [SlotsPerShard]Key, any []Key) {
	base := uintptr(0)
	if len(buf) > 0 {
		k, _ := BytesKey(buf)
		base = k.Pointer
	}
	for length := 2; length <= 64; length++ {
		for off := 0; off+length <= len(buf); off++ {
			key := Key{Pointer: base + uintptr(off), Length: uint32(length), Kind: KindBytes}
			hash := keyHash(key)
			if shardIndex(hash) != 0 {
				continue
			}
			slot := initialSlot(hash)
			if bySlot[slot].Pointer == 0 {
				bySlot[slot] = key
			} else if len(any) < 512 {
				any = append(any, key)
			}
		}
	}
	return bySlot, any
}

func shardOccupancy(s *Store, index int) (live, tomb, empty int) {
	sh := &s.shards[index]
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	for i := range sh.slots {
		switch sh.slots[i].pointer {
		case 0:
			empty++
		case tombstone:
			tomb++
		default:
			live++
		}
	}
	return
}

// TestReviewShardWedgeAfterOwnerFinish shows that once every slot of a shard is
// occupied, finishing the owners does not free the shard: putWindow converts
// the stale slots it probes into tombstones, finds no empty slot within
// ProbeLimit, and fails. compact only runs after a successful insert, so no
// later owner can ever publish a key hashing to that shard again.
func TestReviewShardWedgeAfterOwnerFinish(t *testing.T) {
	s := New()
	a := s.Acquire()
	bufA, refA, ok := a.TaintBytes(make([]byte, MaxRootBytes), 1)
	if !ok {
		t.Fatal("TaintBytes A failed")
	}
	bySlot, _ := shard0Windows(bufA)
	inserted := 0
	for _, key := range bySlot {
		if key.Pointer != 0 && a.Derive(key, refA) {
			inserted++
		}
	}
	live, tomb, empty := shardOccupancy(s, 0)
	t.Logf("owner A derived %d shard-0 windows: live=%d tomb=%d empty=%d values=%d", inserted, live, tomb, empty, a.Values())
	if empty != 0 {
		t.Skipf("could not fill shard 0 (empty=%d)", empty)
	}
	a.Finish()
	compactionsBefore := s.compactions.Load()

	for round := 0; round < 3; round++ {
		b := s.Acquire()
		bufB, refB, ok := b.TaintBytes(make([]byte, MaxRootBytes), 2)
		if !ok {
			t.Fatal("TaintBytes B failed")
		}
		bySlotB, extraB := shard0Windows(bufB)
		okShard0, failShard0 := 0, 0
		for _, key := range append(bySlotB[:], extraB...) {
			if key.Pointer == 0 {
				continue
			}
			if b.Derive(key, refB) {
				okShard0++
			} else {
				failShard0++
			}
		}
		// Control: windows landing in other shards still succeed.
		okOther := 0
		for off := 0; off < 200; off++ {
			key, _ := BytesKey(bufB[off : off+3])
			if shardIndex(keyHash(key)) != 0 && b.Derive(key, refB) {
				okOther++
			}
		}
		// Real source values: every clone whose key hashes to shard 0 is dropped.
		srcShard0, srcShard0OK := 0, 0
		for i := 0; i < 20000 && srcShard0 < 50; i++ {
			v, _, ok := b.TaintString(fmt.Sprintf("header-value-%06d", i), 3)
			key, _ := StringKey(v)
			if shardIndex(keyHash(key)) == 0 {
				srcShard0++
				if ok {
					srcShard0OK++
				}
			}
		}
		live, tomb, empty = shardOccupancy(s, 0)
		t.Logf("round %d (owner B%d): shard-0 derives ok=%d fail=%d; other-shard derives ok=%d; shard-0 TaintString ok=%d/%d; shard0 live=%d tomb=%d empty=%d compactions=%d->%d full-drops=%d",
			round, round, okShard0, failShard0, okOther, srcShard0OK, srcShard0, live, tomb, empty, compactionsBefore, s.compactions.Load(), b.Counters().Full)
		if okShard0 != 0 || srcShard0OK != 0 {
			b.Finish()
			return // shard recovered: no wedge
		}
		b.Finish()
	}
	t.Errorf("shard 0 permanently wedged: no key hashing to it can be published after its occupants finished (Stats=%+v)", s.Stats())
}

// TestReviewOrganicShardSaturation measures whether ordinary saturating
// request waves (no crafted addresses) drive any shard to full occupancy.
func TestReviewOrganicShardSaturation(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	s := New()
	var worstFull, worstOcc int
	totalFailBelowLimit := uint64(0)
	waves, nOwners := 60, 4
	if v, err := strconv.Atoi(os.Getenv("ORGANIC_WAVES")); err == nil {
		waves = v
	}
	if v, err := strconv.Atoi(os.Getenv("ORGANIC_OWNERS")); err == nil {
		nOwners = v
	}
	firstFullWave := -1
	for wave := 0; wave < waves; wave++ {
		owners := make([]*Owner, nOwners)
		keep := make([][]string, nOwners)
		for i := range owners {
			owners[i] = s.Acquire()
			o := owners[i]
			for r := 0; r < MaxRootsPerOwner && o.Values() < RequestValueLimit-8; r++ {
				v, ref, ok := o.TaintString(fmt.Sprintf("w%03d-o%d-r%03d-%s", wave, i, r, "payload-data-0123456789"), 1)
				if !ok {
					continue
				}
				keep[i] = append(keep[i], v)
				for d := 1; d < 8 && d+2 <= len(v); d++ {
					sub := v[d : d+2+d%5]
					if key, ok := StringKey(sub); ok {
						o.Derive(key, ref)
					}
				}
			}
			totalFailBelowLimit += o.Counters().Full
		}
		full, occ := 0, 0
		for si := range s.shards {
			live, tomb, empty := shardOccupancy(s, si)
			if empty == 0 {
				full++
			}
			occ = max(occ, live+tomb)
		}
		if full > 0 && firstFullWave < 0 {
			firstFullWave = wave
		}
		worstFull = max(worstFull, full)
		worstOcc = max(worstOcc, occ)
		for _, o := range owners {
			o.Finish()
		}
		_ = keep
	}
	st := s.Stats()
	t.Logf("organic: waves=%d owners=%d firstFullWave=%d worst fully-occupied shards=%d worst max occupancy=%d/%d full-drops=%d stats=%+v", waves, nOwners, firstFullWave, worstFull, worstOcc, SlotsPerShard, totalFailBelowLimit, st)
}

// TestReviewOrganicRollingSaturation keeps nOwners saturated owners alive at all
// times, finishing the oldest and starting a new one each step, so stale slots
// of finished owners coexist with a near-full live index.
func TestReviewOrganicRollingSaturation(t *testing.T) {
	steps, nOwners := 300, 4
	if v, err := strconv.Atoi(os.Getenv("ORGANIC_WAVES")); err == nil {
		steps = v
	}
	if v, err := strconv.Atoi(os.Getenv("ORGANIC_OWNERS")); err == nil {
		nOwners = v
	}
	s := New()
	fill := func(step int) *Owner {
		o := s.Acquire()
		for r := 0; r < MaxRootsPerOwner && o.Values() < RequestValueLimit-8; r++ {
			v, ref, ok := o.TaintString(fmt.Sprintf("s%05d-r%03d-%s", step, r, "payload-data-0123456789"), 1)
			if !ok {
				continue
			}
			for d := 1; d < 8 && d+2 <= len(v); d++ {
				if key, ok := StringKey(v[d : d+2+d%5]); ok {
					o.Derive(key, ref)
				}
			}
		}
		return o
	}
	live := make([]*Owner, 0, nOwners)
	worstOcc, fullShards, firstFull := 0, 0, -1
	for step := 0; step < steps; step++ {
		if len(live) == nOwners {
			live[0].Finish()
			live = live[1:]
		}
		live = append(live, fill(step))
		full := 0
		for si := range s.shards {
			l, tb, e := shardOccupancy(s, si)
			worstOcc = max(worstOcc, l+tb)
			if e == 0 {
				full++
			}
		}
		if full > 0 && firstFull < 0 {
			firstFull = step
		}
		fullShards = max(fullShards, full)
	}
	for _, o := range live {
		o.Finish()
	}
	wedged := 0
	for si := range s.shards {
		if _, _, e := shardOccupancy(s, si); e == 0 {
			wedged++
		}
	}
	t.Logf("rolling: steps=%d owners=%d worstOcc=%d/%d maxFullShards=%d firstFullStep=%d wedgedAfterDrain=%d stats=%+v", steps, nOwners, worstOcc, SlotsPerShard, fullShards, firstFull, wedged, s.Stats())
	if wedged > 0 {
		t.Errorf("%d shards permanently wedged by organic churn", wedged)
	}
}

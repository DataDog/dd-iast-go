// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestInteriorSliceCases(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)

	text, _, ok := owner.TaintString(strings.Repeat("0123456789abcdef", 4), 1)
	require.True(t, ok)
	for _, window := range []string{text[3:17], text[5:], text[:9], text[63:], text[:1], text[40:41]} {
		require.Equalf(t, []ranges.Range{{Length: uint32(len(window)), SourceID: 1}}, lookupRanges(t, s, mustKey(t, window)), "window %q", window)
	}
	_, valid := StringKey(text[4:4])
	require.False(t, valid, "an empty window has no key")

	data, _, ok := owner.TaintBytes(make([]byte, 48, 64), 2)
	require.True(t, ok)
	full := data[2:10:12]
	key, ok := BytesKey(full)
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 8, SourceID: 2}}, lookupRanges(t, s, key))
	// A window in the capacity tail is in the root span, but the tail is clean.
	tail := data[50:60]
	key, _ = BytesKey(tail)
	require.Nil(t, lookupRanges(t, s, key))
	require.Equal(t, ConfirmClean, s.Confirm(key.Pointer, key.Length))

	// Windows that cross a granule, in both tiers, and the tier boundary.
	for _, size := range []int{200, MaxSpanS, MaxSpanS + 1, 5000, MaxRootBytes} {
		value, _, ok := owner.TaintBytes(make([]byte, size), 3)
		require.Truef(t, ok, "size %d", size)
		base := bytesBase(value)
		large := largeSpan(uint32(size))
		shift := uintptr(ShiftS)
		if large {
			shift = ShiftL
		}
		boundary := int((base>>shift+1)<<shift - base)
		for _, window := range [][2]int{{0, size}, {boundary - 1, boundary + 1}, {size - 1, size}, {size / 2, size/2 + 1}} {
			if window[0] < 0 || window[1] > size || window[0] >= window[1] {
				continue
			}
			key, _ := BytesKey(value[window[0]:window[1]])
			require.Equalf(t, []ranges.Range{{Length: uint32(window[1] - window[0]), SourceID: 3}}, lookupRanges(t, s, key), "size %d window %v", size, window)
		}
		outside := Key{Pointer: base + uintptr(size) - 1, Length: 2, Kind: KindBytes}
		require.Nilf(t, lookupRanges(t, s, outside), "size %d outside", size)
	}

	// A window of a finished owner is a miss.
	other := s.Acquire()
	finished, _, ok := other.TaintString("finished-owner-value", 4)
	require.True(t, ok)
	window := mustKey(t, finished[2:9])
	require.NotNil(t, lookupRanges(t, s, window))
	other.Finish()
	require.Nil(t, lookupRanges(t, s, window))
	require.False(t, s.MayContain(window))
}

func TestInteriorDensitySmallRoots(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	values := make([]string, 128)
	for i := range values {
		var ok bool
		values[i], _, ok = owner.TaintString(strings.Repeat(string(rune('a'+i%26)), 8), ranges.SourceID(i))
		require.True(t, ok)
	}
	for i, value := range values {
		require.Equal(t, []ranges.Range{{Length: 8, SourceID: ranges.SourceID(i)}}, lookupRanges(t, s, mustKey(t, value)))
	}

	// 33 roots of 2 bytes overlap one 64-byte granule.
	buffer, backing := alignedBuffer(256, 64)
	for i := range 33 {
		offset := 63 + 2*i
		window := buffer[offset : offset+2 : offset+2]
		set := mustSet(t, ranges.DefaultLimit, 2, r(0, 2, ranges.SourceID(100+i)))
		_, ok := owner.AdoptBytes(window, set)
		require.Truef(t, ok, "root %d", i)
	}
	for i := range 33 {
		offset := 63 + 2*i
		key, _ := BytesKey(buffer[offset : offset+2])
		require.Equalf(t, []ranges.Range{{Length: 2, SourceID: ranges.SourceID(100 + i)}}, lookupRanges(t, s, key), "root %d", i)
	}
	requireFilterConsistent(t, s)
	runtime.KeepAlive(backing)
}

func TestSharedAllocationOwners(t *testing.T) {
	s := New()
	owners := make([]*Owner, 41)
	for i := range owners {
		owners[i] = s.Acquire()
		require.False(t, owners[i].Disabled())
	}
	t.Cleanup(func() { finishAll(owners) })
	buffer, backing := alignedBuffer(128, 64)
	neighbor := buffer[10:12:12]
	_, ok := owners[0].AdoptBytes(neighbor, mustSet(t, ranges.DefaultLimit, 2, r(0, 2, 9)))
	require.True(t, ok)

	shared := buffer[0:2:2]
	admitted, fanout := 0, uint64(0)
	for i, owner := range owners {
		if _, ok := owner.AdoptBytes(shared, mustSet(t, ranges.DefaultLimit, 2, r(0, 2, ranges.SourceID(i)))); ok {
			admitted++
		}
		fanout += owner.Counters().Fanout
	}
	require.Equal(t, MaxSnapshotOwners, admitted)
	require.Equal(t, uint64(len(owners)-MaxSnapshotOwners), fanout)
	var snapshot Snapshot
	key, _ := BytesKey(shared)
	require.True(t, s.Lookup(key, &snapshot))
	require.Equal(t, MaxSnapshotOwners, snapshot.Len())
	key, _ = BytesKey(neighbor)
	require.Equal(t, []ranges.Range{{Length: 2, SourceID: 9}}, lookupRanges(t, s, key), "no other root in the granule is lost")

	// 33 distinct 2-byte allocations in one granule, each shared by 4 owners.
	dense, denseBacking := alignedBuffer(256, 64)
	for i := range 33 {
		offset := 63 + 2*i
		window := dense[offset : offset+2 : offset+2]
		for _, owner := range owners[1 : 1+MaxSnapshotOwners] {
			_, ok := owner.AdoptBytes(window, mustSet(t, ranges.DefaultLimit, 2, r(0, 2, 1)))
			require.Truef(t, ok, "root %d", i)
		}
	}
	for i := range 33 {
		offset := 63 + 2*i
		key, _ := BytesKey(dense[offset : offset+2])
		require.True(t, s.Lookup(key, &snapshot))
		require.Equalf(t, MaxSnapshotOwners, snapshot.Len(), "root %d", i)
	}
	requireFilterConsistent(t, s)
	runtime.KeepAlive(backing)
	runtime.KeepAlive(denseBacking)
}

func TestRepeatedAdoptionByOneOwner(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value := strings.Clone(strings.Repeat("v", 64))
	var refs []RootRef
	var stats Stats
	for i := range 5 {
		ref, ok := owner.AdoptString(value, mustSet(t, ranges.DefaultLimit, 64, r(uint32(10*i), 4, ranges.SourceID(i))))
		require.True(t, ok)
		refs = append(refs, ref)
		if i == 0 {
			stats = indexState(s)
		}
	}
	for _, ref := range refs {
		require.Equal(t, refs[0].ID, ref.ID)
	}
	require.Equal(t, stats, indexState(s), "one root and one ref for one owner and allocation")
	require.Equal(t, []ranges.Range{r(0, 4, 0), r(10, 4, 1), r(20, 4, 2), r(30, 4, 3), r(40, 4, 4)}, lookupRanges(t, s, mustKey(t, value)))

	// Owner A adopts 4 times, then owners B, C and D: all found, no fanout.
	others := []*Owner{s.Acquire(), s.Acquire(), s.Acquire(), s.Acquire()}
	t.Cleanup(func() { finishAll(others) })
	for _, other := range others[:3] {
		_, ok := other.AdoptString(value, mustSet(t, ranges.DefaultLimit, 64, r(0, 1, 7)))
		require.True(t, ok)
	}
	var snapshot Snapshot
	require.True(t, s.Lookup(mustKey(t, value), &snapshot))
	require.Equal(t, 4, snapshot.Len())
	require.Zero(t, owner.Counters().Fanout+others[0].Counters().Fanout)
	_, ok := others[3].AdoptString(value, mustSet(t, ranges.DefaultLimit, 64, r(0, 1, 7)))
	require.False(t, ok, "a fifth distinct owner is refused")
	require.Equal(t, uint64(1), others[3].Counters().Fanout)
}

func TestExtensionLongerThenShorter(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value := strings.Clone(strings.Repeat("l", 200))
	base := stringBase(value)
	first, ok := owner.AdoptString(value, mustSet(t, ranges.DefaultLimit, 200, r(0, 10, 1), r(150, 10, 1)))
	require.True(t, ok)
	second, ok := owner.AdoptString(value[:100], mustSet(t, ranges.DefaultLimit, 100, r(20, 10, 2)))
	require.True(t, ok)
	require.Equal(t, first, second)
	require.Equal(t, []ranges.Range{r(0, 10, 1), r(20, 10, 2), r(150, 10, 1)}, lookupRanges(t, s, windowKey(base, 0, 200, KindString)))
	require.Equal(t, []ranges.Range{r(0, 10, 1), r(20, 10, 2)}, lookupRanges(t, s, windowKey(base, 0, 100, KindString)))
	require.Equal(t, []ranges.Range{r(0, 10, 1)}, lookupRanges(t, s, windowKey(base, 150, 10, KindString)))

	// Overlapping ranges: the new ranges win on the shared bytes.
	_, ok = owner.AdoptString(value[:100], mustSet(t, ranges.DefaultLimit, 100, r(5, 10, 3)))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{r(0, 5, 1), r(5, 10, 3), r(20, 10, 2), r(150, 10, 1)}, lookupRanges(t, s, windowKey(base, 0, 200, KindString)))
	requireFilterConsistent(t, s)
}

func TestExtensionCrossTier(t *testing.T) {
	t.Run("longer first", func(t *testing.T) {
		s := New()
		owner := s.Acquire()
		t.Cleanup(owner.Finish)
		value := make([]byte, 300)
		_, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 300, r(200, 10, 1)))
		require.True(t, ok)
		stats := indexState(s)
		_, ok = owner.AdoptBytes(value[:100:100], mustSet(t, ranges.DefaultLimit, 100, r(0, 10, 2)))
		require.True(t, ok)
		require.Equal(t, stats, indexState(s), "U == old: no index change")
		key, _ := BytesKey(value)
		require.Equal(t, []ranges.Range{r(0, 10, 2), r(200, 10, 1)}, lookupRanges(t, s, key))
	})
	t.Run("shorter first", func(t *testing.T) {
		s := New()
		owner := s.Acquire()
		t.Cleanup(owner.Finish)
		value := make([]byte, 300)
		_, ok := owner.AdoptBytes(value[:100:100], mustSet(t, ranges.DefaultLimit, 100, r(0, 10, 2)))
		require.True(t, ok)
		sKeys, _ := rootKeys(bytesBase(value), 100, false)
		_, ok = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 300, r(200, 10, 1)))
		require.True(t, ok)
		lKeys, _ := rootKeys(bytesBase(value), 300, true)
		stats := indexState(s)
		require.Equal(t, uint32(lKeys.n), stats.IndexRefs, "tier S refs are removed, tier L refs are added")
		require.NotZero(t, sKeys.n)
		requireFilterConsistent(t, s)
		var snapshot Snapshot
		key, _ := BytesKey(value[2:8])
		require.True(t, s.Lookup(key, &snapshot))
		require.Equal(t, 1, snapshot.Len(), "one contribution")
		entry, _ := snapshot.At(0)
		require.Equal(t, []ranges.Range{r(0, 6, 2)}, rangeSlice(&entry.Ranges))
		key, _ = BytesKey(value)
		require.Equal(t, []ranges.Range{r(0, 10, 2), r(200, 10, 1)}, lookupRanges(t, s, key))
	})
	t.Run("shorter then longer in one tier", func(t *testing.T) {
		s := New()
		owner := s.Acquire()
		t.Cleanup(owner.Finish)
		value := make([]byte, 250)
		_, ok := owner.AdoptBytes(value[:20:20], mustSet(t, ranges.DefaultLimit, 20, r(0, 2, 2)))
		require.True(t, ok)
		before := indexState(s).IndexRefs
		_, ok = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 250, r(240, 2, 1)))
		require.True(t, ok)
		keys, _ := rootKeys(bytesBase(value), 250, false)
		require.Equal(t, uint32(keys.n), indexState(s).IndexRefs)
		require.Greater(t, uint32(keys.n), before)
		requireFilterConsistent(t, s)
		key, _ := BytesKey(value[239:242])
		require.Equal(t, []ranges.Range{r(1, 2, 1)}, lookupRanges(t, s, key))
	})
}

func TestUnionRuleForAllKinds(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value := make([]byte, 64)
	key, _ := BytesKey(value)
	_, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 64, r(0, 8, 1)))
	require.True(t, ok)
	_, ok = owner.AdoptBytes(value[:32:32], mustSet(t, ranges.DefaultLimit, 32, r(16, 8, 2)))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{r(0, 8, 1), r(16, 8, 2)}, lookupRanges(t, s, key), "no taint is removed with no tracked write")
	_, ok = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 64, r(4, 8, 3)))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{r(0, 4, 1), r(4, 8, 3), r(16, 8, 2)}, lookupRanges(t, s, key))

	// A string view of a bytes root uses the same union.
	view := unsafe.String(unsafe.SliceData(value), 40)
	_, ok = owner.AdoptString(view, mustSet(t, ranges.DefaultLimit, 40, r(30, 2, 4)))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{r(0, 4, 1), r(4, 8, 3), r(16, 8, 2), r(30, 2, 4)}, lookupRanges(t, s, mustKey(t, view)))

	// KindRunes.
	runes := make([]rune, 16)
	runeKey, _ := RunesKey(runes)
	_, ok = owner.AdoptRunes(runes, mustSet(t, ranges.DefaultLimit, 64, r(0, 8, 5)))
	require.True(t, ok)
	_, ok = owner.AdoptRunes(runes[:8:8], mustSet(t, ranges.DefaultLimit, 32, r(16, 8, 6)))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{r(0, 8, 5), r(16, 8, 6)}, lookupRanges(t, s, runeKey))
	var snapshot Snapshot
	require.True(t, s.Lookup(runeKey, &snapshot))
	entry, _ := snapshot.At(0)
	require.Equal(t, KindRunes, entry.Kind)
	window, _ := RunesKey(runes[4:6])
	require.Equal(t, []ranges.Range{r(0, 8, 6)}, lookupRanges(t, s, window), "rune i is bytes [4i, 4i+4)")
}

func TestUnionRangeCap(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value := make([]byte, 200)
	first := make([]ranges.Range, 40)
	second := make([]ranges.Range, 40)
	for i := range first {
		first[i] = r(uint32(2*i), 1, 1)
		second[i] = r(uint32(100+2*i), 1, 2)
	}
	_, ok := owner.AdoptBytes(value, mustSet(t, ranges.HardLimit, 200, first...))
	require.True(t, ok)
	dropped := owner.Counters().Ranges
	_, ok = owner.AdoptBytes(value, mustSet(t, ranges.HardLimit, 200, second...))
	require.True(t, ok)
	key, _ := BytesKey(value)
	require.Len(t, lookupRanges(t, s, key), MaxRanges)
	require.Equal(t, dropped+1, owner.Counters().Ranges)
}

func TestExtensionFailureKeepsRoot(t *testing.T) {
	type failure struct {
		name  string
		stage hookStage
		arg   int
	}
	failures := []failure{
		{"E1 lock", hookExtendBegin, -1},
		{"E4 lock", hookExtendCommit, -1},
		{"E4 validity", hookExtendValid, -1},
	}
	for k := range maxRootKeys - 1 {
		failures = append(failures, failure{"E2 key", hookExtendInsert, k})
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			s := New()
			owner := s.Acquire()
			t.Cleanup(owner.Finish)
			value := make([]byte, MaxRootBytes)
			newKeys, _ := rootKeys(bytesBase(value), MaxRootBytes, true)
			oldKeys, _ := rootKeys(bytesBase(value), 4096, true)
			if f.stage == hookExtendInsert && f.arg >= newKeys.n-oldKeys.n {
				t.Skipf("the extension adds %d keys", newKeys.n-oldKeys.n)
			}
			key, _ := BytesKey(value[:4096])
			ref, ok := owner.AdoptBytes(value[:4096:4096], mustSet(t, ranges.DefaultLimit, 4096, r(0, 8, 1)))
			require.True(t, ok)
			stats, charged := indexState(s), owner.Charged()
			setHook(t, func(stage hookStage, arg int) bool {
				return stage == f.stage && (f.arg < 0 || arg == f.arg)
			})
			_, ok = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, MaxRootBytes, r(8000, 8, 2)))
			testHook.Store(nil)
			require.False(t, ok)
			require.Equal(t, stats, indexState(s))
			require.Equal(t, charged, owner.Charged(), "the charge is released")
			require.False(t, owner.owner.extending)
			requireFilterConsistent(t, s)
			require.Equal(t, []ranges.Range{r(0, 8, 1)}, lookupRanges(t, s, key))
			outside, _ := BytesKey(value[8000:8008])
			require.Nil(t, lookupRanges(t, s, outside))
			// The root is still usable.
			next, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, MaxRootBytes, r(8000, 8, 2)))
			require.True(t, ok)
			require.Equal(t, ref.ID, next.ID)
			require.Equal(t, []ranges.Range{r(0, 8, 2)}, lookupRanges(t, s, outside))
		})
	}
}

func TestFirstAdoptionRollbackAtEveryKey(t *testing.T) {
	cases := []struct {
		name   string
		size   int
		offset int
		keys   int
	}{
		{"tier L", MaxRootBytes, 100, maxRootKeys},
		{"tier S", MaxSpanS, 1, MaxSpanS>>ShiftS + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buffer, backing := alignedBuffer(c.size+c.offset+64, 1<<ShiftL)
			value := buffer[c.offset : c.offset+c.size : c.offset+c.size]
			keys, ok := rootKeys(bytesBase(value), uint32(c.size), largeSpan(uint32(c.size)))
			require.True(t, ok)
			require.Equal(t, c.keys, keys.n)
			s := New()
			owner := s.Acquire()
			t.Cleanup(owner.Finish)
			key, _ := BytesKey(value[c.size/2 : c.size/2+1])
			var stop atomic.Bool
			var seen atomic.Int32
			var readers sync.WaitGroup
			readers.Go(func() {
				var snapshot Snapshot
				for !stop.Load() {
					if s.Lookup(key, &snapshot) && snapshot.Len() != 0 {
						seen.Add(1)
					}
				}
			})
			for k := range keys.n {
				fail := k
				hook := func(stage hookStage, arg int) bool { return stage == hookFirstInsert && arg == fail }
				testHook.Store(&hook)
				_, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, uint32(c.size), r(0, uint32(c.size), 1)))
				testHook.Store(nil)
				require.Falsef(t, ok, "key %d", k)
				requireIndexEmpty(t, s)
				require.Zero(t, owner.Charged())
				require.Nil(t, lookupRanges(t, s, key))
			}
			stop.Store(true)
			readers.Wait()
			require.Zero(t, seen.Load(), "readers never see a partial root")
			require.Equal(t, uint64(keys.n), owner.Counters().IndexFull)
			_, ok = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, uint32(c.size), r(0, uint32(c.size), 1)))
			require.True(t, ok)
			require.NotNil(t, lookupRanges(t, s, key))
			runtime.KeepAlive(backing)
		})
	}
}

func TestFirstAdoptionCommitFailureRollsBack(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	setHook(t, func(stage hookStage, _ int) bool { return stage == hookFirstCommit })
	_, _, ok := owner.TaintString("commit-failure", 1)
	require.False(t, ok)
	requireIndexEmpty(t, s)
	require.Zero(t, owner.Charged())
	require.Equal(t, uint64(1), owner.Counters().Contention)
}

func TestConcurrentReadersDuringTierMoveNeverMiss(t *testing.T) {
	// The move from tier S to tier L has three stages that readers must see:
	// 1: the tier L refs are added and counted, the extension is not
	// committed; 2: the extension is committed, the tier S refs are not
	// removed (before E5); 3: after E5. The hook stops the move at stages 1
	// and 2 until readers have made minReads complete reads (Confirm) and
	// minReads complete, uncontended lookups in the stage.
	//
	// The readers hold read locks, and the writer uses TryLock, so a writer
	// can fail with contention for a long time when readers run all the time
	// (on linux/amd64, 10 000 tries were not sufficient). A barrier controls
	// this: the readers park while the writer tries a lock, and they read
	// only in the stages. Thus the writer can always commit, and each stage
	// still has concurrent reads.
	const iterations, minReads, readerCount, maxAttempts = 20, 16, 4, 8
	s := New()
	var stage atomic.Int32
	var stageReads, stageLookups [4]atomic.Int64
	var misses, lookupMisses, duplicates atomic.Int64
	// pause parks the readers; parked counts the readers that are parked. A
	// reader reads only after it sees pause == false at the start of its
	// loop, so parked == readerCount after pause.Store(true) means that no
	// read runs.
	var pause, stop atomic.Bool
	var parked atomic.Int32
	var stalled atomic.Bool
	pauseReaders := func() {
		pause.Store(true)
		for i := 0; parked.Load() != readerCount; i++ {
			if i > 100_000_000 {
				stalled.Store(true)
				return
			}
			runtime.Gosched()
		}
	}
	// readStage lets the readers read in stage current until they made
	// minReads reads and minReads lookups, then parks them again.
	readStage := func(current int32) {
		stage.Store(current)
		first, firstLookups := stageReads[current].Load(), stageLookups[current].Load()
		pause.Store(false)
		for i := 0; stageReads[current].Load()-first < minReads || stageLookups[current].Load()-firstLookups < minReads; i++ {
			if i > 100_000_000 {
				stalled.Store(true)
				break
			}
			runtime.Gosched()
		}
		pauseReaders()
	}
	setHook(t, func(current hookStage, _ int) bool {
		switch current {
		case hookExtendCommit:
			readStage(1)
		case hookExtendCleanup:
			readStage(2)
		}
		return false
	})
	for iteration := range iterations {
		owner := s.Acquire()
		value := make([]byte, 300)
		_, ok := owner.AdoptBytes(value[:200:200], mustSet(t, ranges.DefaultLimit, 200, r(150, 10, 1)))
		require.True(t, ok)
		key, _ := BytesKey(value[150:160])
		stage.Store(0)
		stop.Store(false)
		pause.Store(true)
		var readers sync.WaitGroup
		for range readerCount {
			readers.Go(func() {
				var snapshot Snapshot
				for !stop.Load() {
					if pause.Load() {
						parked.Add(1)
						for pause.Load() && !stop.Load() {
							runtime.Gosched()
						}
						parked.Add(-1)
						continue
					}
					before := stage.Load()
					// Confirm separates a contended read (ConfirmUnknown) from
					// a miss (ConfirmClean).
					result := s.Confirm(key.Pointer, key.Length)
					if result == ConfirmClean {
						misses.Add(1)
					}
					if result == ConfirmTainted && stage.Load() == before {
						stageReads[before].Add(1)
					}
					// A lookup that saw no contention (no contention counter
					// changed) and no stage change must find the root once.
					contended := owner.Counters().Contention + s.Counters().Contention
					before = stage.Load()
					found := s.Lookup(key, &snapshot)
					if stage.Load() != before || owner.Counters().Contention+s.Counters().Contention != contended {
						continue
					}
					switch {
					case !found || snapshot.Len() == 0:
						lookupMisses.Add(1)
					case snapshot.Len() > 1:
						duplicates.Add(1)
					default:
						stageLookups[before].Add(1)
					}
				}
			})
		}
		pauseReaders()
		// No reader runs when the writer tries a lock, so contention is not
		// expected. A failed extension leaves the root unchanged, so a small
		// number of tries is permitted; the failure message has the counters.
		extended, attempts := false, 0
		for ; attempts < maxAttempts && !extended; attempts++ {
			_, extended = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 300, r(250, 10, 2)))
		}
		if extended {
			readStage(3)
		}
		stop.Store(true)
		readers.Wait()
		counters, storeCounters := owner.Counters(), s.Counters()
		owner.Finish()
		require.Truef(t, extended, "iteration %d: %d tries, owner contention %d, store contention %d, owner counters %+v",
			iteration, attempts, counters.Contention, storeCounters.Contention, counters)
		require.Falsef(t, stalled.Load(), "iteration %d: the readers or the writer stalled in a stage", iteration)
	}
	for current := 1; current <= 3; current++ {
		require.GreaterOrEqualf(t, stageReads[current].Load(), int64(iterations*minReads), "reads in stage %d", current)
		require.GreaterOrEqualf(t, stageLookups[current].Load(), int64(iterations*minReads), "lookups in stage %d", current)
	}
	require.Zero(t, misses.Load())
	require.Zero(t, lookupMisses.Load(), "an uncontended lookup found no root")
	require.Zero(t, duplicates.Load())
	requireIndexEmpty(t, s)
}

// TestReaderOrderSurvivesTierMove runs a complete move from tier S to tier L
// between the tier S read and the tier L read of one lookup. The lookup must
// still find the root. It fails when a reader reads tier L before tier S, or
// loads both filter buckets before the probes.
func TestReaderOrderSurvivesTierMove(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value := make([]byte, 300)
	_, ok := owner.AdoptBytes(value[:200:200], mustSet(t, ranges.DefaultLimit, 200, r(150, 10, 1)))
	require.True(t, ok)
	key, _ := BytesKey(value[150:160])
	var moved atomic.Bool
	setHook(t, func(stage hookStage, _ int) bool {
		if stage == hookReaderTiers && moved.CompareAndSwap(false, true) {
			_, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 300, r(250, 10, 2)))
			require.True(t, ok)
		}
		return false
	})
	var snapshot Snapshot
	require.True(t, s.Lookup(key, &snapshot))
	require.True(t, moved.Load())
	require.Equal(t, 1, snapshot.Len(), "the root is found once during the move")
	entry, _ := snapshot.At(0)
	require.Equal(t, []ranges.Range{r(0, 10, 1)}, rangeSlice(&entry.Ranges))
}

func TestConcurrentReadoptionOneSucceeds(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value := make([]byte, 100)
	_, ok := owner.AdoptBytes(value[:10:10], mustSet(t, ranges.DefaultLimit, 10, r(0, 1, 1)))
	require.True(t, ok)
	var second atomic.Bool
	setHook(t, func(stage hookStage, _ int) bool {
		if stage == hookExtendPreCommit && second.CompareAndSwap(false, true) {
			// The first extension holds rootsMu and owner.extending here.
			_, ok := owner.AdoptBytes(value[:50:50], mustSet(t, ranges.DefaultLimit, 50, r(40, 1, 3)))
			require.False(t, ok)
		}
		return false
	})
	before := owner.Counters().Contention
	_, ok = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 100, r(90, 1, 2)))
	require.True(t, ok)
	require.Equal(t, before+1, owner.Counters().Contention)
	require.Equal(t, int32(1), owner.owner.rootCount.Load())
	key, _ := BytesKey(value)
	require.Equal(t, []ranges.Range{r(0, 1, 1), r(90, 1, 2)}, lookupRanges(t, s, key))
}

func TestConcurrentFirstAdoptionsOfOneOwner(t *testing.T) {
	for _, sizes := range [][2]int{{100, 150}, {100, 300}} {
		s := New()
		owner := s.Acquire()
		value := make([]byte, 300)
		var calls atomic.Int32
		var nested bool
		setHook(t, func(stage hookStage, arg int) bool {
			if stage == hookFirstInsert && arg == 0 && calls.Add(1) == 1 {
				// The first adoption did step 0. Run the second adoption
				// completely before the first one inserts its refs.
				_, nested = owner.AdoptBytes(value[:sizes[1]:sizes[1]], mustSet(t, ranges.DefaultLimit, uint32(sizes[1]), r(0, 1, 2)))
			}
			return false
		})
		_, first := owner.AdoptBytes(value[:sizes[0]:sizes[0]], mustSet(t, ranges.DefaultLimit, uint32(sizes[0]), r(0, 1, 1)))
		testHook.Store(nil)
		require.NotEqualf(t, first, nested, "sizes %v: exactly one adoption succeeds", sizes)
		require.Equalf(t, int32(1), owner.owner.rootCount.Load(), "sizes %v: never two roots", sizes)
		require.Equal(t, int32(1), s.IndexedRoots().Load())
		requireFilterConsistent(t, s)
		owner.Finish()
		requireIndexEmpty(t, s)
	}
}

func TestMutationDuringExtension(t *testing.T) {
	for _, when := range []string{"before E4", "inside E4", "after commit"} {
		t.Run(when, func(t *testing.T) {
			s := New()
			owner := s.Acquire()
			t.Cleanup(owner.Finish)
			value := make([]byte, 64)
			ref, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 64, r(0, 8, 1)))
			require.True(t, ok)
			mutate := func() {
				mutation := mustSet(t, ranges.DefaultLimit, 64, r(0, 64, 9))
				_, published := owner.PublishBytesMutation(ref, value, mutation)
				require.False(t, published, "the forced lock failure makes the mutation fail")
			}
			stage := hookExtendCommit
			if when == "inside E4" {
				stage = hookExtendPreCommit
			}
			var done atomic.Bool
			setHook(t, func(current hookStage, _ int) bool {
				if current == hookMutationLock {
					return true
				}
				if current == stage && when != "after commit" && done.CompareAndSwap(false, true) {
					mutate()
				}
				return false
			})
			_, extended := owner.AdoptBytes(value[:32:32], mustSet(t, ranges.DefaultLimit, 32, r(16, 8, 2)))
			if when == "after commit" {
				mutate()
			}
			require.Equal(t, when != "before E4", extended)
			for _, window := range [][2]int{{0, 64}, {0, 32}, {0, 8}, {16, 24}} {
				key, _ := BytesKey(value[window[0]:window[1]])
				require.Nilf(t, lookupRanges(t, s, key), "window %v: no stale taint after a failed mutation", window)
				require.Equal(t, ConfirmClean, s.Confirm(key.Pointer, key.Length))
			}
			require.Equal(t, int32(1), s.IndexedRoots().Load(), "the root stays indexed until Finish")
		})
	}
}

func TestMutationOfExtendedRoot(t *testing.T) {
	setup := func(t *testing.T) (*Store, *Owner, []byte, RootRef) {
		s := New()
		owner := s.Acquire()
		t.Cleanup(owner.Finish)
		value := make([]byte, 64)
		ref, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 64, r(40, 8, 1)))
		require.True(t, ok)
		viewRef, ok := owner.AdoptBytes(value[:32:32], mustSet(t, ranges.DefaultLimit, 32, r(0, 2, 2)))
		require.True(t, ok)
		require.Equal(t, ref, viewRef)
		return s, owner, value, ref
	}
	t.Run("full capacity", func(t *testing.T) {
		s, owner, value, ref := setup(t)
		_, ok := owner.PublishBytesMutation(ref, value, mustSet(t, ranges.DefaultLimit, 64, r(4, 2, 3)))
		require.True(t, ok)
		key, _ := BytesKey(value)
		require.Equal(t, []ranges.Range{r(4, 2, 3)}, lookupRanges(t, s, key))
	})
	t.Run("view", func(t *testing.T) {
		s, owner, value, ref := setup(t)
		_, ok := owner.PublishBytesMutation(ref, value[:32:32], mustSet(t, ranges.DefaultLimit, 32, r(4, 2, 3)))
		require.True(t, ok)
		key, _ := BytesKey(value)
		require.Equal(t, []ranges.Range{r(4, 2, 3), r(40, 8, 1)}, lookupRanges(t, s, key))
	})
	t.Run("stale tail", func(t *testing.T) {
		s, owner, value, ref := setup(t)
		dropped := owner.Counters().Ranges
		setHook(t, func(stage hookStage, _ int) bool { return stage == hookMutationTail })
		_, ok := owner.PublishBytesMutation(ref, value[:32:32], mustSet(t, ranges.DefaultLimit, 32, r(4, 2, 3)))
		require.True(t, ok)
		key, _ := BytesKey(value)
		require.Equal(t, []ranges.Range{r(4, 2, 3)}, lookupRanges(t, s, key))
		require.Equal(t, dropped+1, owner.Counters().Ranges)
	})
}

func TestMutationGate(t *testing.T) {
	t.Run("success keeps the gate on", func(t *testing.T) {
		s := New()
		owner := s.Acquire()
		value, ref, ok := owner.TaintBytes(make([]byte, 64), 1)
		require.True(t, ok)
		_, ok = owner.PublishBytesMutation(ref, value, mustSet(t, ranges.DefaultLimit, 64, r(8, 8, 2)))
		require.True(t, ok)
		require.NotZero(t, s.IndexedRoots().Load())
		key, _ := BytesKey(value[8:12])
		require.Equal(t, []ranges.Range{r(0, 4, 2)}, lookupRanges(t, s, key))
		owner.Finish()
		require.Zero(t, s.IndexedRoots().Load())
	})
	t.Run("failure after the claim", func(t *testing.T) {
		s := New()
		owner := s.Acquire()
		value, ref, ok := owner.TaintBytes(make([]byte, 64), 1)
		require.True(t, ok)
		setHook(t, func(stage hookStage, _ int) bool { return stage == hookMutationLock })
		_, ok = owner.PublishBytesMutation(ref, value, mustSet(t, ranges.DefaultLimit, 64, r(8, 8, 2)))
		require.False(t, ok)
		require.NotZero(t, s.IndexedRoots().Load())
		key, _ := BytesKey(value[8:12])
		require.Nil(t, lookupRanges(t, s, key), "no stale provenance")
		owner.Finish()
		requireIndexEmpty(t, s)
	})
	t.Run("concurrent", func(t *testing.T) {
		s := New()
		var violations, validations atomic.Int64
		// Writer progress. At each validation, the hook records the writer
		// counters. The test then proves that mutations and finishes ran
		// between the first and the last validation: they overlapped reads.
		var mutations, finishes atomic.Int64
		var started atomic.Bool
		var firstMutations, firstFinishes, lastMutations, lastFinishes atomic.Int64
		setHook(t, func(stage hookStage, _ int) bool {
			if stage == hookValidate {
				validations.Add(1)
				if s.IndexedRoots().Load() == 0 {
					violations.Add(1)
				}
				m, f := mutations.Load(), finishes.Load()
				if started.CompareAndSwap(false, true) {
					firstMutations.Store(m)
					firstFinishes.Store(f)
				}
				storeMax(&lastMutations, m)
				storeMax(&lastFinishes, f)
			}
			return false
		})
		var group, ready sync.WaitGroup
		var stop atomic.Bool
		var current atomic.Pointer[Key]
		start := make(chan struct{})
		for range 4 {
			ready.Add(1)
			group.Go(func() {
				ready.Done()
				<-start
				for !stop.Load() {
					owner := s.Acquire()
					value, ref, ok := owner.TaintBytes(make([]byte, 64), 1)
					if ok {
						key, _ := BytesKey(value[4:20])
						current.Store(&key)
						for i := range 4 {
							value[i]++
							if next, ok := owner.PublishBytesMutation(ref, value, mustSetNoFail(64, r(uint32(i), 4, 2))); ok {
								ref = next
								mutations.Add(1)
							}
						}
					}
					owner.Finish()
					finishes.Add(1)
				}
			})
		}
		for range 4 {
			ready.Add(1)
			group.Go(func() {
				ready.Done()
				<-start
				var snapshot Snapshot
				for !stop.Load() {
					if key := current.Load(); key != nil {
						s.Lookup(*key, &snapshot)
						s.Confirm(key.Pointer, key.Length)
					}
				}
			})
		}
		ready.Wait()
		close(start)
		// Run until readers validated enough refs while writers published,
		// mutated and finished. The bound only stops a broken test.
		const wantValidations, wantMutations, wantFinishes = 1000, 200, 50
		overlap := func() bool {
			return validations.Load() >= wantValidations &&
				lastMutations.Load()-firstMutations.Load() >= wantMutations &&
				lastFinishes.Load()-firstFinishes.Load() >= wantFinishes
		}
		for i := 0; !overlap() && i < 100_000_000; i++ {
			runtime.Gosched()
		}
		stop.Store(true)
		group.Wait()
		require.GreaterOrEqual(t, validations.Load(), int64(wantValidations), "readers must validate refs during the concurrent run")
		require.GreaterOrEqual(t, lastMutations.Load()-firstMutations.Load(), int64(wantMutations), "mutations between the first and the last validation")
		require.GreaterOrEqual(t, lastFinishes.Load()-firstFinishes.Load(), int64(wantFinishes), "finishes between the first and the last validation")
		require.Zero(t, violations.Load())
		requireIndexEmpty(t, s)
	})
}

func TestIndexFullRefusesAdmission(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	forceIndexCollision.Store(true)
	t.Cleanup(func() { forceIndexCollision.Store(false) })
	for i := range IndexBucketProbe * IndexBucketSize {
		_, _, ok := owner.TaintString(strings.Repeat(string(rune('a'+i%26)), 16), 1)
		require.True(t, ok)
	}
	source := strings.Clone("refused-source-v")
	managed, _, ok := owner.TaintString(source, 1)
	require.False(t, ok)
	require.Equal(t, source, managed)
	require.Nil(t, lookupRanges(t, s, mustKey(t, managed)), "a refused root is not tainted")
	require.Equal(t, uint64(1), owner.Counters().IndexFull)
}

func TestConfirm(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value, ok := taintBytesWithRanges(t, owner, 64, r(0, 4, 1))
	require.True(t, ok)
	base := bytesBase(value)
	require.Equal(t, ConfirmTainted, s.Confirm(base+2, 4))
	require.Equal(t, ConfirmClean, s.Confirm(base+10, 10), "a clean part of a sparse root")
	clean := strings.Clone("clean-value-here")
	require.Equal(t, ConfirmClean, s.Confirm(stringBase(clean), uint32(len(clean))))
	require.Equal(t, ConfirmClean, s.Confirm(0, 4))
	require.Zero(t, testing.AllocsPerRun(100, func() {
		s.Confirm(base+10, 10)
		s.Confirm(base+2, 4)
	}))

	shard, _ := s.shardOf(indexHash(granuleKey(base, false)))
	shard.mu.Lock()
	result := s.Confirm(base+2, 4)
	shard.mu.Unlock()
	require.Equal(t, ConfirmUnknown, result)
	require.Equal(t, uint64(1), s.Counters().PreContention)

	owner.owner.rootsMu.Lock()
	result = s.Confirm(base+2, 4)
	owner.owner.rootsMu.Unlock()
	require.Equal(t, ConfirmUnknown, result)
	require.Equal(t, uint64(1), owner.Counters().PreContention)
}

func TestAddressReuseAfterFinish(t *testing.T) {
	s := New()
	owner := s.Acquire()
	for range 64 {
		_, _, ok := owner.TaintString(strings.Repeat("r", 48), 1)
		require.True(t, ok)
	}
	owner.Finish()
	runtime.GC()
	runtime.GC()
	values := make([]string, 4096)
	for i := range values {
		values[i] = strings.Clone(strings.Repeat("n", 48))
	}
	for _, value := range values {
		require.False(t, s.MayContain(mustKey(t, value)))
	}
	requireIndexEmpty(t, s)
}

// TestRandomSequenceKeepsIndexInvariants runs random adoptions, extensions,
// mutations and finishes, and checks the filter and counter invariants after
// each operation.
func TestRandomSequenceKeepsIndexInvariants(t *testing.T) {
	s := New()
	random := rand.New(rand.NewPCG(1, 2))
	type live struct {
		owner  *Owner
		values [][]byte
		refs   []RootRef
	}
	owners := make([]*live, 6)
	for step := range 3000 {
		slot := random.IntN(len(owners))
		state := owners[slot]
		switch {
		case state == nil:
			owners[slot] = &live{owner: s.Acquire()}
		case random.IntN(20) == 0:
			state.owner.Finish()
			owners[slot] = nil
		case len(state.values) != 0 && random.IntN(3) == 0:
			index := random.IntN(len(state.values))
			value := state.values[index]
			span := 2 + random.IntN(cap(value)-1)
			start := uint32(random.IntN(span - 1))
			if ref, ok := state.owner.AdoptBytes(value[:span:span], mustSet(t, ranges.DefaultLimit, uint32(span), r(start, 1, ranges.SourceID(step)))); ok {
				require.Equal(t, state.refs[index].ID, ref.ID)
				state.refs[index] = ref
			}
		case len(state.values) != 0 && random.IntN(3) == 0:
			index := random.IntN(len(state.values))
			value := state.values[index]
			if ref, ok := state.owner.PublishBytesMutation(state.refs[index], value[:cap(value)], mustSet(t, ranges.DefaultLimit, uint32(cap(value)), r(0, 1, 3))); ok {
				state.refs[index] = ref
			}
		default:
			size := 2 + random.IntN(600)
			value := make([]byte, size)
			if ref, ok := state.owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, uint32(size), r(0, 1, 1))); ok {
				state.values = append(state.values, value)
				state.refs = append(state.refs, ref)
			}
		}
		requireFilterConsistent(t, s)
		indexed := int32(0)
		for i := range s.owners {
			for j := range s.owners[i].roots {
				if s.owners[i].roots[j].indexed {
					indexed++
				}
			}
		}
		require.Equalf(t, indexed, s.IndexedRoots().Load(), "step %d", step)
		for _, state := range owners {
			if state == nil {
				continue
			}
			require.Equal(t, int32(len(state.values)), state.owner.owner.rootCount.Load(), "one root for each owner and allocation")
		}
	}
	for _, state := range owners {
		if state != nil {
			state.owner.Finish()
		}
	}
	requireIndexEmpty(t, s)
}

// TestStoreFootprint measures the fixed store layout (plan section 5.2.1).
func TestStoreFootprint(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("32-bit platforms are not supported")
	}
	t.Logf("GOARCH=%s Store=%d owner=%d rootRecord=%d indexShard=%d indexEntry=%d ownerRef=%d filter=%d",
		runtime.GOARCH, unsafe.Sizeof(Store{}), unsafe.Sizeof(owner{}), unsafe.Sizeof(rootRecord{}),
		unsafe.Sizeof(indexShard{}), unsafe.Sizeof(indexEntry{}), unsafe.Sizeof(ownerRef{}), unsafe.Sizeof(Store{}.filter))
	require.Equal(t, uintptr(8), unsafe.Sizeof(ownerRef{}))
	require.Equal(t, uintptr(56), unsafe.Sizeof(indexEntry{}))
	require.Equal(t, uintptr(312), unsafe.Sizeof(rootRecord{}))
	require.Equal(t, uintptr(expectedOwnerSize), unsafe.Sizeof(owner{}))
	require.Equal(t, uintptr(expectedStoreSize), unsafe.Sizeof(Store{}))
	const planned = 14_040_136
	require.LessOrEqual(t, unsafe.Sizeof(Store{}), uintptr(planned+planned/100), "the plan budget is 14 040 136 B + 1 %")
}

func mustKey(t testing.TB, value string) Key {
	t.Helper()
	key, ok := StringKey(value)
	require.True(t, ok)
	return key
}

func mustSetNoFail(span uint32, raw ...ranges.Range) *ranges.Set {
	var set ranges.Set
	ranges.Canonicalize(&set, ranges.DefaultLimit, raw, span)
	return &set
}

// taintBytesWithRanges adopts a new byte allocation of size bytes with raw.
func taintBytesWithRanges(t testing.TB, owner *Owner, size int, raw ...ranges.Range) ([]byte, bool) {
	t.Helper()
	value := make([]byte, size)
	_, ok := owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, uint32(size), raw...))
	return value, ok
}

func TestAdoptStringAllocAndRunesBounds(t *testing.T) {
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	value := strings.Clone(strings.Repeat("a", 100))
	set := mustSet(t, ranges.DefaultLimit, 100, r(0, 100, 1))
	_, ok := owner.AdoptStringAlloc(value, 102, set)
	require.False(t, ok, "allocBound below len(value)+3")
	_, ok = owner.AdoptStringAlloc(value, MaxRootBytes+1, set)
	require.False(t, ok, "allocBound above MaxRootBytes")
	require.Equal(t, uint64(2), owner.Counters().Bytes)
	_, ok = owner.AdoptStringAlloc(value, 4*100+3, set)
	require.True(t, ok)
	require.Equal(t, sizeClass(403), owner.Charged())
	require.Equal(t, []ranges.Range{r(0, 10, 1)}, lookupRanges(t, s, mustKey(t, value[20:30])))

	largest := make([]rune, MaxRootBytes/4)
	_, ok = owner.AdoptRunes(largest, mustSet(t, ranges.DefaultLimit, MaxRootBytes, r(0, 4, 2)))
	require.True(t, ok)
	_, ok = owner.AdoptRunes(make([]rune, MaxRootBytes/4+1), mustSet(t, ranges.DefaultLimit, MaxRootBytes, r(0, 4, 2)))
	require.False(t, ok)
	_, ok = owner.AdoptRunes(nil, set)
	require.False(t, ok)
	key, _ := RunesKey(largest[:1])
	require.Equal(t, []ranges.Range{r(0, 4, 2)}, lookupRanges(t, s, key))
}

// TestCrossTierOwnerLimit checks the 4-owner limit for one allocation across
// both tiers: views of one allocation in tier S and in tier L share the limit.
func TestCrossTierOwnerLimit(t *testing.T) {
	t.Run("fifth owner in the other tier", func(t *testing.T) {
		s := New()
		owners := acquireOwners(t, s, MaxSnapshotOwners+1)
		value := make([]byte, 300)
		for i, owner := range owners[:MaxSnapshotOwners] {
			_, ok := owner.AdoptBytes(value[:100:100], mustSet(t, ranges.DefaultLimit, 100, r(uint32(10*i), 5, ranges.SourceID(i+1))))
			require.True(t, ok)
		}
		state := indexState(s)
		_, ok := owners[MaxSnapshotOwners].AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 300, r(0, 300, 9)))
		require.False(t, ok, "a fifth distinct owner of the allocation is refused")
		require.Equal(t, uint64(1), owners[MaxSnapshotOwners].Counters().Fanout)
		require.Equal(t, state, indexState(s))
		requireFilterConsistent(t, s)
		var snapshot Snapshot
		key, _ := BytesKey(value[:50])
		require.True(t, s.Lookup(key, &snapshot))
		require.Equal(t, MaxSnapshotOwners, snapshot.Len())
	})
	t.Run("owners in both tiers are all returned", func(t *testing.T) {
		s := New()
		owners := acquireOwners(t, s, MaxSnapshotOwners+2)
		value := make([]byte, 300)
		want := map[uint64][]ranges.Range{}
		for i, owner := range owners[:MaxSnapshotOwners] {
			span := 100
			if i%2 == 1 {
				span = 300
			}
			set := mustSet(t, ranges.DefaultLimit, uint32(span), r(uint32(5*i), 40, ranges.SourceID(i+1)))
			_, ok := owner.AdoptBytes(value[:span:span], set)
			require.Truef(t, ok, "owner %d", i)
			want[owner.ID()] = []ranges.Range{r(uint32(5*i), 40, ranges.SourceID(i+1))}
		}
		var snapshot Snapshot
		key, _ := BytesKey(value[:60])
		require.True(t, s.Lookup(key, &snapshot))
		require.Equal(t, MaxSnapshotOwners, snapshot.Len(), "no contribution is dropped")
		for i := 0; i < snapshot.Len(); i++ {
			entry, _ := snapshot.At(i)
			require.Equal(t, want[entry.OwnerID], rangeSlice(&entry.Ranges))
		}
		for _, span := range []int{100, 300} {
			_, ok := owners[MaxSnapshotOwners].AdoptBytes(value[:span:span], mustSet(t, ranges.DefaultLimit, uint32(span), r(0, 1, 9)))
			require.Falsef(t, ok, "span %d", span)
		}
		require.Equal(t, uint64(2), owners[MaxSnapshotOwners].Counters().Fanout)
	})
	t.Run("concurrent admissions", func(t *testing.T) {
		for iteration := range 200 {
			s := New()
			owners := acquireOwners(t, s, 2*MaxSnapshotOwners)
			value := make([]byte, 300)
			var admitted atomic.Int32
			var group, ready sync.WaitGroup
			start := make(chan struct{})
			for i, owner := range owners {
				span := 100
				if i%2 == 1 {
					span = 300
				}
				ready.Add(1)
				group.Go(func() {
					ready.Done()
					<-start
					if _, ok := owner.AdoptBytes(value[:span:span], mustSetNoFail(uint32(span), r(0, 50, 1))); ok {
						admitted.Add(1)
					}
				})
			}
			ready.Wait()
			close(start)
			group.Wait()
			require.LessOrEqualf(t, admitted.Load(), int32(MaxSnapshotOwners), "iteration %d", iteration)
			require.Equal(t, admitted.Load(), s.IndexedRoots().Load())
			var snapshot Snapshot
			key, _ := BytesKey(value[:60])
			require.True(t, s.Lookup(key, &snapshot))
			require.Equalf(t, int(admitted.Load()), snapshot.Len(), "iteration %d: every admitted owner is returned", iteration)
			requireFilterConsistent(t, s)
			finishAll(owners)
			requireIndexEmpty(t, s)
		}
	})
}

// TestExtensionPanicClearsState checks that a panic during an extension leaves
// no extension state: owner.extending is false, the charge and the added refs
// of an uncommitted extension are removed, and a committed move still removes
// its tier S refs.
func TestExtensionPanicClearsState(t *testing.T) {
	for _, stage := range []hookStage{hookExtendInsert, hookExtendCommit, hookExtendPreCommit, hookExtendCleanup} {
		s := New()
		owner := s.Acquire()
		value := make([]byte, 300)
		_, ok := owner.AdoptBytes(value[:100:100], mustSet(t, ranges.DefaultLimit, 100, r(0, 10, 1)))
		require.True(t, ok)
		state, charged := indexState(s), owner.Charged()
		hook := func(current hookStage, _ int) bool {
			if current == stage {
				panic("injected")
			}
			return false
		}
		testHook.Store(&hook)
		require.PanicsWithValuef(t, "injected", func() {
			owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 300, r(250, 10, 2)))
		}, "stage %d", stage)
		testHook.Store(nil)
		require.Falsef(t, owner.owner.extending, "stage %d", stage)
		requireFilterConsistent(t, s)
		key, _ := BytesKey(value[:10])
		require.Equal(t, []ranges.Range{r(0, 10, 1)}, lookupRanges(t, s, key))
		if stage == hookExtendCleanup {
			keys, _ := rootKeys(bytesBase(value), 300, true)
			require.Equal(t, uint32(keys.n), indexState(s).IndexRefs, "the committed move removed its tier S refs")
		} else {
			require.Equalf(t, state, indexState(s), "stage %d", stage)
			require.Equalf(t, charged, owner.Charged(), "stage %d", stage)
		}
		_, ok = owner.AdoptBytes(value, mustSet(t, ranges.DefaultLimit, 300, r(250, 10, 2)))
		require.Truef(t, ok, "stage %d: a later extension runs", stage)
		owner.Finish()
		requireIndexEmpty(t, s)
	}
}

func acquireOwners(t testing.TB, s *Store, count int) []*Owner {
	t.Helper()
	owners := make([]*Owner, count)
	for i := range owners {
		owners[i] = s.Acquire()
		require.False(t, owners[i].Disabled())
	}
	t.Cleanup(func() { finishAll(owners) })
	return owners
}

// storeMax stores value in counter when it is larger than the current value.
func storeMax(counter *atomic.Int64, value int64) {
	for {
		current := counter.Load()
		if value <= current || counter.CompareAndSwap(current, value) {
			return
		}
	}
}

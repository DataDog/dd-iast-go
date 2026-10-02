// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge/bridgetest"
	"github.com/stretchr/testify/require"
)

// The runtime bridge has one binding for the process. In this test binary,
// runtimeBoundStore is that store.
var runtimeBound = sync.OnceValue(func() *Store {
	s := New()
	if !s.BindRuntimeBridge(runtimebridge.Options{StringToSlice: true}) {
		return nil
	}
	return s
})

func runtimeBoundStore(t *testing.T) *Store {
	t.Helper()
	s := runtimeBound()
	require.NotNil(t, s, "the first BindRuntimeBridge call of the binary succeeds")
	require.Same(t, s, RuntimeStore())
	return s
}

// heapBytes returns a heap byte slice. The bridgetest declarations are
// //go:noescape, so a value that only goes to them can be on the stack.
//
//go:noinline
func heapBytes(n int) []byte { return make([]byte, n) }

//go:noinline
func heapString(s string) string { return strings.Clone(s) }

func windowString(value []byte, low, high int) string {
	return unsafe.String(&value[low], high-low)
}

// TestRuntimeBridgeBindsOnlyTheProcessStore checks plan section 9.1 item 6b.
func TestRuntimeBridgeBindsOnlyTheProcessStore(t *testing.T) {
	bound := runtimeBoundStore(t)
	first, second := New(), New()
	require.False(t, first.BindRuntimeBridge(runtimebridge.Options{}), "a second binding is refused")
	require.Same(t, bound, RuntimeStore())
	require.Nil(t, first.runtimeGate.Load())
	require.Zero(t, bridgetest.Gate(), "no indexed root yet")

	const workers, rounds = 4, 50
	var group sync.WaitGroup
	errs := make(chan string, 3*workers*rounds)
	run := func(s *Store, expectTainted bool) {
		defer group.Done()
		for range rounds {
			owner := s.Acquire()
			value, _, ok := owner.TaintString("independent-store-value", 1)
			if !ok {
				owner.Finish()
				continue
			}
			operands := []string{"x", value}
			if expectTainted && !bridgetest.ConcatPre(operands) {
				errs <- "a value of the bound store is not seen"
			}
			if !expectTainted {
				// Contention with the other workers can give a true
				// result (ConfirmUnknown). It cannot last for 3 tries
				// in a row with a short pause.
				seen := true
				for try := 0; seen && try < 3; try++ {
					seen = bridgetest.ConcatPre(operands)
					if seen {
						runtime.Gosched()
					}
				}
				if seen {
					errs <- "a value of another store is seen"
				}
			}
			owner.Finish()
		}
	}
	group.Add(3 * workers)
	for range workers {
		go run(first, false)
		go run(second, false)
		go run(bound, true)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	require.Zero(t, bridgetest.Gate(), "all owners finished")

	// Taint in another store does not change the gate and is not seen.
	other := first.Acquire()
	t.Cleanup(other.Finish)
	foreign, _, ok := other.TaintString("foreign-store-value", 1)
	require.True(t, ok)
	require.Zero(t, bridgetest.Gate())
	require.Equal(t, int32(1), first.indexedRoots.Load())
	require.False(t, bridgetest.StrPre(foreign))
	require.False(t, bridgetest.ConcatPre([]string{foreign}))

	// Taint in the bound store changes the gate and is seen.
	owner := bound.Acquire()
	value, _, ok := owner.TaintString("bound-store-value", 1)
	require.True(t, ok)
	require.Equal(t, uint32(1), bridgetest.Gate())
	require.True(t, bridgetest.ConcatPre([]string{value}))
	require.True(t, bridgetest.StrPre(value))
	owner.Finish()
	require.Zero(t, bridgetest.Gate())
	require.False(t, bridgetest.ConcatPre([]string{value}), "a finished owner is clean")
}

func TestBindRuntimeBridgeRefusesAStoreWithRoots(t *testing.T) {
	runtimeBoundStore(t)
	s := New()
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	_, _, ok := owner.TaintString("existing-root", 1)
	require.True(t, ok)
	require.False(t, s.BindRuntimeBridge(runtimebridge.Options{}))
	var none *Store
	require.False(t, none.BindRuntimeBridge(runtimebridge.Options{}))
}

// TestRuntimeGateFollowsIndexedRoots checks plan section 3.2 rule 3.
func TestRuntimeGateFollowsIndexedRoots(t *testing.T) {
	s := runtimeBoundStore(t)
	require.Zero(t, bridgetest.Gate())
	owners := [3]*Owner{s.Acquire(), s.Acquire(), s.Acquire()}
	for i, owner := range owners {
		for j := range i + 1 {
			_, _, ok := owner.TaintString(strings.Repeat("g", 8+j), 1)
			require.True(t, ok)
		}
		require.Equal(t, uint32(s.indexedRoots.Load()), bridgetest.Gate())
	}
	require.Equal(t, uint32(6), bridgetest.Gate())
	for _, owner := range owners {
		owner.Finish()
		require.Equal(t, uint32(s.indexedRoots.Load()), bridgetest.Gate())
	}
	require.Zero(t, bridgetest.Gate())
}

// TestRuntimePreConfirm checks the direct-call part of plan section 9.1 item
// 4b: the pre-checks never report a tainted operand as clean, and a clean
// operand does not allocate.
func TestRuntimePreConfirm(t *testing.T) {
	s := runtimeBoundStore(t)
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	root := heapBytes(64)
	_, ok := owner.AdoptBytes(root, mustSet(t, 10, 64, r(0, 4, 1)))
	require.True(t, ok)

	cleanWindow := windowString(root, 10, 20)
	taintedWindow := windowString(root, 2, 6)
	clean := heapString("clean-operand-value")
	cleanOperands := []string{clean, cleanWindow}
	taintedOperands := []string{clean, taintedWindow}
	cleanRunes := unsafe.Slice((*rune)(unsafe.Pointer(&root[16])), 4)

	require.False(t, bridgetest.ConcatPre(cleanOperands), "a clean part of a sparse root")
	require.False(t, bridgetest.BytesPreOf(root[10:20]))
	require.False(t, bridgetest.StrPre(cleanWindow))
	require.False(t, bridgetest.RunesPre(cleanRunes))
	require.Zero(t, testing.AllocsPerRun(1000, func() {
		bridgetest.ConcatPre(cleanOperands)
		bridgetest.BytesPreOf(root[10:20])
		bridgetest.StrPre(cleanWindow)
		bridgetest.RunesPre(cleanRunes)
	}))

	require.True(t, bridgetest.ConcatPre(taintedOperands), "a tainted part of a sparse root")
	require.True(t, bridgetest.BytesPreOf(root[2:6]))
	require.True(t, bridgetest.StrPre(taintedWindow))
	require.True(t, bridgetest.RunesPre(unsafe.Slice((*rune)(unsafe.Pointer(&root[0])), 2)))

	// A failed TryRLock gives ConfirmUnknown: the pre-check forces the heap.
	shard, _ := s.shardOf(indexHash(granuleKey(bytesBase(root), false)))
	before := s.Counters().PreContention
	shard.mu.Lock()
	contended := bridgetest.ConcatPre(cleanOperands)
	shard.mu.Unlock()
	require.True(t, contended, "contention does not lose taint")
	require.Equal(t, before+1, s.Counters().PreContention)

	owner.owner.rootsMu.Lock()
	contended = bridgetest.BytesPreOf(root[10:20])
	owner.owner.rootsMu.Unlock()
	require.True(t, contended)

	// Finish: the root is not visible, and no pre-check sees it.
	owner.Finish()
	require.False(t, bridgetest.ConcatPre(taintedOperands))
	require.False(t, bridgetest.BytesPreOf(root[2:6]))
}

// TestRuntimePreWithFullFanout checks the forced fanout case of plan 9.1 item
// 4b: the allocation of a root already has MaxSnapshotOwners owners, so the
// admission of one more owner fails. The pre-checks and Confirm see the taint
// of the admitted owners only, and a lookup never reports the refused owner.
func TestRuntimePreWithFullFanout(t *testing.T) {
	s := runtimeBoundStore(t)
	owners := make([]*Owner, MaxSnapshotOwners+1)
	for i := range owners {
		owners[i] = s.Acquire()
	}
	t.Cleanup(func() { finishAll(owners) })
	root := heapBytes(64)
	for i, owner := range owners[:MaxSnapshotOwners] {
		_, ok := owner.AdoptBytes(root, mustSet(t, 10, 64, r(uint32(10*i), 4, ranges.SourceID(i+1))))
		require.True(t, ok, "owner %d", i)
	}
	refused := owners[MaxSnapshotOwners]
	_, ok := refused.AdoptBytes(root, mustSet(t, 10, 64, r(50, 4, 9)))
	require.False(t, ok, "the allocation has the maximum number of owners")
	require.Equal(t, uint64(1), refused.Counters().Fanout)

	for i := range MaxSnapshotOwners {
		window := windowString(root, 10*i, 10*i+4)
		require.True(t, bridgetest.ConcatPre([]string{"x", window}), "owner %d", i)
		require.True(t, bridgetest.StrPre(window), "owner %d", i)
		require.True(t, bridgetest.BytesPreOf(root[10*i:10*i+4]), "owner %d", i)
		require.Equal(t, ConfirmTainted, s.Confirm(bytesBase(root)+uintptr(10*i), 4))
	}
	refusedWindow := windowString(root, 50, 54)
	require.False(t, bridgetest.ConcatPre([]string{"x", refusedWindow}), "the refused owner has no visible taint")
	require.False(t, bridgetest.StrPre(refusedWindow))
	require.False(t, bridgetest.BytesPreOf(root[50:54]))
	require.Equal(t, ConfirmClean, s.Confirm(bytesBase(root)+50, 4))
	var snapshot Snapshot
	require.True(t, s.Lookup(mustKey(t, refusedWindow), &snapshot))
	require.Zero(t, snapshot.Len(), "no lookup reports the refused owner")
	require.True(t, s.Lookup(mustKey(t, windowString(root, 0, 64)), &snapshot))
	require.Equal(t, MaxSnapshotOwners, snapshot.Len())
	for i := 0; i < snapshot.Len(); i++ {
		entry, _ := snapshot.At(i)
		require.NotEqual(t, refused.ID(), entry.OwnerID)
	}
	cleanOperands := []string{"x", refusedWindow}
	require.Zero(t, testing.AllocsPerRun(100, func() { bridgetest.ConcatPre(cleanOperands) }))
}

// TestRuntimePreAfterRefusedAdmission checks that a root that the index
// refused is not tainted for the pre-checks or for a lookup (plan 9.1 item
// 4b, forced indexFull).
func TestRuntimePreAfterRefusedAdmission(t *testing.T) {
	s := runtimeBoundStore(t)
	owner := s.Acquire()
	t.Cleanup(owner.Finish)
	setHook(t, func(stage hookStage, _ int) bool { return stage == hookFirstInsert })
	value, _, ok := owner.TaintString(heapString("refused-by-index"), 1)
	require.False(t, ok)
	require.Equal(t, uint64(1), owner.Counters().IndexFull)
	require.False(t, bridgetest.ConcatPre([]string{value}))
	require.False(t, bridgetest.StrPre(value))
	require.Nil(t, lookupRanges(t, s, mustKey(t, value)))
	require.Zero(t, bridgetest.Gate())
}

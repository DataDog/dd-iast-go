// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
)

const param = constants.OriginHttpRequestParameter

func TestManagerPermitAndFinish(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	first, ok := manager.Acquire(2)
	require.True(t, ok)
	second, ok := manager.Acquire(2)
	require.True(t, ok)
	_, ok = manager.Acquire(2)
	require.False(t, ok)

	_, ok = first.TaintString(param, "q", heapString("attacker"))
	require.True(t, ok)
	require.Equal(t, 1, first.SourceCount())

	first.Finish()
	require.False(t, first.Active())
	require.Zero(t, first.SourceCount())
	_, ok = first.TaintString(param, "q", heapString("attacker"))
	require.False(t, ok, "a finished analysis registers nothing")

	reused, ok := manager.Acquire(2)
	require.True(t, ok)
	require.Equal(t, first.slot, reused.slot)
	first.Finish()
	require.True(t, reused.Active(), "stale finish must not close a reused slot")
	require.Zero(t, reused.SourceCount(), "source table must reset on reuse")
	require.Equal(t, OwnerBudget, reused.Budget(), "budget must reset on reuse")
	second.Finish()
	reused.Finish()
	require.Zero(t, manager.used.Load())
}

func TestManagerClampAndZero(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	_, ok := manager.Acquire(0)
	require.False(t, ok)
	analyses := make([]Analysis, MaxAnalyses)
	for i := range analyses {
		analyses[i], ok = manager.Acquire(MaxAnalyses + 100)
		require.True(t, ok)
	}
	_, ok = manager.Acquire(MaxAnalyses + 100)
	require.False(t, ok)
	for _, analysis := range analyses {
		analysis.Finish()
	}
	require.Zero(t, manager.used.Load())
}

func TestIdentityAndOwnerLookup(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	owner, ok := analysis.Owner()
	require.True(t, ok)
	require.NotZero(t, owner.ID)
	require.NotZero(t, owner.Generation)
	found, ok := manager.Analysis(owner)
	require.True(t, ok)
	require.Equal(t, analysis, found)
	_, ok = manager.Analysis(Owner{ID: owner.ID + 1, Generation: owner.Generation, Index: owner.Index})
	require.False(t, ok, "a different ID is not the owner")
	analysis.Finish()
	_, ok = manager.Analysis(owner)
	require.False(t, ok)
	_, _, _, ok = analysis.Identity()
	require.False(t, ok)
}

// TestFinishWithPausedReader: Finish returns at once while an accessor has
// the slot pinned and locked; the slot is not reused before the cleanup,
// and the last accessor does the cleanup.
func TestFinishWithPausedReader(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	_, ok = analysis.TaintString(param, "q", heapString("attacker"))
	require.True(t, ok)

	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.use(analysis.slot, analysis.generation, analysis.id, func(d *ownerData) {
			close(inside)
			<-release
			// The data stay valid while the slot is pinned.
			if d.table.Len() != 1 {
				panic("data cleared while pinned")
			}
		})
	}()
	<-inside

	finished := make(chan struct{})
	go func() {
		analysis.Finish()
		close(finished)
	}()
	<-finished // Finish never waits.
	require.False(t, analysis.Active())
	_, ok = manager.Acquire(1)
	require.False(t, ok, "the slot must not be reused before the cleanup")
	// New accessors are refused while the slot is closing.
	require.False(t, manager.use(analysis.slot, analysis.generation, analysis.id, func(*ownerData) {}))

	close(release)
	<-done
	next, ok := manager.Acquire(1)
	require.True(t, ok, "the last accessor must do the cleanup")
	require.Zero(t, next.SourceCount())
	next.Finish()
}

// TestBusySlotDropsAccess: an accessor never waits for the slot lock.
func TestBusySlotDropsAccess(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	defer analysis.Finish()
	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		manager.use(analysis.slot, analysis.generation, analysis.id, func(*ownerData) {
			close(inside)
			<-release
		})
	}()
	<-inside
	_, ok = analysis.TaintString(param, "q", heapString("attacker"))
	require.False(t, ok, "a busy slot drops the source")
	var r Attribution
	require.False(t, analysis.AttributeString("attacker", &r))
	close(release)
	<-done
	_, ok = analysis.TaintString(param, "q", heapString("attacker"))
	require.True(t, ok)
}

// TestConcurrentWritersReadersAndFinish runs source, body, derived writes
// and cross-owner reads on many goroutines before, during and after the
// Finish of the owners (use -race). A start barrier starts the workers at
// the same time. The parent waits until each worker has one successful
// operation while the owners are live. Then it latches one operation of each
// worker: the operation stops in tryUse after its pin (testHookPinned). With
// all six operations in flight, the parent pins the slots (a controlled
// accessor) and calls Finish. It checks that the latched pins delay the
// cleanup, that the latched operations complete after Finish, that all the
// operations that start during the closing and after the cleanup fail, and
// that the cleanup removes the data of the latched writes.
func TestConcurrentWritersReadersAndFinish(t *testing.T) {
	f := useFakeBits(t)
	manager := NewManager()
	// The latch: when armed, each access of manager stops after its pin
	// until release closes. A blocked worker cannot arrive again, thus
	// arrived counts the workers.
	var (
		armed   atomic.Bool
		arrived atomic.Int32
		release chan struct{}
	)
	testHookPinned = func(m *Manager, _ *slot) {
		if m != manager || !armed.Load() {
			return
		}
		arrived.Add(1)
		<-release
	}
	t.Cleanup(func() { testHookPinned = nil })
	const workers = 6
	const phaseOps = 20
	const (
		phaseBefore = iota
		phaseDuring
		phaseAfter
		phaseStop
	)
	for round := 0; round < 20; round++ {
		alpha, ok := manager.Acquire(2)
		require.True(t, ok)
		bravo, ok := manager.Acquire(2)
		require.True(t, ok)
		body := new([64]byte)
		require.True(t, alpha.RegisterBody(unsafe.Pointer(body)))
		alphaValue, ok := alpha.TaintString(param, "a", heapString("alpha-value"))
		require.True(t, ok)
		bravoValue, ok := bravo.TaintString(param, "b", heapString("bravo-value"))
		require.True(t, ok)
		out := heapBytes(strings.ToUpper(alphaValue))

		// op runs the operation of worker, and reports whether it had an
		// effect on a live owner.
		op := func(worker int, r *Attribution) bool {
			switch worker {
			case 0:
				_, ok := alpha.TaintString(param, "q", heapString("value-x"))
				return ok
			case 1:
				p := heapBytes("body-bytes")
				// The fake bits of a freed buffer stay at its address.
				f.clear(p)
				manager.bodyRead(unsafe.Pointer(body), unsafe.Pointer(&p[0]), uintptr(len(p)))
				return f.any(uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)))
			case 2:
				f.set(uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
				manager.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(unsafe.StringData(alphaValue)), uintptr(len(alphaValue)), 2)
				// Only the derived entry attributes all of out ("ALPHA"
				// is in no source copy).
				return alpha.AttributeBytes(out, r) && r.N == 1 && r.Segments[0].Length == uint32(len(out))
			case 3:
				return manager.AttributeStringAny(bravoValue, Owner{}, r)
			case 4:
				return alpha.AttributeString(alphaValue, r)
			default:
				bravo.AttributeString(alphaValue, r)
				_, ok := alpha.Source(0)
				return ok
			}
		}

		var phase atomic.Int32
		start := make(chan struct{})
		var (
			live   sync.WaitGroup // one Done for each worker: one success while live
			during sync.WaitGroup // one Done for each worker: phaseOps ops in phaseDuring
			after  sync.WaitGroup // one Done for each worker: phaseOps ops in phaseAfter
			wait   sync.WaitGroup
		)
		live.Add(workers)
		during.Add(workers)
		after.Add(workers)
		var failures [workers]atomic.Int32
		for worker := 0; worker < workers; worker++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				var r Attribution
				<-start
				succeeded := false
				counts := map[int32]int{}
				for {
					current := phase.Load()
					if current == phaseStop {
						return
					}
					ok := op(worker, &r)
					counts[current]++
					// Let the parent run soon (GOMAXPROCS=1).
					runtime.Gosched()
					switch current {
					case phaseBefore:
						if ok && !succeeded {
							succeeded = true
							live.Done()
						}
					case phaseDuring, phaseAfter:
						if ok {
							failures[worker].Add(1)
						}
						if counts[current] == phaseOps {
							if current == phaseDuring {
								during.Done()
							} else {
								after.Done()
							}
						}
					}
				}
			}()
		}
		close(start)
		live.Wait()

		// Latch one phaseBefore operation of each worker after its pin.
		release = make(chan struct{})
		arrived.Store(0)
		armed.Store(true)
		deadline := time.Now().Add(10 * time.Second)
		for arrived.Load() < workers {
			if time.Now().After(deadline) {
				armed.Store(false)
				close(release)
				t.Fatalf("round %d: %d of %d workers latched", round, arrived.Load(), workers)
			}
			runtime.Gosched()
		}

		// The controlled accessors: the slots stay pinned while closing.
		pinLive(t, manager, alpha)
		pinLive(t, manager, bravo)
		// Finish runs while the six latched operations hold their pins.
		alpha.Finish()
		bravo.Finish()
		require.False(t, alpha.Active())
		require.False(t, bravo.Active())
		require.NotZero(t, manager.used.Load(), "round %d: no cleanup while pinned", round)
		phase.Store(phaseDuring)
		armed.Store(false)
		close(release)
		// A worker counts phaseOps phaseDuring operations only after its
		// latched operation completed.
		during.Wait()
		require.NotZero(t, manager.used.Load(), "round %d: no cleanup while pinned", round)

		manager.unpin(alpha.slot)
		manager.unpin(bravo.slot)
		require.Zero(t, manager.used.Load(), "round %d: the last unpin does the cleanup", round)
		for _, a := range []Analysis{alpha, bravo} {
			a.slot.mu.Lock()
			sources, derived := a.slot.data.table.Len(), a.slot.data.nderived
			bodyCopy := len(a.slot.data.body.copy)
			a.slot.mu.Unlock()
			require.Zero(t, sources, "round %d: the cleanup removes the sources of the latched writes", round)
			require.Zero(t, derived, "round %d: the cleanup removes the derived entries", round)
			require.Zero(t, bodyCopy, "round %d: the cleanup removes the body copy", round)
			require.Nil(t, a.slot.body.Load(), "round %d: the cleanup removes the body registration", round)
		}
		phase.Store(phaseAfter)
		after.Wait()
		phase.Store(phaseStop)
		wait.Wait()
		for worker := range failures {
			require.Zero(t, failures[worker].Load(), "round %d worker %d: an operation succeeded after Finish", round, worker)
		}
		require.Zero(t, manager.used.Load(), "round %d: all slots must be clean", round)
	}
}

// pinLive pins the slot of the live owner a. A pin try can fail because of
// concurrent pins and unpins (accessBusy): try again.
func pinLive(t *testing.T, m *Manager, a Analysis) {
	t.Helper()
	for {
		switch m.pinOwner(a.slot, a.generation, a.id) {
		case accessDone:
			return
		case accessGone:
			t.Fatal("the owner is not live")
		}
	}
}

// TestGenerationWrap: after a wrap of the 32-bit generation, a stale handle
// has the generation of the new owner; the owner ID tells them apart for
// all the operations.
func TestGenerationWrap(t *testing.T) {
	f := useFakeBits(t)
	manager := NewManager()
	previous := processManager.Swap(manager)
	t.Cleanup(func() { processManager.Store(previous) })
	stale, ok := manager.Acquire(1)
	require.True(t, ok)
	require.Equal(t, uint32(1), stale.generation)
	// No byte of the stale value is in the new source: no content match.
	staleValue, ok := stale.TaintString(param, "old", heapString("QQQQ"))
	require.True(t, ok)
	staleOwner, ok := stale.Owner()
	require.True(t, ok)
	stale.Finish()

	// Inject the state of a free slot before the last generation.
	s := &manager.slots[0]
	s.state.Store(uint64(^uint32(0)-1) << stateGenShift)
	last, ok := manager.Acquire(1)
	require.True(t, ok)
	require.Equal(t, ^uint32(0), last.generation)
	require.True(t, last.Active())
	last.Finish()

	current, ok := manager.Acquire(1)
	require.True(t, ok)
	defer current.Finish()
	require.Equal(t, stale.generation, current.generation, "the generation wrapped to 1")
	require.NotEqual(t, stale.id, current.id)
	value, ok := current.TaintString(param, "new", heapString("new-value"))
	require.True(t, ok)
	currentBody := new([64]byte)
	require.True(t, current.RegisterBody(unsafe.Pointer(currentBody)))

	// The stale handle cannot see or change the new owner.
	require.False(t, stale.Active())
	_, _, _, ok = stale.Identity()
	require.False(t, ok)
	_, ok = manager.Analysis(staleOwner)
	require.False(t, ok)
	_, ok = stale.TaintString(param, "x", heapString("stale-value"))
	require.False(t, ok)
	require.False(t, stale.TaintBytesInPlace(param, "x", heapBytes("stale-bytes")))
	require.False(t, stale.IsSource(value))
	_, ok = stale.Source(0)
	require.False(t, ok)
	require.Zero(t, stale.SourceCount())
	require.Zero(t, stale.Budget())
	var r Attribution
	require.False(t, stale.AttributeString(value, &r))
	require.False(t, stale.RegisterBody(unsafe.Pointer(new([64]byte))))
	require.Equal(t, current.id, s.body.Load().owner, "the body of the new owner stays")
	require.False(t, VisitStringOwner(value, staleOwner, func(ResolvedRange) bool { return true }))
	require.True(t, manager.AttributeStringAny(value, staleOwner, &r))
	require.Equal(t, current.id, r.Owner.ID, "the stale preferred owner is not used")
	require.False(t, manager.use(s, stale.generation, stale.id, func(*ownerData) {}))
	stale.Finish()
	require.True(t, current.Active(), "a stale Finish must not close the new owner")

	// The new owner works.
	require.Equal(t, 1, current.SourceCount())
	require.True(t, current.AttributeString(value, &r))
	source, _ := r.Source(0)
	require.Equal(t, "new", source.Name)
	// The bits of the stale value stay, but no live owner has its source.
	require.True(t, f.any(uintptr(unsafe.Pointer(unsafe.StringData(staleValue))), uintptr(len(staleValue))))
	require.False(t, IsTaintedString(staleValue))
}

// TestRegisterBodyStaleCall: a RegisterBody call of an owner that finishes
// while the call has the slot pinned cannot replace or erase the
// registration of the next owner of the slot.
func TestRegisterBodyStaleCall(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	first, ok := manager.Acquire(1)
	require.True(t, ok)
	firstBody := new([64]byte)

	paused := make(chan struct{})
	resume := make(chan struct{})
	testHookRegisterBody = func() {
		close(paused)
		<-resume
	}
	t.Cleanup(func() { testHookRegisterBody = nil })
	registered := make(chan bool)
	go func() { registered <- first.RegisterBody(unsafe.Pointer(firstBody)) }()
	<-paused
	testHookRegisterBody = nil

	// Finish while the call is between its pin and its store: the slot is
	// not reused before the call unpins.
	first.Finish()
	_, ok = manager.Acquire(1)
	require.False(t, ok, "the slot is pinned: no reuse")
	close(resume)
	require.True(t, <-registered)
	require.Nil(t, manager.slots[0].body.Load(), "the cleanup after the stale store clears the body")

	second, ok := manager.Acquire(1)
	require.True(t, ok)
	defer second.Finish()
	secondBody := new([64]byte)
	require.True(t, second.RegisterBody(unsafe.Pointer(secondBody)))
	// A late call of the first owner: refused.
	require.False(t, first.RegisterBody(unsafe.Pointer(firstBody)))
	ref := manager.slots[0].body.Load()
	require.NotNil(t, ref)
	require.Equal(t, second.id, ref.owner)
	require.Equal(t, unsafe.Pointer(secondBody), unsafe.Pointer(ref.object.Value()))
}

// TestOwnAccessRetries: the access of the owning request retries while a
// different goroutine holds its slot for a short time; when the slot stays
// busy, the drop is counted. A cross-owner scan does not retry.
//
// The test holds the slot lock as a different goroutine does, and a hook
// unlocks it:
// +checklocksignore
func TestOwnAccessRetries(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	defer analysis.Finish()
	value, ok := analysis.TaintString(param, "q", heapString("attacker"))
	require.True(t, ok)

	// The slot stays busy: ownAttempts attempts, then one counted drop.
	s := analysis.slot
	s.mu.Lock()
	drops := OwnBusyDrops()
	var r Attribution
	require.False(t, analysis.AttributeString(value, &r))
	require.Equal(t, drops+1, OwnBusyDrops())
	require.False(t, manager.AttributeStringAny(value, Owner{}, &r), "a scan: one attempt")
	require.Equal(t, drops+1, OwnBusyDrops(), "a scan does not count")
	// The per-call reason (the seam of the woven tests): a busy drop.
	strong, busy := AttributeBytesBusy(analysis, bytesOf(value), &r)
	require.False(t, strong)
	require.True(t, busy, "the call counted a busy drop")
	require.Equal(t, drops+2, OwnBusyDrops())
	s.mu.Unlock()
	strong, busy = AttributeBytesBusy(analysis, bytesOf(value), &r)
	require.True(t, strong)
	require.False(t, busy)

	// The holder releases the slot during the retries.
	s.mu.Lock()
	drops = OwnBusyDrops()
	retries := 0
	testHookOwnRetry = func() {
		retries++
		if retries == 3 {
			s.mu.Unlock()
		}
	}
	t.Cleanup(func() { testHookOwnRetry = nil })
	require.True(t, analysis.AttributeString(value, &r))
	testHookOwnRetry = nil
	require.Equal(t, 3, retries, "the fourth attempt succeeded")
	require.Equal(t, drops, OwnBusyDrops())

	// A finished owner does not retry and does not count.
	analysis.Finish()
	drops = OwnBusyDrops()
	require.False(t, analysis.AttributeString(value, &r))
	require.Equal(t, drops, OwnBusyDrops())
	strong, busy = AttributeBytesBusy(analysis, bytesOf(value), &r)
	require.False(t, strong)
	require.False(t, busy, "a finished owner is not a busy drop")
}

// TestPausedWriterWhileFinish: a writer that holds the slot when Finish
// runs completes its write; the cleanup then releases it.
func TestPausedWriterWhileFinish(t *testing.T) {
	useFakeBits(t)
	manager := NewManager()
	analysis, ok := manager.Acquire(1)
	require.True(t, ok)
	inside := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	value := heapString("attacker")
	go func() {
		defer close(done)
		manager.use(analysis.slot, analysis.generation, analysis.id, func(d *ownerData) {
			close(inside)
			<-release
			d.taint(param, "q", bytesOf(value), SourceString, false)
		})
	}()
	<-inside
	analysis.Finish()
	close(release)
	<-done
	require.Zero(t, manager.used.Load())
	s := &manager.slots[0]
	s.mu.Lock()
	count := s.data.table.Len()
	s.mu.Unlock()
	require.Zero(t, count, "the cleanup ran after the writer")
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"math/bits"
	"runtime"
	"sync"
	"sync/atomic"
	"weak"
)

// MaxAnalyses is the number of owner slots: the largest number of requests
// that can be analyzed at the same time.
const MaxAnalyses = 64

// The state word of a slot (one atomic.Uint64):
//
//	bits 0-23   accessor count (the goroutines that pinned the slot)
//	bit  24     closing: Finish was called; no new pin is possible
//	bit  25     live: the slot has an owner
//	bits 32-63  generation of the owner (never 0 for a live owner)
const (
	stateCountMask = 1<<24 - 1
	stateClosing   = 1 << 24
	stateLive      = 1 << 25
	stateGenShift  = 32

	// pinTries is the number of compare-and-swap tries of a pin. A pin that
	// fails because of concurrent pins and unpins drops the access: no
	// accessor waits.
	pinTries = 4

	// ownAttempts is the number of attempts of an access of the owning
	// request to its own slot (see Manager.useOwn).
	ownAttempts = 8
)

func stateGeneration(state uint64) uint32 { return uint32(state >> stateGenShift) }

// slot is one owner slot. Its permit bit in Manager.used is set while the
// slot has an owner, and also while the cleanup of the last owner is not
// done: a new owner gets only a clean slot.
//
// The lifetime protocol (non-blocking):
//   - every accessor first pins the slot (pin): it increments the accessor
//     count only when the generation is the expected one, the slot is live
//     and not closing;
//   - then it compares owner with the ID of its owner (the generation can
//     repeat after a wrap of the 32-bit counter, the ID cannot): while the
//     slot is pinned, owner does not change;
//   - then it uses TryLock on mu (it drops the access when mu is busy);
//   - it unlocks, then unpins;
//   - Finish sets closing and returns at once. The goroutine whose atomic
//     change reaches "closing and count 0" does the cleanup: Finish itself
//     when no accessor has the slot pinned, else the last accessor.
type slot struct {
	state atomic.Uint64
	// owner is the process-unique ID of the owner (0 when the slot is
	// free). Acquire sets it before the slot becomes live; the cleanup
	// clears it before the slot becomes free.
	owner atomic.Uint64
	index uint8

	// body is the request body object of the owner (see RegisterBody). It
	// is read without the lock by the Read hook.
	body atomic.Pointer[bodyRef]
	// url is the request URL object of the owner (see registerURL). It is
	// read without the lock by the URL.Query hook.
	url atomic.Pointer[urlRef]

	mu sync.Mutex
	// +checklocks:mu
	data ownerData
}

// bodyRef is a weak reference to a request body object. The weak pointer
// does not retain the body, and it cannot match a new object at a reused
// address.
type bodyRef struct {
	// owner is the ID of the owner that registered the body.
	owner  uint64
	object weak.Pointer[byte]
	// offset is the number of body bytes that the Reads wrote.
	offset atomic.Uint64
}

// Manager owns the fixed request-analysis permits and owner slots. Sampling
// occurs before Acquire.
type Manager struct {
	// used has one bit for each slot that is not free. It is also the cheap
	// "is an analysis active" check of the hooks.
	used   atomic.Uint64
	nextID atomic.Uint64
	slots  [MaxAnalyses]slot
}

// Analysis is a generation-captured request analysis handle.
type Analysis struct {
	manager    *Manager
	slot       *slot
	id         uint64
	generation uint32
}

// Owner identifies one generation-validated request owner: the slot index,
// the process-unique ID and the generation of the slot.
type Owner struct {
	ID         uint64
	Generation uint64
	Index      uint8
}

// NewManager returns a manager with all its slots free.
func NewManager() *Manager {
	m := new(Manager)
	for i := range m.slots {
		m.slots[i].index = uint8(i)
	}
	return m
}

// Acquire takes one of max non-blocking permits. max is clamped to [0,64].
// Sampled-out requests must not call Acquire and therefore consume no permit.
// The first activation also turns the sticky taint gate on (so that the
// hooks of reads are on before the first read of the body).
func (m *Manager) Acquire(max int) (Analysis, bool) {
	if m == nil || max <= 0 {
		return Analysis{}, false
	}
	if max > MaxAnalyses {
		max = MaxAnalyses
	}
	var index int
	for {
		current := m.used.Load()
		index = -1
		for i := 0; i < max; i++ {
			if current&(uint64(1)<<i) == 0 {
				index = i
				break
			}
		}
		if index < 0 {
			return Analysis{}, false
		}
		if m.used.CompareAndSwap(current, current|uint64(1)<<index) {
			break
		}
	}
	s := &m.slots[index]
	// The generation can wrap: a stale handle can then have the generation
	// of the new owner. All the accesses thus also compare the owner ID,
	// which cannot repeat.
	generation := stateGeneration(s.state.Load()) + 1
	if generation == 0 {
		generation = 1
	}
	id := m.nextID.Add(1)
	// No accessor can hold mu: the slot is not live, so no pin succeeds, and
	// the cleanup of the last owner is done (else its bit is still set).
	if !s.mu.TryLock() {
		m.used.And(^(uint64(1) << index))
		return Analysis{}, false
	}
	s.data.start() // +checklocksforce: TryLock succeeded.
	s.mu.Unlock()  // +checklocksforce: TryLock succeeded.
	s.owner.Store(id)
	s.state.Store(uint64(generation)<<stateGenShift | stateLive)
	bitsMarkLive()
	return Analysis{manager: m, slot: s, id: id, generation: generation}, true
}

// access is the result of one access attempt to a slot.
type access uint8

const (
	// accessDone: the access ran.
	accessDone access = iota
	// accessGone: the owner is not live (finished, closing or replaced).
	accessGone
	// accessBusy: concurrent accessors made the attempt fail.
	accessBusy
)

// pin increments the accessor count of s when its owner is the live owner of
// generation. It does not compare the owner ID (see Manager.pinOwner).
func (s *slot) pin(generation uint32) access {
	for range pinTries {
		state := s.state.Load()
		if stateGeneration(state) != generation || state&stateLive == 0 || state&stateClosing != 0 {
			return accessGone
		}
		if state&stateCountMask == stateCountMask {
			return accessBusy
		}
		if s.state.CompareAndSwap(state, state+1) {
			return accessDone
		}
	}
	return accessBusy
}

// pinOwner pins s when (generation, id) is its live owner. On accessDone,
// the caller must call unpin.
func (m *Manager) pinOwner(s *slot, generation uint32, id uint64) access {
	if result := s.pin(generation); result != accessDone {
		return result
	}
	// The pin keeps the owner: owner cannot change before unpin.
	if s.owner.Load() != id {
		m.unpin(s)
		return accessGone
	}
	return accessDone
}

// unpin decrements the accessor count of s. The last accessor of a closing
// slot does the cleanup.
func (m *Manager) unpin(s *slot) {
	state := s.state.Add(^uint64(0))
	if state&stateClosing != 0 && state&stateCountMask == 0 {
		m.cleanup(s)
	}
}

// cleanup clears the data of s and frees its permit. Only one goroutine calls
// it for one owner: the one whose change reached "closing and count 0". No
// accessor holds mu then (each accessor unlocks before it unpins), so Lock
// does not wait.
func (m *Manager) cleanup(s *slot) {
	s.body.Store(nil)
	s.url.Store(nil)
	s.mu.Lock()
	s.data.clear()
	s.mu.Unlock()
	s.owner.Store(0)
	generation := stateGeneration(s.state.Load())
	s.state.Store(uint64(generation) << stateGenShift)
	m.used.And(^(uint64(1) << s.index))
}

// tryUse runs f with the data of the owner (s, generation, id), with the
// protocol of slot (one attempt).
func (m *Manager) tryUse(s *slot, generation uint32, id uint64, f func(d *ownerData)) access {
	if result := m.pinOwner(s, generation, id); result != accessDone {
		return result
	}
	defer m.unpin(s)
	if !s.mu.TryLock() {
		return accessBusy
	}
	defer s.mu.Unlock() // +checklocksforce: TryLock succeeded.
	f(&s.data)          // +checklocksforce: TryLock succeeded.
	return accessDone
}

// use runs f with the data of the owner (s, generation, id). It returns
// false (and does not run f) when the owner is not live, is closing, or
// when the slot is busy (one attempt: no accessor waits).
func (m *Manager) use(s *slot, generation uint32, id uint64, f func(d *ownerData)) bool {
	return m.tryUse(s, generation, id, f) == accessDone
}

// ownBusyDrops counts the accesses of owning requests to their own slot
// that useOwn dropped because the slot stayed busy.
var ownBusyDrops atomic.Uint64

// OwnBusyDrops returns the number of accesses of owning requests to their
// own slot (sink attribution, visits, body registration) that were dropped
// because the slot stayed busy for all the attempts (telemetry).
func OwnBusyDrops() uint64 { return ownBusyDrops.Load() }

// useOwn is use for an access of the owning request to its own slot: the
// sink of the request, a visit on the context of the request, and the body
// registration. A different goroutine can hold the slot for a short time
// (for example a scan of all the owners by IsTainted* or by a propagation
// callback). A drop here is a missed report of the request itself, thus
// useOwn tries ownAttempts times, with runtime.Gosched between attempts. It
// never sleeps and never waits for the lock: the work stays bounded. When
// all the attempts fail, it counts the drop in ownBusyDrops. The scans of
// all the owners use only one attempt (use).
func (m *Manager) useOwn(s *slot, generation uint32, id uint64, f func(d *ownerData)) bool {
	for attempt := 1; ; attempt++ {
		switch m.tryUse(s, generation, id, f) {
		case accessDone:
			return true
		case accessGone:
			return false
		}
		if attempt >= ownAttempts {
			ownBusyDrops.Add(1)
			return false
		}
		if hook := testHookOwnRetry; hook != nil {
			hook()
		}
		runtime.Gosched()
	}
}

// testHookOwnRetry is nil, except in the unit tests: useOwn calls it before
// each retry.
var testHookOwnRetry func()

// Active reports whether the captured analysis is the live owner of its slot
// and not closing.
func (a Analysis) Active() bool {
	if a.manager == nil || a.slot == nil {
		return false
	}
	state := a.slot.state.Load()
	return stateGeneration(state) == a.generation && state&stateLive != 0 && state&stateClosing == 0 && a.slot.owner.Load() == a.id
}

// Identity returns the slot index, ID and generation of the owner.
func (a Analysis) Identity() (index uint8, id, generation uint64, ok bool) {
	if !a.Active() {
		return 0, 0, 0, false
	}
	return a.slot.index, a.id, uint64(a.generation), true
}

// Owner returns the identity of the owner of a.
func (a Analysis) Owner() (Owner, bool) {
	index, id, generation, ok := a.Identity()
	return Owner{ID: id, Generation: generation, Index: index}, ok
}

// Analysis returns the analysis of owner when it is still live.
func (m *Manager) Analysis(owner Owner) (Analysis, bool) {
	if m == nil || int(owner.Index) >= MaxAnalyses || owner.ID == 0 || owner.Generation == 0 || owner.Generation > uint64(^uint32(0)) {
		return Analysis{}, false
	}
	a := Analysis{manager: m, slot: &m.slots[owner.Index], id: owner.ID, generation: uint32(owner.Generation)}
	if !a.Active() {
		return Analysis{}, false
	}
	return a, true
}

// Finish releases the analysis of this exact owner. It is idempotent, and
// it never waits for an accessor: when an accessor has the slot pinned, the
// last accessor does the cleanup. A stale handle cannot finish a reused
// slot, also after a wrap of the generation.
//
// Finish first pins the slot, so that it can compare the owner ID (the pin
// keeps the owner), then sets closing. Its unpin does the cleanup when no
// other accessor has the slot pinned. A failed pin try means that a
// different accessor changed the state (lock-free progress), thus Finish
// tries again until the pin succeeds or the owner is gone: Finish must not
// leave the slot live.
func (a Analysis) Finish() {
	if a.manager == nil || a.slot == nil {
		return
	}
	s := a.slot
	for {
		result := a.manager.pinOwner(s, a.generation, a.id)
		if result == accessGone {
			return
		}
		if result == accessDone {
			break
		}
		// The count is full (not possible in practice: one pin is one
		// goroutine in a short access): yield, then try again.
		runtime.Gosched()
	}
	defer a.manager.unpin(s)
	for {
		state := s.state.Load()
		if state&stateClosing != 0 {
			return
		}
		if s.state.CompareAndSwap(state, state|stateClosing) {
			return
		}
	}
}

// Active reports whether at least one owner slot is not free. It is the
// cheap check of the hooks.
func (m *Manager) Active() bool {
	return m != nil && m.used.Load() != 0
}

// forEachActive calls f for each live owner of m, until f returns false.
// The generation and the ID are two loads: when the owner changes between
// them, the access of f fails (pinOwner compares both).
func (m *Manager) forEachActive(f func(s *slot, generation uint32, id uint64) bool) {
	used := m.used.Load()
	for used != 0 {
		i := bits.TrailingZeros64(used)
		used &= used - 1
		s := &m.slots[i]
		state := s.state.Load()
		if state&stateLive == 0 || state&stateClosing != 0 {
			continue
		}
		id := s.owner.Load()
		if id == 0 {
			continue
		}
		if !f(s, stateGeneration(state), id) {
			return
		}
	}
}

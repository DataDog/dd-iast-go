// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"sync"
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

const MaxAnalyses = store.MaxOwners

type analysisSlot struct {
	generation atomic.Uint64
	active     atomic.Bool
	ownerID    atomic.Uint64
	ownerGen   atomic.Uint64
	table      Table
	sourceMu   sync.Mutex
	owner      atomic.Pointer[store.Owner]
}

// Manager owns the fixed request-analysis permits and taint store. Sampling is
// intentionally deferred to Phase 3 and occurs before Acquire.
type Manager struct {
	store     *store.Store
	used      atomic.Uint64
	slots     [MaxAnalyses]analysisSlot
	directory [MaxAnalyses]atomic.Pointer[analysisSlot]
}

// Analysis is a generation-captured request analysis handle.
type Analysis struct {
	manager    *Manager
	slot       *analysisSlot
	index      uint8
	ownerIndex uint8
	gen        uint64
}

// NewManager returns a manager over taintStore. A nil store creates one.
func NewManager(taintStore *store.Store) *Manager {
	if taintStore == nil {
		taintStore = store.New()
	}
	return &Manager{store: taintStore}
}

// Acquire takes one of max non-blocking permits. max is clamped to [0,64].
// Sampled-out requests must not call Acquire and therefore consume no permit.
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
	slot := &m.slots[index]
	storeOwner := m.store.Acquire()
	if storeOwner.Disabled() {
		m.used.And(^(uint64(1) << index))
		return Analysis{}, false
	}
	ownerIndex, validIndex := storeOwner.Index()
	if !validIndex {
		storeOwner.Finish()
		m.used.And(^(uint64(1) << index))
		return Analysis{}, false
	}
	slot.sourceMu.Lock()
	slot.table.Reset()
	slot.sourceMu.Unlock()
	generation := slot.generation.Add(1)
	slot.owner.Store(storeOwner)
	slot.ownerID.Store(storeOwner.ID())
	slot.ownerGen.Store(storeOwner.Generation())
	m.directory[ownerIndex].Store(slot)
	slot.active.Store(true)
	return Analysis{manager: m, slot: slot, index: uint8(index), ownerIndex: ownerIndex, gen: generation}, true
}

// Active reports whether the captured analysis generation is live.
func (a Analysis) Active() bool {
	return a.manager != nil && a.slot != nil && a.slot.generation.Load() == a.gen && a.slot.active.Load()
}

// TaintString transactionally publishes a managed string source. The source
// table is changed only after store publication succeeds.
func (a Analysis) TaintString(origin constants.Origin, name, value string) (string, bool) {
	if !a.Active() || !a.slot.sourceMu.TryLock() {
		return value, false
	}
	defer a.slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !a.Active() {
		return value, false
	}
	result, token := a.slot.table.prepareString(origin, name, value)
	if result.Status != AddAdded && result.Status != AddDuplicate {
		return value, false
	}
	owner := a.slot.owner.Load()
	if owner == nil || owner.Disabled() {
		return value, false
	}
	if result.Status == AddDuplicate {
		managed, _, ok := owner.TaintString(value, result.ID)
		return managed, ok
	}
	managed, managedName, _, ok := owner.TaintSourceString(value, name, result.ID)
	if !ok {
		return value, false
	}
	a.slot.table.commit(token, Source{Origin: origin, Name: managedName, Value: managed})
	return managed, true
}

// TaintBytes transactionally publishes managed mutable bytes and immutable
// source metadata. The source table is changed only after publication succeeds.
func (a Analysis) TaintBytes(origin constants.Origin, name string, value []byte) ([]byte, bool) {
	if !a.Active() || !a.slot.sourceMu.TryLock() {
		return value, false
	}
	defer a.slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !a.Active() {
		return value, false
	}
	result, token := a.slot.table.prepareBytes(origin, name, value)
	if result.Status != AddAdded && result.Status != AddDuplicate {
		return value, false
	}
	owner := a.slot.owner.Load()
	if owner == nil || owner.Disabled() {
		return value, false
	}
	if result.Status == AddDuplicate {
		managed, _, ok := owner.TaintBytes(value, result.ID)
		return managed, ok
	}
	managed, managedName, managedValue, _, ok := owner.TaintSourceBytes(value, name, result.ID)
	if !ok {
		return value, false
	}
	a.slot.table.commit(token, Source{Origin: origin, Name: managedName, Value: managedValue})
	return managed, true
}

// Source returns a copied source record while the analysis is active.
func (a Analysis) Source(id SourceID) (Source, bool) {
	if !a.Active() || !a.slot.sourceMu.TryLock() {
		return Source{}, false
	}
	defer a.slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !a.Active() {
		return Source{}, false
	}
	return a.slot.table.Get(id)
}

// SourceCount returns the current bounded source count.
func (a Analysis) SourceCount() int {
	if !a.Active() || !a.slot.sourceMu.TryLock() {
		return 0
	}
	defer a.slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !a.Active() {
		return 0
	}
	return a.slot.table.Len()
}

// Finish idempotently releases roots, sources, and the permit for this exact
// generation. A stale handle cannot finish a reused slot.
func (a Analysis) Finish() {
	if a.manager == nil || a.slot == nil || a.slot.generation.Load() != a.gen || !a.slot.active.CompareAndSwap(true, false) {
		return
	}
	a.manager.directory[a.ownerIndex].CompareAndSwap(a.slot, nil)
	a.slot.sourceMu.Lock()
	a.slot.table.Reset()
	a.slot.ownerID.Store(0)
	a.slot.ownerGen.Store(0)
	a.slot.sourceMu.Unlock()
	if owner := a.slot.owner.Swap(nil); owner != nil {
		owner.Finish()
	}
	a.manager.used.And(^(uint64(1) << a.index))
}

// Store returns the manager's process store.
func (m *Manager) Store() *store.Store {
	if m == nil {
		return nil
	}
	return m.store
}

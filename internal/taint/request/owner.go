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
	table      Table
	sourceMu   sync.Mutex
	owner      atomic.Pointer[store.Owner]
}

// Manager owns the fixed request-analysis permits and taint store. Sampling is
// intentionally deferred to Phase 3 and occurs before Acquire.
type Manager struct {
	store *store.Store
	used  atomic.Uint64
	slots [MaxAnalyses]analysisSlot
}

// Analysis is a generation-captured request analysis handle.
type Analysis struct {
	manager *Manager
	slot    *analysisSlot
	index   uint8
	gen     uint64
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
	slot.sourceMu.Lock()
	slot.table.Reset()
	slot.sourceMu.Unlock()
	generation := slot.generation.Add(1)
	slot.owner.Store(storeOwner)
	slot.active.Store(true)
	return Analysis{manager: m, slot: slot, index: uint8(index), gen: generation}, true
}

// Active reports whether the captured analysis generation is live.
func (a Analysis) Active() bool {
	return a.manager != nil && a.slot != nil && a.slot.generation.Load() == a.gen && a.slot.active.Load()
}

// AddSource adds or finds one request source without waiting on concurrent
// source-table work.
func (a Analysis) AddSource(origin constants.Origin, name, value string) AddResult {
	if !a.Active() || !a.slot.sourceMu.TryLock() {
		return AddResult{Status: AddRejected}
	}
	defer a.slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !a.Active() {
		return AddResult{Status: AddRejected}
	}
	return a.slot.table.Add(origin, name, value)
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

// StoreOwner returns the bounded store handle while active.
func (a Analysis) StoreOwner() *store.Owner {
	if !a.Active() {
		return nil
	}
	return a.slot.owner.Load()
}

// Finish idempotently releases roots, sources, and the permit for this exact
// generation. A stale handle cannot finish a reused slot.
func (a Analysis) Finish() {
	if a.manager == nil || a.slot == nil || a.slot.generation.Load() != a.gen || !a.slot.active.CompareAndSwap(true, false) {
		return
	}
	if owner := a.slot.owner.Swap(nil); owner != nil {
		owner.Finish()
	}
	a.slot.sourceMu.Lock()
	a.slot.table.Reset()
	a.slot.sourceMu.Unlock()
	a.manager.used.And(^(uint64(1) << a.index))
}

// Store returns the manager's process store.
func (m *Manager) Store() *store.Store {
	if m == nil {
		return nil
	}
	return m.store
}

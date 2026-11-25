// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "sync/atomic"

const (
	slabSize = 1 << 20
	maxSlabs = 1024
)

var (
	runtimeAccountSlab   func()
	runtimePublishSlab   func(uintptr) bool
	runtimeReadySlabs    func() uint32
	runtimeTakeRefill    func() bool
	runtimeAllocateUnits func(uint32) uint32
	runtimeSlabAddress   func(uint32) uintptr
	runtimeSetQueue      func(uint32, uint32) bool
	runtimeQueueEntry    func(uint32) uint32
)

type slabAllocator struct {
	limit    uint64
	reserved atomic.Uint64
	mapped   atomic.Uint64
	mapFn    func() ([]byte, bool)
	account  func()
}

func newSlabAllocator(limit uint64) *slabAllocator {
	if limit > slabSize*maxSlabs {
		limit = slabSize * maxSlabs
	}
	return &slabAllocator{
		limit:   limit / slabSize * slabSize,
		mapFn:   mapSlab,
		account: runtimeAccountSlab,
	}
}

// allocate is only for initialization and the background refiller.
func (a *slabAllocator) allocate() ([]byte, bool) {
	if a.account == nil {
		return nil, false
	}
	for {
		used := a.reserved.Load()
		if used >= a.limit {
			return nil, false
		}
		if a.reserved.CompareAndSwap(used, used+slabSize) {
			break
		}
	}
	memory, ok := a.mapFn()
	if !ok {
		a.reserved.Add(^uint64(slabSize - 1))
		return nil, false
	}
	a.account()
	a.mapped.Add(slabSize)
	return memory, true
}

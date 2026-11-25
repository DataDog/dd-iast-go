// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package runtime

import (
	ddheapatomic "internal/runtime/atomic"
	_ "unsafe"
)

var (
	ddiastHeapGate ddheapatomic.Uint32
	_              *sysMemStat                              = &memstats.other_sys
	_              *ddheapatomic.Uint64                     = &gcController.mappedReady
	_              func(*sysMemStat, int64)                 = (*sysMemStat).add
	_              func(*ddheapatomic.Uint64, int64) uint64 = (*ddheapatomic.Uint64).Add
)

//go:linkname ddiastHeapRangesNeedRuntime runtime.ddiastHeapRangesNeedTheWovenRuntime
func ddiastHeapRangesNeedRuntime() {}

//go:linkname ddiastHeapRangesGate github.com/DataDog/dd-iast-go/internal/taint/heapranges.runtimeGate
func ddiastHeapRangesGate() uint32 {
	return ddiastHeapGate.Load()
}

//go:linkname ddiastHeapRangesAccountSlab github.com/DataDog/dd-iast-go/internal/taint/heapranges.accountSlab
//go:nosplit
func ddiastHeapRangesAccountSlab() {
	memstats.other_sys.add(1 << 20)
	gcController.mappedReady.Add(1 << 20)
}

const (
	ddiastSlabCount = 1024
	ddiastSlabUnits = 1 << 14
	ddiastSlabBusy  = ^uint32(0)
)

type ddiastSlab struct {
	base uintptr
	bump ddheapatomic.Uint32
	next uint32
}

var (
	ddiastSlabs        [ddiastSlabCount]ddiastSlab
	ddiastSlabsUsed    ddheapatomic.Uint32
	ddiastReadyHead    ddheapatomic.Uint32
	ddiastReadyCount   ddheapatomic.Uint32
	ddiastCurrentSlab  ddheapatomic.Uint32
	ddiastSlabTailLost ddheapatomic.Uint64
	ddiastRefill       ddheapatomic.Uint32
	ddiastQueues       [ddiastSlabCount]ddheapatomic.Uint32
)

//go:linkname ddiastPublishSlab github.com/DataDog/dd-iast-go/internal/taint/heapranges.publishSlab
func ddiastPublishSlab(base uintptr) bool {
	if base == 0 || base&63 != 0 {
		return false
	}
	for {
		count := ddiastReadyCount.Load()
		if count >= 2 {
			return false
		}
		if ddiastReadyCount.CompareAndSwap(count, count+1) {
			break
		}
	}
	var index uint32
	for {
		index = ddiastSlabsUsed.Load()
		if index >= ddiastSlabCount {
			ddiastReadyCount.Add(-1)
			return false
		}
		if ddiastSlabsUsed.CompareAndSwap(index, index+1) {
			break
		}
	}
	slab := &ddiastSlabs[index]
	slab.base = base
	for {
		head := ddiastReadyHead.Load()
		slab.next = head
		if ddiastReadyHead.CompareAndSwap(head, index+1) {
			return true
		}
	}
}

//go:linkname ddiastReadySlabs github.com/DataDog/dd-iast-go/internal/taint/heapranges.readySlabs
func ddiastReadySlabs() uint32 { return ddiastReadyCount.Load() }

//go:linkname ddiastTakeRefill github.com/DataDog/dd-iast-go/internal/taint/heapranges.takeRefill
func ddiastTakeRefill() bool { return ddiastRefill.Swap(0) != 0 }

//go:linkname ddiastTailUnits github.com/DataDog/dd-iast-go/internal/taint/heapranges.tailUnits
func ddiastTailUnits() uint64 { return ddiastSlabTailLost.Load() }

//go:linkname ddiastAllocateUnits github.com/DataDog/dd-iast-go/internal/taint/heapranges.allocateUnits
//go:nosplit
func ddiastAllocateUnits(units uint32) uint32 {
	if units == 0 || units > ddiastSlabUnits {
		return 0
	}
	current := ddiastCurrentSlab.Load()
	if current == ddiastSlabBusy || current > ddiastSlabCount {
		return 0
	}
	if current != 0 {
		slab := &ddiastSlabs[current-1]
		if slab.bump.Load() <= ddiastSlabUnits-units {
			start := slab.bump.Add(int32(units)) - units
			if start <= ddiastSlabUnits-units {
				return ((current-1)<<14 | start) + 1
			}
		}
	}
	if !ddiastCurrentSlab.CompareAndSwap(current, ddiastSlabBusy) {
		return 0
	}
	head := ddiastReadyHead.Load()
	if head == 0 || head > ddiastSlabCount || !ddiastReadyHead.CompareAndSwap(head, ddiastSlabs[head-1].next) {
		ddiastCurrentSlab.Store(current)
		ddiastRefill.Store(1)
		return 0
	}
	ddiastReadyCount.Add(-1)
	if current != 0 {
		// A late writer must not use a tail that is counted as lost.
		used := ddiastSlabs[current-1].bump.Swap(ddiastSlabUnits)
		if used < ddiastSlabUnits {
			ddiastSlabTailLost.Add(int64(ddiastSlabUnits - used))
		}
	}
	ddiastCurrentSlab.Store(head)
	ddiastRefill.Store(1)
	start := ddiastSlabs[head-1].bump.Add(int32(units)) - units
	if start > ddiastSlabUnits-units {
		return 0
	}
	return ((head-1)<<14 | start) + 1
}

//go:linkname ddiastSlabAddress github.com/DataDog/dd-iast-go/internal/taint/heapranges.slabAddress
//go:nosplit
func ddiastSlabAddress(entry uint32) uintptr {
	if entry == 0 {
		return 0
	}
	index := entry - 1
	slab := index >> 14
	if slab >= ddiastSlabCount || slab >= ddiastSlabsUsed.Load() {
		return 0
	}
	return ddiastSlabs[slab].base + uintptr(index&(ddiastSlabUnits-1))*64
}

//go:linkname ddiastSetQueue github.com/DataDog/dd-iast-go/internal/taint/heapranges.setQueue
func ddiastSetQueue(index, entry uint32) bool {
	if index >= ddiastSlabCount || entry == 0 {
		return false
	}
	return ddiastQueues[index].CompareAndSwap(0, entry)
}

//go:linkname ddiastQueue github.com/DataDog/dd-iast-go/internal/taint/heapranges.queueEntry
func ddiastQueue(index uint32) uint32 {
	if index >= ddiastSlabCount {
		return 0
	}
	return ddiastQueues[index].Load()
}

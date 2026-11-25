// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package heapranges

import (
	ddheapknobs "github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
	_ "unsafe"
)

//go:linkname runtimeGate
func runtimeGate() uint32

//go:linkname needWovenRuntime runtime.ddiastHeapRangesNeedTheWovenRuntime
func needWovenRuntime()

//go:linkname accountSlab
func accountSlab()

//go:linkname publishSlab
func publishSlab(uintptr) bool

//go:linkname readySlabs
func readySlabs() uint32

//go:linkname takeRefill
func takeRefill() bool

//go:linkname tailUnits
func tailUnits() uint64

//go:linkname allocateUnits
func allocateUnits(uint32) uint32

//go:linkname slabAddress
func slabAddress(uint32) uintptr

//go:linkname setQueue
func setQueue(uint32, uint32) bool

//go:linkname queueEntry
func queueEntry(uint32) uint32

var _ = func() bool {
	needWovenRuntime()
	ddheapknobs.Gate = runtimeGate
	ddheapknobs.OffReason = func() string { return offReason }
	ddheapknobs.MapSlab = func(skipAccounting bool) (bool, uint64) {
		allocator := newSlabAllocator(slabSize)
		if skipAccounting {
			allocator.account = func() {}
		}
		_, ok := allocator.allocate()
		return ok, allocator.mapped.Load()
	}
	ddheapknobs.InitSlabWorker = func(limit uint64) (uint32, uint64, bool) {
		worker, ok := newSlabWorker(limit)
		if !ok {
			return 0, 0, false
		}
		ddheapknobs.RefillOnce = worker.refillOnce
		ddheapknobs.StartRefiller = func() { go worker.run() }
		ddheapknobs.PauseRefiller = func(paused bool) { worker.paused.Store(paused) }
		ddheapknobs.WorkerStats = func() (uint32, uint64) {
			return worker.queues.Load(), worker.allocator.mapped.Load()
		}
		return worker.queues.Load(), worker.allocator.mapped.Load(), true
	}
	ddheapknobs.QueueEntry = queueEntry
	ddheapknobs.PublishSlab = publishSlab
	ddheapknobs.AllocateUnits = allocateUnits
	ddheapknobs.TailUnits = tailUnits
	ddheapknobs.SlabAddress = slabAddress
	ddheapknobs.ReadySlabs = readySlabs
	runtimeAccountSlab = accountSlab
	runtimePublishSlab = publishSlab
	runtimeReadySlabs = readySlabs
	runtimeTakeRefill = takeRefill
	runtimeAllocateUnits = allocateUnits
	runtimeSlabAddress = slabAddress
	runtimeSetQueue = setQueue
	runtimeQueueEntry = queueEntry
	runtimeEnabled = func() bool { return runtimeGate() == 1 }
	return true
}()

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	queueBytes = 16 << 10
	unitBytes  = 64
	probeBytes = 64 << 10
)

var slabWorkerClaimed atomic.Bool

type slabWorker struct {
	allocator  *slabAllocator
	queueLimit uint32
	queues     atomic.Uint32
	paused     atomic.Bool
}

func newSlabWorker(limit uint64) (*slabWorker, bool) {
	if limit < slabSize || runtimePublishSlab == nil || runtimeReadySlabs == nil || runtimeTakeRefill == nil || runtimeAllocateUnits == nil || runtimeSetQueue == nil || !slabWorkerClaimed.CompareAndSwap(false, true) {
		return nil, false
	}
	allocator := newSlabAllocator(limit)
	if limit > slabSize*maxSlabs {
		limit = slabSize * maxSlabs
	}
	queueLimit := limit / 4 / queueBytes
	if queueLimit > maxSlabs {
		queueLimit = maxSlabs
	}
	worker := &slabWorker{allocator: allocator, queueLimit: uint32(queueLimit)}
	target := worker.targetQueues()
	if !worker.allocateQueues(target) {
		return nil, false
	}
	needed := (uint64(target)*queueBytes + probeBytes + slabSize - 1) / slabSize
	for allocator.mapped.Load()/slabSize < needed {
		if !worker.publishOne() {
			return nil, false
		}
	}
	return worker, true
}

func (w *slabWorker) targetQueues() uint32 {
	count := uint32(runtime.GOMAXPROCS(0))
	if count > w.queueLimit {
		return w.queueLimit
	}
	return count
}

func (w *slabWorker) publishOne() bool {
	if runtimeReadySlabs() >= 2 {
		return false
	}
	memory, ok := w.allocator.allocate()
	if !ok || len(memory) != slabSize {
		return false
	}
	return runtimePublishSlab(uintptr(unsafe.Pointer(&memory[0])))
}

func (w *slabWorker) allocateQueues(target uint32) bool {
	for index := w.queues.Load(); index < target; index++ {
		entry := runtimeAllocateUnits(queueBytes / unitBytes)
		if entry == 0 {
			if runtimeReadySlabs() != 0 || !w.publishOne() {
				return false
			}
			entry = runtimeAllocateUnits(queueBytes / unitBytes)
			if entry == 0 {
				return false
			}
		}
		if !runtimeSetQueue(index, entry) {
			return false
		}
		w.queues.Store(index + 1)
	}
	return true
}

func (w *slabWorker) refillOnce() {
	if w.paused.Load() {
		return
	}
	w.allocateQueues(w.targetQueues())
	if !runtimeTakeRefill() && runtimeReadySlabs() >= 2 {
		return
	}
	for runtimeReadySlabs() < 2 {
		if !w.publishOne() {
			return
		}
	}
}

func (w *slabWorker) run() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		w.refillOnce()
	}
}

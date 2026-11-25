// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"runtime"
	"testing"
)

func TestWorkerMapsBeforeQueues(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(128)
	defer runtime.GOMAXPROCS(oldProcs)
	oldPublish, oldReady := runtimePublishSlab, runtimeReadySlabs
	oldAllocate, oldSet := runtimeAllocateUnits, runtimeSetQueue
	defer func() {
		runtimePublishSlab, runtimeReadySlabs = oldPublish, oldReady
		runtimeAllocateUnits, runtimeSetQueue = oldAllocate, oldSet
	}()
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "mapping failure"
		}
		t.Run(name, func(t *testing.T) {
			var maps, published, allocations, queues, ready, available uint32
			var premature bool
			memory := make([]byte, slabSize)
			allocator := newSlabAllocator(64 << 20)
			allocator.mapFn = func() ([]byte, bool) {
				maps++
				if fail && maps == 2 {
					return nil, false
				}
				return memory, true
			}
			allocator.account = func() {}
			runtimePublishSlab = func(uintptr) bool {
				premature = premature || maps != 3
				published++
				ready++
				return true
			}
			runtimeReadySlabs = func() uint32 { return ready }
			runtimeAllocateUnits = func(units uint32) uint32 {
				premature = premature || maps != 3 || units != queueBytes/unitBytes
				allocations++
				if available == 0 {
					if ready == 0 {
						return 0
					}
					ready--
					available = slabSize / queueBytes
				}
				available--
				return allocations
			}
			runtimeSetQueue = func(index, entry uint32) bool {
				if index != queues || entry == 0 {
					t.Errorf("queue %d has entry %d, want index %d", index, entry, queues)
				}
				queues++
				return true
			}
			worker, ok := initializeSlabWorker(64<<20, allocator)
			if fail {
				if ok || worker != nil || maps != 2 || published != 0 || allocations != 0 || queues != 0 {
					t.Fatalf("failed initialization: ok=%t maps=%d published=%d allocations=%d queues=%d", ok, maps, published, allocations, queues)
				}
				return
			}
			if !ok || worker == nil || premature || maps != 3 || published != 3 || queues != 128 || ready != 1 {
				t.Fatalf("initialization: ok=%t premature=%t maps=%d published=%d queues=%d ready=%d", ok, premature, maps, published, queues, ready)
			}
		})
	}
}

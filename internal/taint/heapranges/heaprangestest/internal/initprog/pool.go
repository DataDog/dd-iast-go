// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func exerciseSlabTail() bool {
	if knobs.PublishSlab == nil || knobs.AllocateUnits == nil || knobs.TailUnits == nil {
		return false
	}
	if !knobs.PublishSlab(0x10000000) || !knobs.PublishSlab(0x20000000) {
		return false
	}
	first := knobs.AllocateUnits((1 << 14) - 1)
	second := knobs.AllocateUnits(2)
	third := knobs.AllocateUnits(1)
	return first != 0 && second != 0 && third != 0 && (first-1)>>14 != (second-1)>>14 &&
		(second-1)>>14 == (third-1)>>14 && knobs.TailUnits() == 1
}

func exerciseSlabPool() (int, bool) {
	if knobs.PublishSlab == nil || knobs.AllocateUnits == nil || knobs.SlabAddress == nil {
		return 0, false
	}
	if knobs.AllocateUnits(1) != 0 || knobs.PublishSlab(0) || knobs.PublishSlab(17) ||
		!knobs.PublishSlab(0x10000000) || !knobs.PublishSlab(0x20000000) || knobs.PublishSlab(0x30000000) ||
		knobs.AllocateUnits(0) != 0 || knobs.AllocateUnits((1<<14)+1) != 0 || knobs.SlabAddress(0) != 0 {
		return 0, false
	}
	var lock sync.Mutex
	seen := make(map[uint32]bool)
	var failed atomic.Bool
	var group sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for i := 0; i < 3000; i++ {
				var entry uint32
				for attempt := 0; attempt < 10000 && entry == 0; attempt++ {
					entry = knobs.AllocateUnits(1)
					if entry == 0 {
						runtime.Gosched()
					}
				}
				if entry == 0 {
					failed.Store(true)
					return
				}
				index := entry - 1
				slab := index >> 14
				if slab > 1 {
					failed.Store(true)
					return
				}
				base := uintptr(0x10000000) + uintptr(slab)*0x10000000
				if knobs.SlabAddress(entry) != base+uintptr(index&((1<<14)-1))*64 {
					failed.Store(true)
					return
				}
				lock.Lock()
				if seen[entry] {
					failed.Store(true)
				}
				seen[entry] = true
				lock.Unlock()
			}
		}()
	}
	group.Wait()
	return len(seen), !failed.Load()
}

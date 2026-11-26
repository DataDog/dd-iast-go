// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"math"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func exerciseTable() bool {
	if knobs.InitSlabWorker == nil || knobs.AllocateUnits == nil || knobs.BindTable == nil || knobs.SpanRead == nil || knobs.TableBase == nil || knobs.TableEntry == nil {
		return false
	}
	_, _, ok := knobs.InitSlabWorker(1 << 20)
	if !ok {
		return false
	}
	entry := knobs.AllocateUnits(65)
	if entry == 0 || knobs.TableBase(entry) != 0 || knobs.BindTable(entry, 0) {
		return false
	}
	var wins [2]atomic.Uint32
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			base := uintptr(i%2+1) * 0x100000
			if knobs.BindTable(entry, base) {
				wins[i%2].Add(1)
			}
		}(i)
	}
	group.Wait()
	base := uintptr(knobs.TableBase(entry))
	if (base != 0x100000 && base != 0x200000) || wins[base/0x100000-1].Load() != 16 || wins[2-base/0x100000].Load() != 0 {
		return false
	}
	if knobs.TableEntry(entry, 0, 7, true) != 7 || knobs.TableEntry(entry, 1023, 9, true) != 9 || knobs.TableEntry(entry, 1024, 11, true) != 0 {
		return false
	}
	other := uintptr(0x300000) - base
	return knobs.BindTable(entry, base) && !knobs.BindTable(entry, other) &&
		knobs.TableEntry(entry, 0, 0, false) == 7 && knobs.TableEntry(entry, 1023, 0, false) == 9 &&
		knobs.SpanRead(entry) && exerciseEntryState()
}

func exerciseEntryState() bool {
	if knobs.CompareEntry == nil || knobs.ReadEntry == nil || knobs.SpanState == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	large := new([65536]byte)
	largePointer := unsafe.Pointer(&large[0])
	if knobs.SpanState(largePointer) != 0 || !knobs.CompareEntry(largePointer, 0, 7) ||
		knobs.SpanState(largePointer) != uint64(7)<<32|2 || knobs.ReadEntry(largePointer) != 7 ||
		knobs.CompareEntry(largePointer, 0, 8) || !knobs.CompareEntry(largePointer, 7, 0) ||
		knobs.SpanState(largePointer) != 0 {
		return false
	}
	small := new([256]byte)
	smallPointer := unsafe.Pointer(&small[0])
	var wins atomic.Uint32
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if knobs.CompareEntry(smallPointer, 0, 7) {
				wins.Add(1)
			}
		}()
	}
	group.Wait()
	state := knobs.SpanState(smallPointer)
	if wins.Load() != 1 || state == 0 || state&63 != 0 || knobs.ReadEntry(smallPointer) != 7 ||
		knobs.CompareEntry(smallPointer, 0, 8) || !knobs.CompareEntry(smallPointer, 7, 0) ||
		knobs.SpanState(smallPointer) != state || !knobs.CompareEntry(smallPointer, 0, 9) ||
		knobs.ReadEntry(smallPointer) != 9 || knobs.SpanState(smallPointer) != state {
		return false
	}
	runtime.KeepAlive(large)
	runtime.KeepAlive(small)
	return true
}

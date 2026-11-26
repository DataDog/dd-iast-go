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

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func exerciseSnapshotBytes() bool {
	if knobs.InitSlabWorker == nil || knobs.StoreSnapshot == nil || knobs.MakeRecord == nil ||
		knobs.RecordDetails == nil || knobs.CompareEntry == nil || knobs.SetGate == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if _, _, ok := knobs.InitSlabWorker(1 << 20); !ok {
		return false
	}
	knobs.SetGate(1)
	defer knobs.SetGate(0)
	value := new([65536]byte)
	for i := 0; i < 32; i++ {
		value[i] = byte(i + 1)
	}
	p := unsafe.Pointer(&value[0])
	const slot, generation = uint32(5), uint64(7)
	if !heapranges.StartOwner(slot, generation) || !heapranges.AttachSnapshotArea(slot, generation) {
		return false
	}
	first, ok := knobs.StoreSnapshot(slot, generation, p, 16)
	if !ok || first != 0 {
		return false
	}
	second, ok := knobs.StoreSnapshot(slot, generation, unsafe.Add(p, 16), 16)
	if !ok || second != 16 {
		return false
	}
	if _, ok := knobs.StoreSnapshot(slot, generation+1, p, 1); ok {
		return false
	}
	tail, ok := knobs.StoreSnapshot(slot, generation, p, 65504)
	if !ok || tail != 32 {
		return false
	}
	if _, ok := knobs.StoreSnapshot(slot, generation, p, 1); ok {
		return false
	}
	origin := generation | uint64(slot)<<40
	entry := knobs.MakeRecord(0, 16, 0)
	if entry == 0 || !knobs.RecordDetails(entry, origin, 2, 0, 2, first) || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	var buf [heapranges.MaxRanges]heapranges.Range
	got := heapranges.Ranges(p, 16, buf[:0])
	if len(got) != 1 || got[0].Origin != heapranges.Origin(origin) || got[0].Marks != 2 {
		return false
	}
	value[15] ^= 1
	got = heapranges.Ranges(p, 8, buf[:0])
	if len(got) != 1 || got[0].Origin != heapranges.Origin(origin) || got[0].Marks != 2 {
		return false
	}
	got = heapranges.Ranges(p, 16, buf[:0])
	if len(got) != 1 || got[0].Origin != 0 || got[0].Marks != 0 {
		return false
	}
	if !heapranges.EndOwner(slot, generation) || !heapranges.StartOwner(slot, generation+1) || !heapranges.AttachSnapshotArea(slot, generation+1) {
		return false
	}
	got = heapranges.Ranges(p, 8, buf[:0])
	if len(got) != 1 || got[0].Origin != 0 || got[0].Marks != 0 || !heapranges.EndOwner(slot, generation+1) {
		return false
	}
	runtime.KeepAlive(value)
	return true
}

func exerciseSnapshot() bool {
	if knobs.InitSlabWorker == nil || knobs.Retirement == nil || knobs.SetGate == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	knobs.SetGate(1)
	if !heapranges.StartOwner(0, 1) {
		return false
	}
	if heapranges.AttachSnapshotArea(0, 1) || heapranges.AttachSnapshotArea(64, 1) || heapranges.AttachSnapshotArea(0, 0) ||
		heapranges.AttachSnapshotArea(0, 1<<40) || heapranges.RetireSnapshotArea(0, 1) {
		return false
	}
	knobs.SetGate(0)
	if queues, _, ok := knobs.InitSlabWorker(1 << 20); !ok || queues != 2 {
		return false
	}
	if heapranges.AttachSnapshotArea(0, 1) {
		return false
	}
	knobs.SetGate(1)
	defer knobs.SetGate(0)
	if heapranges.AttachSnapshotArea(64, 1) || heapranges.AttachSnapshotArea(0, 0) || heapranges.AttachSnapshotArea(0, 1<<40) {
		return false
	}
	if !heapranges.StartOwner(3, 1) {
		return false
	}
	var wins atomic.Uint64
	var group sync.WaitGroup
	for i := uint64(1); i <= 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if heapranges.AttachSnapshotArea(3, 1) {
				wins.Add(1)
			}
		}()
	}
	group.Wait()
	if wins.Load() != 1 || heapranges.EndOwner(3, 101) || !heapranges.EndOwner(3, 1) || heapranges.EndOwner(3, 1) {
		return false
	}
	var retired uint32
	for processor := uint32(0); processor < 2; processor++ {
		entry, kind, epoch, producer, lost := knobs.Retirement(processor, 0)
		if lost != 0 || producer > 1 {
			return false
		}
		if producer == 1 {
			if entry == 0 || kind != 2 || epoch != 1 {
				return false
			}
			retired++
		}
	}
	if retired != 1 || !heapranges.StartOwner(3, 101) || !heapranges.AttachSnapshotArea(3, 101) || !heapranges.EndOwner(3, 101) {
		return false
	}
	return true
}

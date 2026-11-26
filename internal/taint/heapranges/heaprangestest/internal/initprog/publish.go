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

func exercisePublish() bool {
	if knobs.InitSlabWorker == nil || knobs.MakeRecord == nil || knobs.CompareEntry == nil || knobs.PublishEntry == nil ||
		knobs.RetireOwn == nil || knobs.Retirement == nil || knobs.ReadEntry == nil || knobs.PoisonEntry == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if queues, _, ok := knobs.InitSlabWorker(1 << 20); !ok || queues != 2 {
		return false
	}
	value := new([65536]byte)
	p := unsafe.Pointer(&value[0])
	old := knobs.MakeRecord(0, 1, 0)
	if old == 0 || !knobs.CompareEntry(p, 0, old) {
		return false
	}
	var candidates [32]uint32
	for i := range candidates {
		candidates[i] = knobs.MakeRecord(uint32(i), 1, 0)
		if candidates[i] == 0 {
			return false
		}
	}
	var wins, winner atomic.Uint32
	var failed atomic.Bool
	var group sync.WaitGroup
	start := make(chan struct{})
	for _, candidate := range candidates {
		group.Add(1)
		go func(candidate uint32) {
			defer group.Done()
			<-start
			if knobs.PublishEntry(p, old, candidate) {
				winner.Store(candidate)
				wins.Add(1)
			} else if !knobs.RetireOwn(candidate) {
				failed.Store(true)
			}
		}(candidate)
	}
	close(start)
	group.Wait()
	if failed.Load() || wins.Load() != 1 || knobs.ReadEntry(p) != winner.Load() {
		return false
	}
	seen := make(map[uint32]bool)
	for processor := uint32(0); processor < 2; processor++ {
		_, _, _, producer, lost := knobs.Retirement(processor, 0)
		if lost != 0 {
			return false
		}
		for pos := uint32(0); pos < producer; pos++ {
			entry, kind, epoch, _, _ := knobs.Retirement(processor, pos)
			if entry == 0 || kind != 1 || epoch != 1 || seen[entry] {
				return false
			}
			seen[entry] = true
		}
	}
	if len(seen) != len(candidates) || !seen[old] || seen[winner.Load()] {
		return false
	}
	for _, candidate := range candidates {
		if candidate != winner.Load() && !seen[candidate] {
			return false
		}
	}
	if !knobs.PublishEntry(p, winner.Load(), winner.Load()) || !knobs.PublishEntry(p, winner.Load(), 0) || knobs.ReadEntry(p) != 0 {
		return false
	}
	var total, found uint32
	for processor := uint32(0); processor < 2; processor++ {
		_, _, _, producer, _ := knobs.Retirement(processor, 0)
		total += producer
		for pos := uint32(0); pos < producer; pos++ {
			entry, _, _, _, _ := knobs.Retirement(processor, pos)
			if entry == winner.Load() {
				found++
			}
		}
	}
	if total != 33 || found != 1 {
		return false
	}
	if !knobs.CompareEntry(p, 0, ^uint32(0)) || knobs.PublishEntry(p, ^uint32(0), old) || knobs.ReadEntry(p) != ^uint32(0) {
		return false
	}
	runtime.KeepAlive(value)
	return true
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"math"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func exerciseOwner() bool {
	if knobs.InitSlabWorker == nil || knobs.SetGate == nil || knobs.Retirement == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if _, _, ok := knobs.InitSlabWorker(2 << 20); !ok {
		return false
	}
	knobs.SetGate(2)
	if heapranges.StartOwner(0, 1) {
		return false
	}
	knobs.SetGate(1)
	defer knobs.SetGate(0)
	if heapranges.StartOwner(heapranges.MaxOwners, 1) || heapranges.StartOwner(0, 0) ||
		heapranges.StartOwner(0, heapranges.MaxGeneration+1) || heapranges.OwnerLive(0, 0) || heapranges.EndOwner(0, 0) {
		return false
	}
	if heapranges.AttachSnapshotArea(3, 5) || !heapranges.StartOwner(3, 5) || !heapranges.OwnerLive(3, 5) ||
		heapranges.OwnerLive(3, 4) || !heapranges.AttachSnapshotArea(3, 5) || heapranges.EndOwner(3, 4) ||
		!heapranges.EndOwner(3, 5) || heapranges.OwnerLive(3, 5) || heapranges.EndOwner(3, 5) ||
		heapranges.AttachSnapshotArea(3, 5) {
		return false
	}
	var count uint32
	for processor := uint32(0); processor < 2; processor++ {
		entry, kind, _, producer, lost := knobs.Retirement(processor, 0)
		if lost != 0 || producer > 1 || (producer == 1 && (entry == 0 || kind != 2)) {
			return false
		}
		count += producer
	}
	if count != 1 || heapranges.StartOwner(3, 5) || heapranges.StartOwner(3, 4) || !heapranges.StartOwner(3, 6) ||
		heapranges.StartOwner(3, 7) || !heapranges.EndOwner(3, 6) {
		return false
	}
	if !heapranges.StartOwner(9, heapranges.MaxGeneration) || !heapranges.EndOwner(9, heapranges.MaxGeneration) ||
		heapranges.StartOwner(9, heapranges.MaxGeneration) {
		return false
	}
	var wins, winner atomic.Uint64
	var group sync.WaitGroup
	start := make(chan struct{})
	for generation := uint64(1); generation <= 8; generation++ {
		group.Add(1)
		go func(generation uint64) {
			defer group.Done()
			<-start
			if heapranges.StartOwner(5, generation) {
				winner.Store(generation)
				wins.Add(1)
			}
		}(generation)
	}
	close(start)
	group.Wait()
	if wins.Load() != 1 || !heapranges.OwnerLive(5, winner.Load()) || !heapranges.EndOwner(5, winner.Load()) {
		return false
	}
	for generation := uint64(1); generation <= 7; generation += 2 {
		if !heapranges.StartOwner(10, generation) {
			return false
		}
		start := make(chan struct{})
		group.Add(2)
		go func() { defer group.Done(); <-start; heapranges.AttachSnapshotArea(10, generation) }()
		go func() { defer group.Done(); <-start; heapranges.EndOwner(10, generation) }()
		close(start)
		group.Wait()
		if heapranges.OwnerLive(10, generation) || !heapranges.StartOwner(10, generation+1) ||
			!heapranges.AttachSnapshotArea(10, generation+1) || !heapranges.EndOwner(10, generation+1) {
			return false
		}
	}
	return true
}

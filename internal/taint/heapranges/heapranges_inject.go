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

var _ = func() bool {
	needWovenRuntime()
	ddheapknobs.Gate = runtimeGate
	ddheapknobs.OffReason = func() string { return offReason }
	ddheapknobs.MapSlab = func() (bool, uint64) {
		allocator := newSlabAllocator(slabSize)
		_, ok := allocator.allocate()
		return ok, allocator.mapped.Load()
	}
	runtimeAccountSlab = accountSlab
	runtimeEnabled = func() bool { return runtimeGate() == 1 }
	return true
}()

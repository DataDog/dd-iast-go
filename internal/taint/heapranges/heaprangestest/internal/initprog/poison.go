// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"math"
	"runtime"
	"runtime/debug"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func exercisePoison() bool {
	if knobs.InitSlabWorker == nil || knobs.MakeRecord == nil || knobs.CompareEntry == nil || knobs.PoisonEntry == nil ||
		knobs.Retirement == nil || knobs.SpanState == nil || knobs.ReadEntry == nil || knobs.SpanPoison == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if queues, _, ok := knobs.InitSlabWorker(1 << 20); !ok || queues != 2 {
		return false
	}
	large := new([65536]byte)
	small := new([256]byte)
	unbound := new([2048]byte)
	for _, pointer := range []unsafe.Pointer{unsafe.Pointer(&large[0]), unsafe.Pointer(&small[0])} {
		record := knobs.MakeRecord(0, 1, 0)
		if record == 0 || !knobs.CompareEntry(pointer, 0, record) {
			return false
		}
		old, processor, ok := knobs.PoisonEntry(pointer)
		if !ok || old != record || processor >= 2 || knobs.ReadEntry(pointer) != ^uint32(0) {
			return false
		}
		_, _, _, producer, lost := knobs.Retirement(processor, 0)
		retired, kind, epoch, _, _ := knobs.Retirement(processor, producer-1)
		if producer == 0 || lost != 0 || retired != record || kind != 1 || epoch != 1 {
			return false
		}
		old, _, ok = knobs.PoisonEntry(pointer)
		if !ok || old != ^uint32(0) || knobs.ReadEntry(pointer) != ^uint32(0) {
			return false
		}
	}
	pointer := unsafe.Pointer(&unbound[0])
	if knobs.SpanState(pointer) != 0 {
		return false
	}
	old, _, ok := knobs.PoisonEntry(pointer)
	if !ok || old != 0 || knobs.SpanState(pointer) != 1 || knobs.ReadEntry(pointer) != ^uint32(0) || !knobs.SpanPoison(pointer, false) {
		return false
	}
	runtime.KeepAlive(large)
	runtime.KeepAlive(small)
	runtime.KeepAlive(unbound)
	return true
}

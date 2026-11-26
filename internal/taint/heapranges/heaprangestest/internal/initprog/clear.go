// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"math"
	"runtime"
	"runtime/debug"
	"slices"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func exerciseClear() bool {
	if knobs.InitSlabWorker == nil || knobs.SetGate == nil || knobs.MakeRecord == nil || knobs.RecordDetails == nil ||
		knobs.RecordRange == nil || knobs.CompareEntry == nil || knobs.ReadEntry == nil || knobs.SpanState == nil ||
		knobs.ClearFailures == nil || knobs.Retirement == nil || knobs.Snapshot == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if _, _, ok := knobs.InitSlabWorker(4 << 20); !ok {
		return false
	}
	knobs.SetGate(1)
	defer knobs.SetGate(0)
	value := new([65536]byte)
	p := unsafe.Pointer(&value[0])
	entry, original := makeRangeChain(5, false, false)
	if entry == 0 || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	heapranges.Clear(unsafe.Add(p, 7), 8)
	want := []heapranges.Range{original[0], original[1], original[3], original[4]}
	want[1].Len = 1
	want[2].Off, want[2].Len = 15, 1
	var buffer [heapranges.MaxRanges]heapranges.Range
	if got := heapranges.Ranges(p, 32, buffer[:0]); !slices.Equal(got, want) {
		return false
	}
	heapranges.Clear(p, uintptr(len(value)))
	if knobs.ReadEntry(p) != 0 || knobs.SpanState(p) != 0 {
		return false
	}
	entry = knobs.MakeRecord(2, 8, 0)
	if entry == 0 || !knobs.RecordDetails(entry, 1, 0, 0, 1, 0) || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	heapranges.Clear(p, 32)
	if knobs.ReadEntry(p) != ^uint32(1) || !knobs.CompareEntry(p, ^uint32(1), 0) {
		return false
	}
	for i := 0; i < 16; i++ {
		value[i] = byte(i + 1)
	}
	if !knobs.Snapshot(0, 1, p, 16) {
		return false
	}
	entry = knobs.MakeRecord(2, 10, 0)
	if entry == 0 || !knobs.RecordDetails(entry, 1, 3, 0, 2, 2) || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	heapranges.Clear(unsafe.Add(p, 5), 3)
	got := heapranges.Ranges(p, 16, buffer[:0])
	if len(got) != 2 || got[0] != (heapranges.Range{Off: 2, Len: 3, Origin: 1, Marks: 3}) ||
		got[1] != (heapranges.Range{Off: 8, Len: 4, Origin: 1, Marks: 3}) {
		return false
	}
	value[10] ^= 1
	got = heapranges.Ranges(p, 16, buffer[:0])
	if len(got) != 2 || got[0].Origin != 1 || got[1].Origin != 0 || got[1].Marks != 0 {
		return false
	}
	heapranges.Clear(p, 16)
	if knobs.ReadEntry(p) != 0 {
		return false
	}
	entry = knobs.MakeRecord(2, 8, 0)
	if entry == 0 || !knobs.RecordDetails(entry, 0, 0, 1, 0, 0) || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	heapranges.Clear(p, 32)
	got = heapranges.Ranges(p, 32, buffer[:0])
	if len(got) != 1 || got[0].Off != 2 || got[0].Len != 8 || got[0].Flags != 1 || !knobs.CompareEntry(p, entry, 0) {
		return false
	}
	entry = knobs.MakeRecord(2, 8, 0)
	if entry == 0 || !knobs.RecordDetails(entry, 1, 0, 0, 0, 0) || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	queueCount := func() uint32 {
		var count uint32
		for processor := uint32(0); processor < 2; processor++ {
			_, _, _, producer, _ := knobs.Retirement(processor, 0)
			count += producer
		}
		return count
	}
	before := queueCount()
	knobs.ClearFailures(4)
	heapranges.Clear(unsafe.Add(p, 4), 1)
	if knobs.ReadEntry(p) != entry || queueCount()-before != 4 {
		return false
	}
	before = queueCount()
	knobs.ClearFailures(2)
	heapranges.Clear(unsafe.Add(p, 4), 1)
	knobs.ClearFailures(0)
	if knobs.ReadEntry(p) == entry || queueCount()-before != 3 {
		return false
	}
	heapranges.Clear(p, 32)
	if knobs.ReadEntry(p) != 0 {
		return false
	}
	entry, _ = makeRangeChain(64, false, false)
	if entry == 0 || !knobs.RecordRange(entry, 0, 2, 4, 1, 3, 0, 0) || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	heapranges.Clear(unsafe.Add(p, 3), 1)
	got = heapranges.Ranges(p, uintptr(len(value)), buffer[:0])
	if len(got) != 64 || got[0].Off != 2 || got[0].Len != 1 || got[1].Off != 4 || got[1].Len != 2 ||
		got[63].Off != 250 || got[63].Len != 65536-250 || got[63].Origin != 0 || got[63].Marks != 0 {
		return false
	}
	heapranges.Clear(p, uintptr(len(value)))
	if knobs.ReadEntry(p) != 0 {
		return false
	}
	entry = knobs.MakeRecord(2, 10, 0)
	if entry == 0 || !knobs.RecordDetails(entry, 1, 0, 0, 0, 0) || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	for knobs.MakeRecord(0, 1, 0) != 0 {
	}
	heapranges.Clear(unsafe.Add(p, 4), 4)
	if knobs.ReadEntry(p) != entry {
		return false
	}
	runtime.KeepAlive(value)
	return true
}

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

//go:noinline
func mapToStack(inputs []heapranges.Input, segs []heapranges.Segment, self heapranges.Owner) bool {
	var dst [8]byte
	return heapranges.Map(unsafe.Pointer(&dst[0]), uintptr(len(dst)), inputs, segs, heapranges.Immutable, self)
}

func exerciseMap(scenario string) bool {
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if knobs.InitSlabWorker == nil {
		return false
	}
	if _, _, ok := knobs.InitSlabWorker(4 << 20); !ok {
		return false
	}
	knobs.SetGate(1)
	defer knobs.SetGate(0)
	if !heapranges.StartOwner(3, 5) || !heapranges.StartOwner(4, 1) {
		return false
	}
	if scenario != "exposed-no-area" && !heapranges.AttachSnapshotArea(3, 5) {
		return false
	}
	src, src2, dst := new([131072]byte), new([131072]byte), new([131072]byte)
	defer runtime.KeepAlive(src)
	defer runtime.KeepAlive(src2)
	defer runtime.KeepAlive(dst)
	sp, sp2, dp := unsafe.Pointer(&src[0]), unsafe.Pointer(&src2[0]), unsafe.Pointer(&dst[0])
	for i := range src {
		src[i] = byte(i)
		src2[i] = byte(i + 1)
	}
	copy(dst[:], src[:])
	a := setOrigin(3, 5, 1)
	a2 := setOrigin(3, 5, 2)
	b := setOrigin(4, 1, 3)
	self := heapranges.OwnerOf(3, 5)
	inputs := []heapranges.Input{{P: sp, N: uintptr(len(src))}}
	var buf [heapranges.MaxRanges]heapranges.Range
	ranges := func(n uintptr) []heapranges.Range { return heapranges.Ranges(dp, n, buf[:0]) }
	mapTo := func(n uintptr, segs []heapranges.Segment, kind heapranges.Kind) bool {
		return heapranges.Map(dp, n, inputs, segs, kind, self)
	}
	one := func(origin heapranges.Origin, flags uint8) bool {
		entry := knobs.MakeRecord(0, 1, 0)
		return entry != 0 && knobs.RecordDetails(entry, uint64(origin), 3, flags, 0, 0) && knobs.CompareEntry(sp, 0, entry)
	}
	two := func(second heapranges.Origin, flags uint8) bool {
		entry := knobs.MakeRecord(0, 1, 0)
		return entry != 0 && knobs.RecordDetails(entry, uint64(a), 3, 0, 0, 0) &&
			knobs.RecordRange(entry, 1, 2, 1, uint64(second), 7, flags, 0) && knobs.CompareEntry(sp, 0, entry)
	}
	segment := []heapranges.Segment{{DstLen: 1, SrcLen: 3}}
	switch scenario {
	case "exact":
		return one(a, 0) && mapTo(1, []heapranges.Segment{{DstLen: 1, SrcLen: 1, Flags: heapranges.SegmentExact}}, heapranges.Immutable) &&
			slices.Equal(ranges(1), []heapranges.Range{{Len: 1, Origin: a, Marks: 3}})
	case "contributors-same", "contributors-different", "contributors-unknown", "contributors-conflict", "bits":
		second, flags, want := a2, uint8(0), a
		switch scenario {
		case "contributors-different":
			second, want = b, 0
		case "contributors-unknown":
			second, want = 0, 0
		case "contributors-conflict":
			second, flags, want = 0, 1, 0
		case "bits":
			second |= 1 << 54
			flags, want = 2, a|(1<<54)
		}
		wantFlags := uint8(0)
		if scenario == "bits" {
			wantFlags = 2
		}
		return two(second, flags) && mapTo(1, segment, heapranges.Immutable) &&
			slices.Equal(ranges(1), []heapranges.Range{{Len: 1, Origin: want, Flags: wantFlags}})
	case "contributors-poison":
		_, _, ok := knobs.PoisonEntry(sp)
		return ok && mapTo(1, segment, heapranges.Immutable) && slices.Equal(ranges(1), []heapranges.Range{{Len: 1, Origin: 1 << 54, Flags: 2}})
	case "clean-contributors":
		return one(a, 0) && mapTo(1, segment, heapranges.Immutable) && slices.Equal(ranges(1), []heapranges.Range{{Len: 1, Origin: a}})
	case "all-clean":
		return mapTo(1, segment, heapranges.Immutable) && len(ranges(1)) == 0
	case "exposed-input":
		return heapranges.Set(sp, 3, a, heapranges.Exposed) && mapTo(1, segment, heapranges.Immutable) &&
			slices.Equal(ranges(1), []heapranges.Range{{Len: 1, Origin: a, Flags: 2}})
	case "constant-unknown":
		segs := []heapranges.Segment{{DstLen: 2}, {DstOff: 2, DstLen: 2, Flags: heapranges.SegmentUnknown | heapranges.SegmentSensitive}}
		return mapTo(4, segs, heapranges.Immutable) && slices.Equal(ranges(4), []heapranges.Range{{Off: 2, Len: 2, Origin: 1 << 54}})
	case "early-end", "early-gap", "early-overlap", "early-bounds", "early-source", "early-input-bounds", "early-exact", "early-flags":
		if !one(a, 0) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 1, SrcLen: 1, Flags: heapranges.SegmentExact}}
		bad := heapranges.Segment{DstOff: 1, DstLen: 1}
		switch scenario {
		case "early-gap":
			bad.DstOff = 2
		case "early-overlap":
			bad.DstOff = 0
		case "early-bounds":
			bad.DstLen = 4
		case "early-source":
			bad.Src = 1
		case "early-input-bounds":
			bad.SrcOff, bad.SrcLen = uint32(len(src)), 1
		case "early-exact":
			bad.Flags, bad.SrcLen = heapranges.SegmentExact, 2
		case "early-flags":
			bad.Flags = heapranges.SegmentSensitive
		}
		if scenario != "early-end" {
			segs = append(segs, bad)
		}
		return mapTo(4, segs, heapranges.Immutable) && slices.Equal(ranges(4), []heapranges.Range{{Len: 1, Origin: a, Marks: 3}, {Off: 1, Len: 3, Origin: 1 << 54}})
	case "early-count":
		segs := make([]heapranges.Segment, heapranges.MaxSegments+1)
		for i := range segs {
			segs[i] = heapranges.Segment{DstOff: uint32(i), DstLen: 1}
		}
		return mapTo(uintptr(len(segs)), segs, heapranges.Immutable) &&
			slices.Equal(ranges(uintptr(len(segs))), []heapranges.Range{{Off: heapranges.MaxSegments, Len: 1, Origin: 1 << 54}})
	case "early-budget":
		if !heapranges.Set(sp, 65536, a, heapranges.Exposed) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 65536, SrcLen: 65536, Flags: heapranges.SegmentExact}, {DstOff: 65536, DstLen: 1}}
		return mapTo(65537, segs, heapranges.Immutable) && slices.Equal(ranges(65537), []heapranges.Range{{Len: 65536, Origin: a, Flags: 2}, {Off: 65536, Len: 1, Origin: 1 << 54}})
	case "early-partial-scan":
		if !heapranges.Set(sp, 65536, a, heapranges.Exposed) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 32768, SrcLen: 32768, Flags: heapranges.SegmentExact}, {DstOff: 32768, DstLen: 65536, SrcLen: 65536, Flags: heapranges.SegmentExact}}
		return mapTo(98304, segs, heapranges.Immutable) && slices.Equal(ranges(98304), []heapranges.Range{{Len: 32768, Origin: a, Flags: 2}, {Off: 32768, Len: 65536, Origin: 1 << 54}})
	case "early-snapshot", "early-partial-snapshot":
		if !heapranges.Set(sp, 65537, a, heapranges.Immutable) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 65536, SrcLen: 65536, Flags: heapranges.SegmentExact}, {DstOff: 65536, DstLen: 1}}
		want := []heapranges.Range{{Len: 65536, Origin: a}, {Off: 65536, Len: 1, Origin: 1 << 54}}
		if scenario == "early-partial-snapshot" {
			segs = []heapranges.Segment{{DstLen: 65537, SrcLen: 65537, Flags: heapranges.SegmentExact}}
			want = []heapranges.Range{{Len: 65537, Origin: 1 << 54}}
		}
		return mapTo(65537, segs, heapranges.Exposed) && slices.Equal(ranges(65537), want)
	case "two-inputs", "same-object-inputs":
		if !one(a, 0) {
			return false
		}
		if scenario == "same-object-inputs" {
			inputs = append(inputs, heapranges.Input{P: sp, N: uintptr(len(src))})
		} else {
			if !heapranges.Set(sp2, 1, b, heapranges.Immutable) {
				return false
			}
			inputs = append(inputs, heapranges.Input{P: sp2, N: uintptr(len(src2))})
		}
		segs := []heapranges.Segment{{DstLen: 1, SrcLen: 1, Flags: heapranges.SegmentExact}, {DstOff: 1, DstLen: 1, SrcLen: 1, Src: 1, Flags: heapranges.SegmentExact}, {DstOff: 2, DstLen: 1, SrcLen: 1, Src: 1, Flags: heapranges.SegmentExact}}
		want := []heapranges.Range{{Len: 1, Origin: a, Marks: 3}, {Off: 1, Len: 2, Origin: b}}
		if scenario == "same-object-inputs" {
			want = []heapranges.Range{{Len: 3, Origin: a, Marks: 3}}
		}
		return mapTo(3, segs, heapranges.Immutable) && slices.Equal(ranges(3), want)
	case "too-many-inputs":
		inputs = make([]heapranges.Input, heapranges.MaxMapInputs+1)
		return mapTo(4, nil, heapranges.Immutable) && slices.Equal(ranges(4), []heapranges.Range{{Len: 4, Origin: 1 << 54}})
	case "exposed-self", "exposed-other", "exposed-no-owner", "exposed-ended-owner", "exposed-no-area", "exposed-changed":
		origin := a
		if scenario == "exposed-other" {
			origin = b | 1<<54
		}
		if scenario == "exposed-changed" {
			if !heapranges.Set(sp, 1, a, heapranges.Exposed) {
				return false
			}
			src[0]++
		} else if !one(origin, 0) {
			return false
		}
		if scenario == "exposed-no-owner" {
			self = heapranges.NoOwner
		}
		if scenario == "exposed-ended-owner" && !heapranges.EndOwner(3, 5) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 1, SrcLen: 1, Flags: heapranges.SegmentExact}}
		if !mapTo(1, segs, heapranges.Exposed) {
			return false
		}
		want := heapranges.Range{Len: 1}
		if scenario == "exposed-self" {
			want.Origin, want.Marks = a, 3
		} else if scenario == "exposed-other" {
			want.Origin = 1 << 54
		} else if scenario == "exposed-changed" {
			want.Flags = 2
		}
		return slices.Equal(ranges(1), []heapranges.Range{want})
	case "exposed-reuse":
		if !heapranges.Set(sp, 1, a, heapranges.Exposed) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 1, SrcLen: 1, Flags: heapranges.SegmentExact}}
		if !mapTo(1, segs, heapranges.Exposed) || !slices.Equal(ranges(1), []heapranges.Range{{Len: 1, Origin: a, Flags: 2}}) {
			return false
		}
		offset, ok := knobs.StoreSnapshot(3, 5, sp, 1)
		return ok && offset == 1
	case "exposed-full":
		if !one(a, 0) {
			return false
		}
		if _, ok := knobs.StoreSnapshot(3, 5, sp, 65536); !ok {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 1, SrcLen: 1, Flags: heapranges.SegmentExact}}
		return mapTo(1, segs, heapranges.Exposed) && slices.Equal(ranges(1), []heapranges.Range{{Len: 1}})
	case "observed-writes":
		knobs.SnapshotsOff(1)
		defer knobs.SnapshotsOff(0)
		if !one(a, 0) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 1, SrcLen: 1, Flags: heapranges.SegmentExact}}
		return mapTo(1, segs, heapranges.Exposed) && slices.Equal(ranges(1), []heapranges.Range{{Len: 1}})
	case "private-to-exposed":
		entry := knobs.MakeRecord(0, 12, 0)
		if entry == 0 || !knobs.RecordDetails(entry, uint64(a), 3, 0, 1, 0) || !knobs.CompareEntry(dp, 0, entry) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 4}}
		return heapranges.Map(unsafe.Add(dp, 4), 4, inputs, segs, heapranges.Exposed, self) &&
			slices.Equal(ranges(12), []heapranges.Range{{Len: 4, Origin: a, Marks: 3, Flags: 2}, {Off: 8, Len: 4, Origin: a, Marks: 3, Flags: 2}})
	case "real-write", "conflict-write":
		if !heapranges.Set(dp, 12, a, heapranges.Immutable) {
			return false
		}
		if scenario == "conflict-write" && heapranges.Set(dp, 12, b, heapranges.Immutable) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 4}}
		if !heapranges.Map(unsafe.Add(dp, 4), 4, inputs, segs, heapranges.Immutable, self) {
			return false
		}
		want := []heapranges.Range{{Len: 4, Origin: a}, {Off: 8, Len: 4, Origin: a}}
		if scenario == "conflict-write" {
			want = []heapranges.Range{{Len: 4, Flags: 1}, {Off: 8, Len: 4, Flags: 1}}
		}
		return slices.Equal(ranges(12), want)
	case "poison-destination":
		_, _, ok := knobs.PoisonEntry(dp)
		return ok && !mapTo(4, nil, heapranges.Immutable) && knobs.ReadEntry(dp) == ^uint32(0)
	case "span-poison-destination":
		return knobs.SpanPoison(dp, true) && !mapTo(4, nil, heapranges.Immutable) && knobs.ReadEntry(dp) == ^uint32(0)
	case "failure", "clean-failure":
		if !heapranges.Set(dp, 12, a, heapranges.Immutable) || (scenario == "failure" && !one(b, 0)) {
			return false
		}
		for knobs.MakeRecord(0, 1, 0) != 0 {
		}
		segs := []heapranges.Segment{{DstLen: 4}}
		if scenario == "failure" {
			segs[0].SrcLen = 1
		}
		return !heapranges.Map(unsafe.Add(dp, 4), 4, inputs, segs, heapranges.Immutable, self) && knobs.ReadEntry(dp) == ^uint32(0)
	case "cas-failure":
		if !heapranges.Set(dp, 12, a, heapranges.Immutable) {
			return false
		}
		queueCount := func() uint32 {
			var total uint32
			for i := uint32(0); i < 2; i++ {
				_, _, _, producer, _ := knobs.Retirement(i, 0)
				total += producer
			}
			return total
		}
		before := queueCount()
		knobs.MapFailures(4)
		segs := []heapranges.Segment{{DstLen: 4}}
		return !heapranges.Map(unsafe.Add(dp, 4), 4, inputs, segs, heapranges.Immutable, self) &&
			knobs.ReadEntry(dp) == ^uint32(0) && queueCount()-before == 5
	case "empty":
		return heapranges.Map(nil, 0, nil, nil, heapranges.Immutable, heapranges.NoOwner) && knobs.ReadEntry(dp) == 0
	case "stack-destination":
		return !mapToStack(inputs, nil, self)
	case "out-of-bounds":
		return !mapTo(uintptr(len(dst))+1, nil, heapranges.Immutable) && knobs.ReadEntry(dp) == 0
	case "range-limit":
		entry, _ := makeRangeChain(64, false, false)
		if entry == 0 || !knobs.CompareEntry(sp, 0, entry) || !heapranges.Set(unsafe.Add(dp, 300), 4, a, heapranges.Immutable) {
			return false
		}
		segs := []heapranges.Segment{{DstLen: 256, SrcLen: 256, Flags: heapranges.SegmentExact}}
		if !mapTo(256, segs, heapranges.Immutable) {
			return false
		}
		got := ranges(uintptr(len(dst)))
		return len(got) == 64 && got[0].Off == 2 && got[63].Origin&heapranges.Origin(heapranges.MaxGeneration) == 0 && got[63].Off == 254
	}
	return false
}

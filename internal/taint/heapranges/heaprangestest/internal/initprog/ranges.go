// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

var rangeSink []heapranges.Range

func makeRangeChain(count int, exposed bool, contiguous bool) (uint32, []heapranges.Range) {
	var next uint32
	want := make([]heapranges.Range, count)
	for group := (count - 1) / 4; group >= 0; group-- {
		entry := knobs.MakeRecord(0, 0, next)
		if entry == 0 {
			return 0, nil
		}
		kind := uint8(0)
		if exposed {
			kind = 2
		}
		if !knobs.RecordDetails(entry, 1, 0, 0, kind, 0) {
			return 0, nil
		}
		for j := 0; j < 4 && group*4+j < count; j++ {
			i := group*4 + j
			off, length := uint32(2+i*4), uint32(2)
			origin := uint64(1) | uint64(i)<<46
			snapshot := uint32(0)
			if exposed {
				off, length = uint32(i*1026), 1025
			}
			if contiguous {
				off, length, origin, snapshot = uint32(i*4), 4, 1, uint32(i*8)
			}
			if !knobs.RecordRange(entry, uint32(j), off, length, origin, 3, 0, snapshot) {
				return 0, nil
			}
			want[i] = heapranges.Range{Off: off, Len: length, Origin: heapranges.Origin(origin), Marks: 3}
		}
		next = entry
	}
	return next, want
}

func exerciseRanges(scenario string) bool {
	if knobs.InitSlabWorker == nil || knobs.MakeRecord == nil || knobs.RecordRange == nil || knobs.RecordDetails == nil ||
		knobs.Snapshot == nil || knobs.CompareEntry == nil || knobs.SetGate == nil || knobs.SetRangeLimit == nil ||
		knobs.RangeCollapses == nil || knobs.SpanPoison == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if _, _, ok := knobs.InitSlabWorker(4 << 20); !ok {
		return false
	}
	value := new([131072]byte)
	p := unsafe.Pointer(&value[0])
	knobs.SetGate(1)
	defer func() { knobs.SetGate(0); runtime.KeepAlive(value) }()

	if scenario == "clean" {
		var stack [64]byte
		if len(heapranges.Ranges(p, 32, nil)) != 0 || len(heapranges.Ranges(unsafe.Pointer(&stack[0]), 64, nil)) != 0 ||
			!knobs.CompareEntry(p, 0, ^uint32(1)) || len(heapranges.Ranges(p, 32, nil)) != 0 ||
			!knobs.CompareEntry(p, ^uint32(1), 0) {
			return false
		}
		knobs.SetGate(2)
		return len(heapranges.Ranges(p, 32, nil)) == 0 && testing.AllocsPerRun(100, func() { rangeSink = heapranges.Ranges(p, 32, nil) }) == 0
	}
	if scenario == "poison" {
		var buf [heapranges.MaxRanges]heapranges.Range
		check := func() bool {
			for _, b := range [][]heapranges.Range{nil, buf[:0]} {
				got := heapranges.Ranges(p, 32, b)
				if len(got) != 1 || got[0] != (heapranges.Range{Len: 32}) {
					return false
				}
			}
			return true
		}
		return knobs.CompareEntry(p, 0, ^uint32(0)) && check() && knobs.CompareEntry(p, ^uint32(0), 0) &&
			knobs.SpanPoison(p, true) && check() && knobs.SpanPoison(p, false)
	}

	count, exposed, contiguous := 5, false, false
	switch scenario {
	case "nil buffer", "zero capacity":
		count = 3
	case "exact fit":
		count = 4
	case "maximum":
		count, exposed = 64, true
	case "missing snapshot", "snapshot mismatch":
		count, exposed = 1, true
	case "merge":
		count, exposed, contiguous = 2, true, true
	case "model":
		count = 64
	}
	if exposed && scenario != "missing snapshot" && !knobs.Snapshot(0, 1, p, 65536) {
		return false
	}
	entry, want := makeRangeChain(count, exposed, contiguous)
	if entry == 0 || !knobs.CompareEntry(p, 0, entry) {
		return false
	}
	var buf [heapranges.MaxRanges]heapranges.Range
	switch scenario {
	case "nil buffer", "zero capacity":
		var small []heapranges.Range
		if scenario == "zero capacity" {
			small = make([]heapranges.Range, 0)
		}
		got := heapranges.Ranges(p, 128, small)
		return slices.Equal(got, want) && cap(got) == heapranges.MaxRanges &&
			testing.AllocsPerRun(50, func() { rangeSink = heapranges.Ranges(p, 128, small) }) == 1
	case "exact fit":
		got := heapranges.Ranges(p, 128, buf[:0:4])
		return slices.Equal(got, want) && &got[0] == &buf[0] &&
			testing.AllocsPerRun(50, func() { rangeSink = heapranges.Ranges(p, 128, buf[:0:4]) }) == 0
	case "one more than capacity":
		var small [4]heapranges.Range
		for i := range small {
			small[i].Off = 99
		}
		got := heapranges.Ranges(p, 128, small[:])
		return slices.Equal(got, want) && cap(got) == heapranges.MaxRanges && &got[0] != &small[0] &&
			small[0].Off == 99 && small[1].Off == 99 && small[2].Off == 99 && small[3].Off == 99
	case "length is ignored":
		buf[0].Off = 99
		got := heapranges.Ranges(p, 128, buf[:3])
		return slices.Equal(got, want) && &got[0] == &buf[0]
	case "missing snapshot":
		got := heapranges.Ranges(p, 1025, buf[:0])
		return len(got) == 1 && got[0] == (heapranges.Range{Len: 1025})
	case "snapshot mismatch":
		value[0] = 1
		got := heapranges.Ranges(p, 1025, buf[:0])
		if len(got) != 1 || got[0] != (heapranges.Range{Len: 1025}) {
			return false
		}
		got = heapranges.Ranges(unsafe.Add(p, 1), 1024, buf[:0])
		return len(got) == 1 && got[0] == (heapranges.Range{Len: 1024, Origin: 1, Marks: 3})
	case "relative offsets":
		got := heapranges.Ranges(unsafe.Add(p, 3), 8, buf[:0])
		return len(got) == 3 && got[0].Off == 0 && got[0].Len == 1 && got[1].Off == 3 && got[1].Len == 2 && got[2].Off == 7 && got[2].Len == 1
	case "merge":
		got := heapranges.Ranges(p, 8, buf[:0])
		return len(got) == 1 && got[0] == (heapranges.Range{Len: 8, Origin: 1, Marks: 3})
	case "collapse":
		before := knobs.RangeCollapses()
		knobs.SetRangeLimit(3)
		got := heapranges.Ranges(p, 128, buf[:0])
		knobs.SetRangeLimit(0)
		if len(got) != 3 || got[2] != (heapranges.Range{Off: want[2].Off, Len: 128 - want[2].Off}) || knobs.RangeCollapses() != before+1 {
			return false
		}
		for _, expected := range want {
			covered := false
			for _, actual := range got {
				covered = covered || actual.Off <= expected.Off && actual.Off+actual.Len >= expected.Off+expected.Len
			}
			if !covered {
				return false
			}
		}
		return true
	case "maximum":
		got := heapranges.Ranges(p, 65536+128, buf[:0])
		return len(got) == heapranges.MaxRanges && got[64].Origin == 0 && got[64].Marks == 0 &&
			testing.AllocsPerRun(50, func() { rangeSink = heapranges.Ranges(p, 65536+128, buf[:0]) }) == 0
	case "model":
		random := rand.New(rand.NewSource(71829))
		for trial := 0; trial < 200; trial++ {
			start := uint32(random.Intn(257))
			end := start + uint32(random.Intn(int(257-start)))
			var expected []heapranges.Range
			for _, r := range want {
				if start == end {
					break
				}
				lo, hi := r.Off, r.Off+r.Len
				if lo >= end || hi <= start {
					continue
				}
				if lo < start {
					lo = start
				}
				if hi > end {
					hi = end
				}
				r.Off, r.Len = lo-start, hi-lo
				expected = append(expected, r)
			}
			capacities := []int{0, 1, len(expected), len(expected) + 1, heapranges.MaxRanges}
			if len(expected) > 0 {
				capacities = append(capacities, len(expected)-1)
			}
			for _, capacity := range capacities {
				got := heapranges.Ranges(unsafe.Add(p, start), uintptr(end-start), buf[:0:capacity])
				if !slices.Equal(got, expected) || heapranges.Any(unsafe.Add(p, start), uintptr(end-start)) != (len(expected) != 0) {
					fmt.Fprintf(os.Stderr, "trial=%d start=%d end=%d capacity=%d got=%+v want=%+v any=%v\n", trial, start, end, capacity, got, expected, heapranges.Any(unsafe.Add(p, start), uintptr(end-start)))
					return false
				}
			}
		}
		return true
	}
	return false
}

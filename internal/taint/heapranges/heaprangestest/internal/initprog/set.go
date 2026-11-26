// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"math"
	"math/rand"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func setOrigin(slot, generation, source uint64) heapranges.Origin {
	return heapranges.Origin(generation | slot<<40 | source<<46)
}

func exerciseSet(scenario string) bool {
	if knobs.InitSlabWorker == nil || knobs.SetGate == nil || knobs.CompareEntry == nil || knobs.ReadEntry == nil ||
		knobs.MakeRecord == nil || knobs.RecordDetails == nil || knobs.SetFailures == nil || knobs.SnapshotsOff == nil ||
		knobs.StoreSnapshot == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if _, _, ok := knobs.InitSlabWorker(2 << 20); !ok {
		return false
	}
	knobs.SetGate(1)
	defer knobs.SetGate(0)
	value := new([65536]byte)
	p := unsafe.Pointer(&value[0])
	defer runtime.KeepAlive(value)
	a, b := setOrigin(3, 5, 1), setOrigin(4, 1, 1)
	if scenario == "no-snapshot" || scenario == "exposed-cc" {
		knobs.SnapshotsOff(1)
		defer knobs.SnapshotsOff(0)
	}
	if scenario != "unregistered" && !heapranges.StartOwner(3, 5) {
		return false
	}
	if !heapranges.StartOwner(4, 1) {
		return false
	}
	var buffer [heapranges.MaxRanges]heapranges.Range
	ranges := func(n uintptr) []heapranges.Range { return heapranges.Ranges(p, n, buffer[:0]) }
	switch scenario {
	case "unregistered":
		return heapranges.Set(p, 8, a, heapranges.Immutable) && heapranges.Set(p, 8, b, heapranges.Immutable) &&
			slices.Equal(ranges(8), []heapranges.Range{{Len: 8, Origin: b}})
	case "live", "reverse", "absorbing", "no-snapshot":
		if scenario == "reverse" {
			if !heapranges.Set(unsafe.Add(p, 4), 8, b, heapranges.Immutable) || heapranges.Set(p, 8, a, heapranges.Immutable) {
				return false
			}
		} else if !heapranges.Set(p, 8, a, heapranges.Immutable) || heapranges.Set(unsafe.Add(p, 4), 8, b, heapranges.Immutable) {
			return false
		}
		want := []heapranges.Range{{Len: 4, Origin: a}, {Off: 4, Len: 4, Flags: 1}, {Off: 8, Len: 4, Origin: b}}
		if !slices.Equal(ranges(12), want) {
			return false
		}
		if scenario == "no-snapshot" {
			if !heapranges.EndOwner(3, 5) || !heapranges.Set(p, 4, b, heapranges.Immutable) {
				return false
			}
			return slices.Equal(ranges(12), []heapranges.Range{{Len: 4, Origin: b}, {Off: 4, Len: 4, Flags: 1}, {Off: 8, Len: 4, Origin: b}})
		}
		if scenario == "absorbing" {
			c := setOrigin(6, 1, 1)
			if !heapranges.StartOwner(6, 1) || heapranges.Set(unsafe.Add(p, 4), 4, c, heapranges.Immutable) ||
				heapranges.Set(unsafe.Add(p, 4), 4, a, heapranges.Immutable) || !heapranges.EndOwner(3, 5) ||
				!heapranges.EndOwner(4, 1) || heapranges.Set(unsafe.Add(p, 4), 4, c, heapranges.Immutable) {
				return false
			}
			return slices.Equal(ranges(12), want)
		}
		return true
	case "ended":
		return heapranges.Set(p, 8, a, heapranges.Immutable) && heapranges.EndOwner(3, 5) &&
			heapranges.Set(p, 8, b, heapranges.Immutable) && slices.Equal(ranges(8), []heapranges.Range{{Len: 8, Origin: b}})
	case "reused":
		next := setOrigin(3, 6, 2)
		return heapranges.Set(p, 8, a, heapranges.Immutable) && heapranges.EndOwner(3, 5) && heapranges.StartOwner(3, 6) &&
			heapranges.Set(p, 8, next, heapranges.Immutable) && slices.Equal(ranges(8), []heapranges.Range{{Len: 8, Origin: next}})
	case "same":
		next := setOrigin(3, 5, 2)
		return heapranges.Set(p, 8, a, heapranges.Immutable) && heapranges.Set(p, 8, next, heapranges.Immutable) &&
			slices.Equal(ranges(8), []heapranges.Range{{Len: 8, Origin: next}})
	case "unknown":
		entry := knobs.MakeRecord(0, 8, 0)
		return entry != 0 && knobs.RecordDetails(entry, 0, 0, 0, 0, 0) && knobs.CompareEntry(p, 0, entry) &&
			!heapranges.Set(p, 8, a, heapranges.Immutable) && slices.Equal(ranges(8), []heapranges.Range{{Len: 8}})
	case "exposed-cc":
		if !heapranges.AttachSnapshotArea(3, 5) {
			return false
		}
		if offset, ok := knobs.StoreSnapshot(3, 5, p, 8); !ok || offset != 0 {
			return false
		}
		if !heapranges.Set(p, 8, a, heapranges.Exposed) || !slices.Equal(ranges(8), []heapranges.Range{{Len: 8}}) {
			return false
		}
		knobs.SnapshotsOff(0)
		if !slices.Equal(ranges(8), []heapranges.Range{{Len: 8}}) {
			return false
		}
		heapranges.Clear(unsafe.Add(p, 2), 2)
		return slices.Equal(ranges(8), []heapranges.Range{{Len: 2}, {Off: 4, Len: 4}})
	case "exposed":
		for i := 0; i < 8; i++ {
			value[i] = byte(i + 1)
		}
		if !heapranges.AttachSnapshotArea(3, 5) || !heapranges.Set(p, 8, a, heapranges.Exposed) ||
			!slices.Equal(ranges(8), []heapranges.Range{{Len: 8, Origin: a}}) {
			return false
		}
		value[7] ^= 1
		if !slices.Equal(ranges(4), []heapranges.Range{{Len: 4, Origin: a}}) || !slices.Equal(ranges(8), []heapranges.Range{{Len: 8}}) {
			return false
		}
		return heapranges.EndOwner(3, 5) && slices.Equal(ranges(4), []heapranges.Range{{Len: 4}})
	case "drop-on-failure":
		if !heapranges.Set(p, 8, a, heapranges.Immutable) {
			return false
		}
		knobs.SetFailures(4)
		defer knobs.SetFailures(0)
		next := setOrigin(3, 5, 2)
		return !heapranges.Set(p, 8, next, heapranges.Immutable) &&
			slices.Equal(ranges(8), []heapranges.Range{{Len: 8, Origin: a}})
	case "limit":
		entry, _ := makeRangeChain(64, false, false)
		if entry == 0 || !knobs.CompareEntry(p, 0, entry) || !heapranges.Set(unsafe.Add(p, 3), 1, b, heapranges.Immutable) {
			return false
		}
		got := ranges(uintptr(len(value)))
		return len(got) == 64 && got[0].Off == 2 && got[0].Len == 1 && got[0].Origin == 1 &&
			got[1].Off == 3 && got[1].Len == 1 && got[1].Origin == b && got[63].Off == 250 &&
			got[63].Len == 65536-250 && got[63].Origin == 0
	case "model":
		var origins [32]heapranges.Origin
		var conflicts [32]bool
		random := rand.New(rand.NewSource(12345))
		for i := 0; i < 200; i++ {
			start := random.Intn(len(origins))
			end := start + 1 + random.Intn(len(origins)-start)
			next := a
			if random.Intn(2) != 0 {
				next = b
			}
			want := true
			for j := start; j < end; j++ {
				if conflicts[j] {
					want = false
				} else if origins[j] != 0 && origins[j] != next {
					origins[j], conflicts[j], want = 0, true, false
				} else {
					origins[j] = next
				}
			}
			if heapranges.Set(unsafe.Add(p, start), uintptr(end-start), next, heapranges.Immutable) != want {
				return false
			}
			for j := range origins {
				got := heapranges.Ranges(unsafe.Add(p, j), 1, buffer[:0])
				if origins[j] == 0 && !conflicts[j] {
					if len(got) != 0 {
						return false
					}
				} else if len(got) != 1 || got[0].Len != 1 || got[0].Origin != origins[j] || (got[0].Flags == 1) != conflicts[j] {
					return false
				}
			}
		}
		return true
	case "pool-empty", "cas-failed":
		if !heapranges.Set(p, 8, a, heapranges.Immutable) {
			return false
		}
		if scenario == "pool-empty" {
			for knobs.MakeRecord(0, 1, 0) != 0 {
			}
		} else {
			knobs.SetFailures(4)
			defer knobs.SetFailures(0)
		}
		return !heapranges.Set(p, 8, b, heapranges.Immutable) && knobs.ReadEntry(p) == ^uint32(0) &&
			slices.Equal(ranges(8), []heapranges.Range{{Len: 8}})
	case "end-race":
		if !heapranges.EndOwner(3, 5) {
			return false
		}
		for generation := uint64(6); generation < 1006; generation++ {
			origin := setOrigin(3, generation, 1)
			if !heapranges.StartOwner(3, generation) || !heapranges.Set(p, 8, origin, heapranges.Immutable) {
				return false
			}
			var group sync.WaitGroup
			start := make(chan struct{})
			group.Add(2)
			go func() { defer group.Done(); <-start; heapranges.EndOwner(3, generation) }()
			go func() { defer group.Done(); <-start; heapranges.Set(p, 8, b, heapranges.Immutable) }()
			close(start)
			group.Wait()
			got := ranges(8)
			if len(got) != 1 || got[0].Len != 8 || (got[0].Origin != b && (got[0].Origin != 0 || got[0].Flags != 1)) {
				return false
			}
			entry := knobs.ReadEntry(p)
			if entry == 0 || !knobs.CompareEntry(p, entry, 0) {
				return false
			}
		}
		return true
	}
	return false
}

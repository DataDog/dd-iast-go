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
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

//go:noinline
func copyToStack(src unsafe.Pointer, self heapranges.Owner) bool {
	var dst [8]byte
	return heapranges.Copy(unsafe.Pointer(&dst[0]), src, 8, heapranges.Immutable, self)
}

func exerciseCopy(scenario string) bool {
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	if knobs.InitSlabWorker == nil || knobs.CopyFailures == nil {
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
	if scenario != "no-area" && !heapranges.AttachSnapshotArea(3, 5) {
		return false
	}
	src, dst := new([65536]byte), new([65536]byte)
	sp, dp := unsafe.Pointer(&src[0]), unsafe.Pointer(&dst[0])
	defer runtime.KeepAlive(src)
	defer runtime.KeepAlive(dst)
	a := setOrigin(3, 5, 1)
	b := setOrigin(4, 1, 2) | 1<<54
	self := heapranges.OwnerOf(3, 5)
	for i := range src[:32] {
		src[i] = byte(i + 1)
	}
	copy(dst[:], src[:])
	var buf [heapranges.MaxRanges]heapranges.Range
	ranges := func(p unsafe.Pointer, n uintptr) []heapranges.Range { return heapranges.Ranges(p, n, buf[:0]) }
	source := func(kind uint8, two bool) bool {
		entry := knobs.MakeRecord(0, 4, 0)
		if entry == 0 || !knobs.RecordDetails(entry, uint64(a), 3, 0, kind, 0) {
			return false
		}
		if two && !knobs.RecordRange(entry, 1, 4, 4, uint64(b), 7, 0, 0) {
			return false
		}
		return knobs.CompareEntry(sp, 0, entry)
	}
	switch scenario {
	case "immutable-origins":
		if !source(0, true) || !heapranges.Copy(dp, sp, 8, heapranges.Immutable, heapranges.NoOwner) {
			return false
		}
		return slices.Equal(ranges(dp, 8), []heapranges.Range{{Len: 4, Origin: a, Marks: 3}, {Off: 4, Len: 4, Origin: b, Marks: 7}})
	case "exposed-self", "no-owner", "ended-owner", "no-area":
		if !source(0, true) {
			return false
		}
		if scenario == "no-owner" {
			self = heapranges.NoOwner
		}
		if scenario == "ended-owner" && !heapranges.EndOwner(3, 5) {
			return false
		}
		if !heapranges.Copy(dp, sp, 8, heapranges.Exposed, self) {
			return false
		}
		first := heapranges.Range{Len: 4}
		if scenario == "exposed-self" {
			first.Origin, first.Marks = a, 3
		}
		return slices.Equal(ranges(dp, 8), []heapranges.Range{first, {Off: 4, Len: 4, Origin: 1 << 54}})
	case "snapshot-reference", "changed-bytes", "sensitive-mismatch", "ended-source", "exposed-to-immutable":
		if scenario == "sensitive-mismatch" {
			a |= 1 << 54
		}
		if !heapranges.Set(sp, 8, a, heapranges.Exposed) {
			return false
		}
		if scenario == "changed-bytes" || scenario == "sensitive-mismatch" {
			src[2] ^= 1
			copy(dst[:8], src[:8])
		}
		if scenario == "ended-source" && !heapranges.EndOwner(3, 5) {
			return false
		}
		kind := heapranges.Exposed
		if scenario == "exposed-to-immutable" {
			kind = heapranges.Immutable
		}
		if !heapranges.Copy(dp, sp, 8, kind, self) {
			return false
		}
		want := heapranges.Range{Len: 8, Origin: a, Flags: 2}
		if scenario == "changed-bytes" || scenario == "ended-source" {
			want.Origin = 0
		} else if scenario == "sensitive-mismatch" {
			want.Origin = 1 << 54
		}
		if !slices.Equal(ranges(dp, 8), []heapranges.Range{want}) {
			return false
		}
		if scenario == "snapshot-reference" {
			offset, ok := knobs.StoreSnapshot(3, 5, sp, 1)
			return ok && offset == 8
		}
		return true
	case "clean-source", "clean-inline":
		if !heapranges.Set(dp, 12, a, heapranges.Immutable) {
			return false
		}
		if scenario == "clean-inline" {
			return heapranges.Copy(dp, sp, 12, heapranges.Immutable, self) && knobs.ReadEntry(dp) == 0 && knobs.SpanState(dp) == 0
		}
		if !heapranges.Copy(unsafe.Add(dp, 4), sp, 4, heapranges.Immutable, self) {
			return false
		}
		return slices.Equal(ranges(dp, 12), []heapranges.Range{{Len: 4, Origin: a}, {Off: 8, Len: 4, Origin: a}})
	case "conflict":
		if !heapranges.Set(dp, 12, a, heapranges.Immutable) || heapranges.Set(dp, 12, b, heapranges.Immutable) {
			return false
		}
		if !heapranges.Copy(unsafe.Add(dp, 4), sp, 4, heapranges.Immutable, self) {
			return false
		}
		return slices.Equal(ranges(dp, 12), []heapranges.Range{{Len: 4, Flags: 1}, {Off: 8, Len: 4, Flags: 1}})
	case "poison-destination":
		_, _, ok := knobs.PoisonEntry(dp)
		return ok && !heapranges.Copy(dp, sp, 4, heapranges.Immutable, self) && knobs.ReadEntry(dp) == ^uint32(0)
	case "span-poison-destination":
		if !knobs.SpanPoison(dp, true) {
			return false
		}
		return !heapranges.Copy(dp, sp, 4, heapranges.Immutable, self) && knobs.ReadEntry(dp) == ^uint32(0)
	case "poison-source":
		_, _, ok := knobs.PoisonEntry(sp)
		if !ok || !heapranges.Copy(dp, sp, 4, heapranges.Immutable, self) {
			return false
		}
		got := ranges(dp, 4)
		return len(got) == 1 && got[0].Len == 4 && got[0].Origin&heapranges.Origin(heapranges.MaxGeneration) == 0
	case "private", "expose-private", "unmarked-private":
		if scenario != "unmarked-private" && !knobs.CompareEntry(dp, 0, ^uint32(1)) {
			return false
		}
		if !source(0, false) {
			return false
		}
		kind := heapranges.Private
		if scenario == "expose-private" {
			kind = heapranges.Exposed
		}
		if !heapranges.Copy(dp, sp, 4, kind, self) {
			return false
		}
		if scenario == "private" {
			heapranges.Clear(dp, 4)
			return knobs.ReadEntry(dp) == ^uint32(1)
		}
		if scenario == "unmarked-private" {
			heapranges.Clear(dp, 4)
			return knobs.ReadEntry(dp) == 0
		}
		if !slices.Equal(ranges(dp, 4), []heapranges.Range{{Len: 4, Origin: a, Marks: 3}}) {
			return false
		}
		heapranges.Clear(dp, 4)
		return knobs.ReadEntry(dp) == 0 && heapranges.Copy(dp, sp, 4, heapranges.Private, heapranges.NoOwner) &&
			slices.Equal(ranges(dp, 4), []heapranges.Range{{Len: 4}})
	case "overlap-left", "overlap-right", "overlap-exposed":
		kind := heapranges.Immutable
		if scenario == "overlap-exposed" {
			kind = heapranges.Exposed
		}
		if !heapranges.Set(dp, 8, a, kind) {
			return false
		}
		if scenario == "overlap-left" {
			copy(dst[:8], dst[4:12])
			if !heapranges.Copy(dp, unsafe.Add(dp, 4), 8, kind, self) {
				return false
			}
			return slices.Equal(ranges(dp, 12), []heapranges.Range{{Len: 4, Origin: a}})
		}
		copy(dst[4:12], dst[:8])
		if !heapranges.Copy(unsafe.Add(dp, 4), dp, 8, kind, self) {
			return false
		}
		if scenario == "overlap-exposed" {
			return slices.Equal(ranges(dp, 12), []heapranges.Range{{Len: 4, Origin: a}, {Off: 4, Len: 8, Origin: a, Flags: 2}})
		}
		return slices.Equal(ranges(dp, 12), []heapranges.Range{{Len: 12, Origin: a}})
	case "model":
		var model [32]heapranges.Origin
		if !heapranges.Set(dp, 6, a, heapranges.Immutable) || !heapranges.Set(unsafe.Add(dp, 12), 6, b, heapranges.Immutable) {
			return false
		}
		for i := 0; i < 6; i++ {
			model[i], model[i+12] = a, b
		}
		random := rand.New(rand.NewSource(24680))
		for step := 0; step < 300; step++ {
			n := 1 + random.Intn(8)
			from := random.Intn(len(model) - n + 1)
			to := random.Intn(len(model) - n + 1)
			copy(dst[to:to+n], dst[from:from+n])
			copy(model[to:to+n], model[from:from+n])
			if !heapranges.Copy(unsafe.Add(dp, to), unsafe.Add(dp, from), uintptr(n), heapranges.Immutable, self) {
				return false
			}
			for i, want := range model {
				got := ranges(unsafe.Add(dp, i), 1)
				if want == 0 && len(got) != 0 || want != 0 && (len(got) != 1 || got[0].Origin != want || got[0].Len != 1) {
					return false
				}
			}
		}
		return true
	case "recorded-immutable":
		if !heapranges.Set(dp, 4, a, heapranges.Immutable) || !source(0, true) {
			return false
		}
		copy(dst[:4], src[4:8])
		return heapranges.Copy(dp, unsafe.Add(sp, 4), 4, heapranges.Exposed, heapranges.NoOwner) &&
			slices.Equal(ranges(dp, 4), []heapranges.Range{{Len: 4, Origin: b, Marks: 7}})
	case "snapshot-full":
		if !source(0, false) {
			return false
		}
		if _, ok := knobs.StoreSnapshot(3, 5, sp, 65536); !ok {
			return false
		}
		return heapranges.Copy(dp, sp, 4, heapranges.Exposed, self) &&
			slices.Equal(ranges(dp, 4), []heapranges.Range{{Len: 4}})
	case "private-kept-ranges":
		entry := knobs.MakeRecord(0, 12, 0)
		if entry == 0 || !knobs.RecordDetails(entry, uint64(a), 3, 0, 1, 0) || !knobs.CompareEntry(dp, 0, entry) {
			return false
		}
		if !heapranges.Copy(unsafe.Add(dp, 4), sp, 4, heapranges.Exposed, self) {
			return false
		}
		return slices.Equal(ranges(dp, 12), []heapranges.Range{{Len: 4, Origin: a, Marks: 3, Flags: 2}, {Off: 8, Len: 4, Origin: a, Marks: 3, Flags: 2}})
	case "recorded-exposed":
		if !heapranges.Set(dp, 12, a, heapranges.Exposed) || !source(0, false) {
			return false
		}
		copy(dst[4:8], src[:4])
		if !heapranges.Copy(unsafe.Add(dp, 4), sp, 4, heapranges.Immutable, self) {
			return false
		}
		got := ranges(dp, 12)
		return len(got) == 3 && got[0].Origin == a && got[1].Origin == a && got[2].Origin == a && got[1].Marks == 3
	case "budget":
		largeSrc, largeDst := new([1 << 20]byte), new([1 << 20]byte)
		defer runtime.KeepAlive(largeSrc)
		defer runtime.KeepAlive(largeDst)
		lp, lq := unsafe.Pointer(&largeSrc[0]), unsafe.Pointer(&largeDst[0])
		if !heapranges.Set(lp, 1<<20, a, heapranges.Immutable) || !heapranges.Copy(lq, lp, 1<<20, heapranges.Exposed, self) {
			return false
		}
		return slices.Equal(ranges(lq, 1<<20), []heapranges.Range{{Len: 65536, Origin: a}, {Off: 65536, Len: (1 << 20) - 65536}})
	case "range-limit":
		entry, _ := makeRangeChain(64, false, false)
		if entry == 0 || !knobs.CompareEntry(sp, 0, entry) || !heapranges.Set(unsafe.Add(dp, 300), 4, a, heapranges.Immutable) ||
			!heapranges.Copy(dp, sp, 256, heapranges.Immutable, self) {
			return false
		}
		got := ranges(dp, 65536)
		return len(got) == 64 && got[0].Off == 2 && got[63].Origin&heapranges.Origin(heapranges.MaxGeneration) == 0 &&
			got[63].Off == 254 && got[63].Len == 65536-254
	case "stale-table":
		first, second := new([256]byte), new([1024]byte)
		defer runtime.KeepAlive(first)
		defer runtime.KeepAlive(second)
		firstPtr, secondPtr := unsafe.Pointer(&first[0]), unsafe.Pointer(&second[0])
		if !heapranges.Set(firstPtr, 4, a, heapranges.Immutable) || !source(0, false) ||
			!knobs.CloneSpanTable(secondPtr, firstPtr) {
			return false
		}
		return !heapranges.Copy(secondPtr, sp, 4, heapranges.Immutable, self) && knobs.Gate() == 3
	case "span-poison-failure":
		small := new([3072]byte)
		defer runtime.KeepAlive(small)
		p := unsafe.Pointer(&small[0])
		if knobs.SpanState(p) != 0 || !source(0, false) {
			return false
		}
		for knobs.MakeRecord(0, 1, 0) != 0 {
		}
		return !heapranges.Copy(p, sp, 4, heapranges.Immutable, self) && knobs.SpanState(p) == 1
	case "cas-failed":
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
		knobs.CopyFailures(4)
		return !heapranges.Copy(unsafe.Add(dp, 4), sp, 4, heapranges.Immutable, self) &&
			knobs.ReadEntry(dp) == ^uint32(0) && queueCount()-before == 5
	case "clean-nochange-pool":
		if !heapranges.Set(dp, 4, a, heapranges.Immutable) {
			return false
		}
		entry := knobs.ReadEntry(dp)
		for knobs.MakeRecord(0, 1, 0) != 0 {
		}
		return heapranges.Copy(unsafe.Add(dp, 8), sp, 4, heapranges.Immutable, self) && knobs.ReadEntry(dp) == entry
	case "pool-empty":
		if !heapranges.Set(dp, 12, a, heapranges.Immutable) {
			return false
		}
		for knobs.MakeRecord(0, 1, 0) != 0 {
		}
		return !heapranges.Copy(unsafe.Add(dp, 4), sp, 4, heapranges.Immutable, self) && knobs.ReadEntry(dp) == ^uint32(0)
	case "stack-destination":
		return !copyToStack(sp, self)
	case "out-of-bounds":
		return !heapranges.Copy(dp, sp, uintptr(len(dst))+1, heapranges.Immutable, self) && knobs.ReadEntry(dp) == 0
	case "observed-writes":
		knobs.SnapshotsOff(1)
		defer knobs.SnapshotsOff(0)
		if !heapranges.Set(sp, 8, a, heapranges.Exposed) || !heapranges.Copy(dp, sp, 8, heapranges.Immutable, self) {
			return false
		}
		return slices.Equal(ranges(dp, 8), []heapranges.Range{{Len: 8, Flags: 2}})
	case "stack-source":
		var value [8]byte
		if !heapranges.Set(dp, 8, a, heapranges.Immutable) || !heapranges.Copy(dp, unsafe.Pointer(&value[0]), 8, heapranges.Immutable, self) {
			return false
		}
		return len(ranges(dp, 8)) == 0
	}
	return false
}

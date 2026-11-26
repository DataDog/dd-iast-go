// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package runtime

import (
	ddheapatomic "internal/runtime/atomic"
	ddheapunsafe "unsafe"
)

var (
	ddiastHeapGate   ddheapatomic.Uint32
	ddiastProbeStart ddheapatomic.Uintptr
	ddiastProbeEnd   ddheapatomic.Uintptr
	_                *sysMemStat                              = &memstats.other_sys
	_                *ddheapatomic.Uint64                     = &gcController.mappedReady
	_                func(*sysMemStat, int64)                 = (*sysMemStat).add
	_                func(*ddheapatomic.Uint64, int64) uint64 = (*ddheapatomic.Uint64).Add
	_                func(uintptr) *mspan                     = spanOfHeap
	_                func(*mspan, uintptr) uintptr            = (*mspan).objIndex
	_                func(*mspan) uintptr                     = (*mspan).base
	_                func() *g                                = getg
)

var (
	_ func(ddheapunsafe.Pointer) ddheapunsafe.Pointer = noescape
	_ func() *m                                       = acquirem
	_ func(*m)                                        = releasem
	_ func(puintptr) *p                               = puintptr.ptr
	_ func(any)                                       = KeepAlive
)

//go:linkname ddiastHeapRangesNeedRuntime runtime.ddiastHeapRangesNeedTheWovenRuntime
func ddiastHeapRangesNeedRuntime() {}

//go:linkname ddiastHeapRangesGate github.com/DataDog/dd-iast-go/internal/taint/heapranges.runtimeGate
func ddiastHeapRangesGate() uint32 {
	return ddiastHeapGate.Load()
}

//go:linkname ddiastHeapRangesAccountSlab github.com/DataDog/dd-iast-go/internal/taint/heapranges.accountSlab
//go:nosplit
func ddiastHeapRangesAccountSlab() {
	memstats.other_sys.add(1 << 20)
	gcController.mappedReady.Add(1 << 20)
}

var (
	ddiastEpoch         ddheapatomic.Uint64
	ddiastAnnouncements [1024]ddheapatomic.Uint64
)

//go:linkname ddiastInitEpoch github.com/DataDog/dd-iast-go/internal/taint/heapranges.initEpoch
func ddiastInitEpoch() { ddiastEpoch.CompareAndSwap(0, 1) }

//go:nosplit
func ddiastEnter() (*m, uint32) {
	mp := acquirem()
	processor := mp.p.ptr()
	if processor == nil || uint32(processor.id) >= uint32(len(ddiastAnnouncements)) {
		releasem(mp)
		return nil, 0
	}
	epoch := ddiastEpoch.Load()
	if epoch == 0 {
		releasem(mp)
		return nil, 0
	}
	index := uint32(processor.id)
	ddiastAnnouncements[index].Store(epoch)
	return mp, index
}

//go:nosplit
func ddiastLeave(mp *m, index uint32) {
	ddiastAnnouncements[index].Store(0)
	releasem(mp)
}

//go:linkname ddiastTestEpoch github.com/DataDog/dd-iast-go/internal/taint/heapranges.testEpoch
func ddiastTestEpoch() bool {
	mp, index := ddiastEnter()
	if mp == nil {
		return false
	}
	epoch := ddiastEpoch.Load()
	ok := epoch != 0 && ddiastAnnouncements[index].Load() == epoch
	ddiastLeave(mp, index)
	return ok && ddiastAnnouncements[index].Load() == 0
}

type ddiastOutputRange struct {
	offset uint32
	length uint32
	origin uint64
	marks  uint8
	flags  uint8
	_      [6]byte
}

var (
	_ [24 - ddheapunsafe.Sizeof(ddiastOutputRange{})]byte
	_ [ddheapunsafe.Sizeof(ddiastOutputRange{}) - 24]byte
	_ [0 - ddheapunsafe.Offsetof(ddiastOutputRange{}.offset)]byte
	_ [ddheapunsafe.Offsetof(ddiastOutputRange{}.offset) - 0]byte
	_ [4 - ddheapunsafe.Offsetof(ddiastOutputRange{}.length)]byte
	_ [ddheapunsafe.Offsetof(ddiastOutputRange{}.length) - 4]byte
	_ [8 - ddheapunsafe.Offsetof(ddiastOutputRange{}.origin)]byte
	_ [ddheapunsafe.Offsetof(ddiastOutputRange{}.origin) - 8]byte
	_ [16 - ddheapunsafe.Offsetof(ddiastOutputRange{}.marks)]byte
	_ [ddheapunsafe.Offsetof(ddiastOutputRange{}.marks) - 16]byte
	_ [17 - ddheapunsafe.Offsetof(ddiastOutputRange{}.flags)]byte
	_ [ddheapunsafe.Offsetof(ddiastOutputRange{}.flags) - 17]byte
)

type ddiastRange struct {
	offset   uint32
	length   uint32
	origin   uint64
	snapshot uint32
	marks    uint8
	flags    uint8
	_        [2]byte
}

type ddiastRecord struct {
	next   uint32
	count  uint8
	kind   uint8
	_      [26]byte
	ranges [4]ddiastRange
}

type ddiastTable struct {
	base    ddheapatomic.Uint64
	_       [56]byte
	entries [1024]ddheapatomic.Uint32
}

const (
	ddiastSpanPoison   = uint64(1)
	ddiastSpanInline   = uint64(2)
	ddiastSpanTagMask  = uint64(63)
	ddiastEntryPoison  = ^uint32(0)
	ddiastEntryPrivate = ^uint32(1)
)

//go:nosplit
func ddiastReadEntry(span *mspan, index uint32) uint32 {
	state := span.ddiastTaint.Load()
	if state == 0 {
		return 0
	}
	return ddiastReadEntryState(state, span.base(), uint32(span.nelems), index)
}

//go:nosplit
func ddiastReadEntryState(state uint64, base uintptr, count, index uint32) uint32 {
	if index >= count || index >= 1024 {
		return 0
	}
	if state == 0 {
		return 0
	}
	if state == ddiastSpanPoison {
		return ddiastEntryPoison
	}
	if state&ddiastSpanTagMask == ddiastSpanInline {
		if count != 1 || index != 0 {
			return 0
		}
		return uint32(state >> 32)
	}
	if state&ddiastSpanTagMask != 0 {
		return 0
	}
	table := (*ddiastTable)(ddheapunsafe.Pointer(uintptr(state)))
	if table.base.Load() != uint64(base) {
		return 0
	}
	return table.entries[index].Load()
}

//go:nosplit
func ddiastBindTable(table *ddiastTable, base uintptr) bool {
	if base == 0 {
		return false
	}
	value := table.base.Load()
	if value == uint64(base) {
		return true
	}
	if value != 0 {
		return false
	}
	return table.base.CompareAndSwap(0, uint64(base)) || table.base.Load() == uint64(base)
}

var (
	ddiastTablesCreated  ddheapatomic.Uint64
	ddiastTableUnitsLost ddheapatomic.Uint64
)

//go:nosplit
func ddiastTableForSpan(span *mspan, create bool) *ddiastTable {
	state := span.ddiastTaint.Load()
	if state == 0 && create {
		entry := ddiastAllocateUnits(65)
		if entry == 0 {
			return nil
		}
		address := ddiastSlabAddress(entry)
		if address == 0 {
			return nil
		}
		table := (*ddiastTable)(ddheapunsafe.Pointer(address))
		table.base.Store(uint64(span.base()))
		if span.ddiastTaint.CompareAndSwap(0, uint64(address)) {
			ddiastTablesCreated.Add(1)
			return table
		}
		ddiastTableUnitsLost.Add(65)
		state = span.ddiastTaint.Load()
	}
	if state == 0 || state&ddiastSpanTagMask != 0 {
		return nil
	}
	table := (*ddiastTable)(ddheapunsafe.Pointer(uintptr(state)))
	if !ddiastBindTable(table, span.base()) {
		return nil
	}
	return table
}

//go:nosplit
func ddiastCompareEntry(span *mspan, index, old, next uint32) bool {
	if index >= uint32(span.nelems) || index >= 1024 {
		return false
	}
	state := span.ddiastTaint.Load()
	if span.nelems == 1 && (state == 0 || state&ddiastSpanTagMask == ddiastSpanInline) {
		if index != 0 {
			return false
		}
		expected := uint64(0)
		if old != 0 {
			expected = uint64(old)<<32 | ddiastSpanInline
		}
		replacement := uint64(0)
		if next != 0 {
			replacement = uint64(next)<<32 | ddiastSpanInline
		}
		return span.ddiastTaint.CompareAndSwap(expected, replacement)
	}
	if state == 0 && old == 0 && next == 0 {
		return span.ddiastTaint.CompareAndSwap(0, 0)
	}
	table := ddiastTableForSpan(span, state == 0 && old == 0 && next != 0)
	return table != nil && table.entries[index].CompareAndSwap(old, next)
}

//go:linkname ddiastTestCompareEntry github.com/DataDog/dd-iast-go/internal/taint/heapranges.testCompareEntry
func ddiastTestCompareEntry(p ddheapunsafe.Pointer, old, next uint32) bool {
	span, _, index := ddiastClassify(p, 1)
	return span != nil && ddiastCompareEntry(span, index, old, next)
}

//go:linkname ddiastTestReadEntry github.com/DataDog/dd-iast-go/internal/taint/heapranges.testReadEntry
func ddiastTestReadEntry(p ddheapunsafe.Pointer) uint32 {
	span, _, index := ddiastClassify(p, 1)
	if span == nil {
		return 0
	}
	return ddiastReadEntry(span, index)
}

//go:linkname ddiastTestSpanState github.com/DataDog/dd-iast-go/internal/taint/heapranges.testSpanState
func ddiastTestSpanState(p ddheapunsafe.Pointer) uint64 {
	span, _, _ := ddiastClassify(p, 1)
	if span == nil {
		return 0
	}
	return span.ddiastTaint.Load()
}

//go:linkname ddiastTestBindTable github.com/DataDog/dd-iast-go/internal/taint/heapranges.testBindTable
func ddiastTestBindTable(entry uint32, base uintptr) bool {
	address := ddiastSlabAddress(entry)
	if address == 0 {
		return false
	}
	return ddiastBindTable((*ddiastTable)(ddheapunsafe.Pointer(address)), base)
}

//go:linkname ddiastTestSpanRead github.com/DataDog/dd-iast-go/internal/taint/heapranges.testSpanRead
func ddiastTestSpanRead(entry uint32) bool {
	address := ddiastSlabAddress(entry)
	if address == 0 {
		return false
	}
	table := (*ddiastTable)(ddheapunsafe.Pointer(address))
	base := table.base.Load()
	if base == 0 {
		return false
	}
	if ddiastReadEntryState(0, uintptr(base), 1, 0) != 0 ||
		ddiastReadEntryState(ddiastSpanPoison, uintptr(base), 1, 0) != ddiastEntryPoison {
		return false
	}
	inline := uint64(41)<<32 | ddiastSpanInline
	if ddiastReadEntryState(inline, uintptr(base), 1, 0) != 41 ||
		ddiastReadEntryState(inline, uintptr(base), 1, 1) != 0 ||
		ddiastReadEntryState(inline, uintptr(base), 2, 0) != 0 {
		return false
	}
	table.entries[0].Store(42)
	table.entries[1].Store(43)
	state := uint64(address)
	if ddiastReadEntryState(state, uintptr(base), 2, 0) != 42 ||
		ddiastReadEntryState(state, uintptr(base), 2, 1) != 43 ||
		ddiastReadEntryState(state, uintptr(base), 1, 0) != 42 ||
		ddiastReadEntryState(state, uintptr(base), 1, 1) != 0 {
		return false
	}
	return ddiastReadEntryState(state, uintptr(base)^0x300000, 1, 0) == 0
}

//go:linkname ddiastTestTableBase github.com/DataDog/dd-iast-go/internal/taint/heapranges.testTableBase
func ddiastTestTableBase(entry uint32) uint64 {
	address := ddiastSlabAddress(entry)
	if address == 0 {
		return 0
	}
	return (*ddiastTable)(ddheapunsafe.Pointer(address)).base.Load()
}

//go:linkname ddiastTestTableEntry github.com/DataDog/dd-iast-go/internal/taint/heapranges.testTableEntry
func ddiastTestTableEntry(entry, slot uint32, value uint32, write bool) uint32 {
	address := ddiastSlabAddress(entry)
	if address == 0 || slot >= 1024 {
		return 0
	}
	table := (*ddiastTable)(ddheapunsafe.Pointer(address))
	if write {
		table.entries[slot].Store(value)
	}
	return table.entries[slot].Load()
}

var (
	_ [24 - ddheapunsafe.Sizeof(ddiastRange{})]byte
	_ [ddheapunsafe.Sizeof(ddiastRange{}) - 24]byte
	_ [128 - ddheapunsafe.Sizeof(ddiastRecord{})]byte
	_ [ddheapunsafe.Sizeof(ddiastRecord{}) - 128]byte
	_ [4160 - ddheapunsafe.Sizeof(ddiastTable{})]byte
	_ [ddheapunsafe.Sizeof(ddiastTable{}) - 4160]byte
)

//go:nosplit
func ddiastClassify(p ddheapunsafe.Pointer, n uintptr) (*mspan, uintptr, uint32) {
	if p == nil || n == 0 {
		return nil, 0, 0
	}
	address := uintptr(p)
	span := spanOfHeap(address)
	if span == nil || span.isUserArenaChunk || span.elemsize == 0 || uint64(span.elemsize) > uint64(^uint32(0)) {
		return nil, 0, 0
	}
	index := span.objIndex(address)
	if index >= uintptr(span.nelems) || index >= 1024 {
		return nil, 0, 0
	}
	start := span.base() + index*span.elemsize
	offset := address - start
	if address < start || offset >= span.elemsize || n > span.elemsize-offset || n > span.limit-address {
		return nil, 0, 0
	}
	return span, offset, uint32(index)
}

//go:linkname ddiastMayHaveTaint github.com/DataDog/dd-iast-go/internal/taint/heapranges.wovenMayHaveTaint
//go:nosplit
func ddiastMayHaveTaint(p ddheapunsafe.Pointer, n uintptr) bool {
	if gate := ddiastHeapGate.Load(); gate != 1 {
		if gate != 0 {
			return false
		}
		start, end := ddiastProbeStart.Load(), ddiastProbeEnd.Load()
		address := uintptr(p)
		if start == 0 || address < start || address >= end || n > end-address {
			return false
		}
	}
	span, _, index := ddiastClassify(p, n)
	if span == nil {
		return false
	}
	entry := ddiastReadEntry(span, index)
	KeepAlive(p)
	return entry != 0 && entry != ddiastEntryPrivate
}

//go:nosplit
func ddiastChainAny(entry uint32, offset, length uintptr) bool {
	start := uint64(offset)
	end := start + uint64(length)
	for records := 0; records < 16 && entry != 0; records++ {
		if entry == ddiastEntryPoison || entry == ddiastEntryPrivate || (entry-1)&(ddiastSlabUnits-1) > ddiastSlabUnits-2 {
			return true
		}
		address := ddiastSlabAddress(entry)
		if address == 0 {
			return true
		}
		record := (*ddiastRecord)(ddheapunsafe.Pointer(address))
		if record.count == 0 || record.count > 4 {
			return true
		}
		for i := uint8(0); i < record.count; i++ {
			r := &record.ranges[i]
			if r.length != 0 && uint64(r.offset) < end && start < uint64(r.offset)+uint64(r.length) {
				return true
			}
		}
		entry = record.next
	}
	return entry != 0
}

//go:linkname ddiastAny github.com/DataDog/dd-iast-go/internal/taint/heapranges.wovenAny
//go:nosplit
func ddiastAny(p ddheapunsafe.Pointer, n uintptr) bool {
	if gate := ddiastHeapGate.Load(); gate != 1 {
		if gate != 0 {
			return false
		}
		start, end := ddiastProbeStart.Load(), ddiastProbeEnd.Load()
		address := uintptr(p)
		if start == 0 || address < start || address >= end || n > end-address {
			return false
		}
	}
	span, offset, index := ddiastClassify(p, n)
	if span == nil {
		return false
	}
	mp, processor := ddiastEnter()
	entry := ddiastReadEntry(span, index)
	if mp == nil {
		KeepAlive(p)
		return entry != 0 && entry != ddiastEntryPrivate
	}
	result := entry == ddiastEntryPoison || (entry != 0 && entry != ddiastEntryPrivate && ddiastChainAny(entry, offset, n))
	ddiastLeave(mp, processor)
	KeepAlive(p)
	return result
}

var (
	ddiastRangesCollapsed ddheapatomic.Uint64
	ddiastRangeLimit      ddheapatomic.Uint32
	ddiastSnapshotAreas   [64]ddheapatomic.Uint64
)

const (
	ddiastOriginGenerationMask = uint64(1<<40 - 1)
	ddiastOriginSlotShift      = 40
	ddiastSnapshotEntryMask    = uint64(1<<24 - 1)
	ddiastSnapshotSize         = uint64(64 << 10)
)

//go:nosplit
func ddiastUnknownRange(output *[65]ddiastOutputRange, length uintptr) uint32 {
	output[0] = ddiastOutputRange{length: uint32(length)}
	return 1
}

//go:nosplit
func ddiastAppendRange(output *[65]ddiastOutputRange, count uint32, r ddiastOutputRange, length uintptr) (uint32, bool) {
	if count != 0 {
		previous := &output[count-1]
		end := uint64(previous.offset) + uint64(previous.length)
		if uint64(r.offset) < end {
			ddiastRangesCollapsed.Add(1)
			return ddiastUnknownRange(output, length), false
		}
		if uint64(r.offset) == end && previous.origin == r.origin && previous.marks == r.marks && previous.flags == r.flags {
			previous.length += r.length
			return count, true
		}
	}
	limit := ddiastRangeLimit.Load()
	if limit == 0 || limit > uint32(len(output)) {
		limit = uint32(len(output))
	}
	if count >= limit {
		previous := &output[count-1]
		*previous = ddiastOutputRange{offset: previous.offset, length: uint32(length) - previous.offset}
		ddiastRangesCollapsed.Add(1)
		return count, false
	}
	output[count] = r
	return count + 1, true
}

//go:nosplit
func ddiastSnapshotAddress(r *ddiastRange, begin, length uint64) uintptr {
	generation := r.origin & ddiastOriginGenerationMask
	if generation == 0 {
		return 0
	}
	slot := (r.origin >> ddiastOriginSlotShift) & 63
	descriptor := ddiastSnapshotAreas[slot].Load()
	if descriptor>>24 != generation {
		return 0
	}
	entry := uint32(descriptor & ddiastSnapshotEntryMask)
	if entry == 0 || (entry-1)&(ddiastSlabUnits-1) > ddiastSlabUnits-1024 {
		return 0
	}
	snapshot := uint64(r.snapshot) + begin
	if snapshot > ddiastSnapshotSize || length > ddiastSnapshotSize-snapshot {
		return 0
	}
	address := ddiastSlabAddress(entry)
	if address == 0 {
		return 0
	}
	return address + uintptr(snapshot)
}

//go:nosplit
func ddiastSnapshotEqual(address, snapshot uintptr, length uint64) bool {
	for i := uint64(0); i < length; i++ {
		if *(*byte)(ddheapunsafe.Pointer(address + uintptr(i))) != *(*byte)(ddheapunsafe.Pointer(snapshot + uintptr(i))) {
			return false
		}
	}
	return true
}

//go:nosplit
func ddiastChainRanges(entry uint32, offset, length uintptr, source ddheapunsafe.Pointer, output *[65]ddiastOutputRange) uint32 {
	start, end := uint64(offset), uint64(offset)+uint64(length)
	var count uint32
	budget := ddiastSnapshotSize
	for records := 0; records < 16 && entry != 0; records++ {
		if entry == ddiastEntryPoison || entry == ddiastEntryPrivate || (entry-1)&(ddiastSlabUnits-1) > ddiastSlabUnits-2 {
			return ddiastUnknownRange(output, length)
		}
		address := ddiastSlabAddress(entry)
		if address == 0 {
			return ddiastUnknownRange(output, length)
		}
		record := (*ddiastRecord)(ddheapunsafe.Pointer(address))
		if record.count == 0 || record.count > 4 {
			return ddiastUnknownRange(output, length)
		}
		for i := uint8(0); i < record.count; i++ {
			r := &record.ranges[i]
			lo, hi := uint64(r.offset), uint64(r.offset)+uint64(r.length)
			if r.length == 0 || lo >= end || hi <= start {
				continue
			}
			if lo < start {
				lo = start
			}
			if hi > end {
				hi = end
			}
			item := ddiastOutputRange{offset: uint32(lo - start), length: uint32(hi - lo), origin: r.origin, marks: r.marks, flags: r.flags}
			var verified uint64
			if record.kind > 2 || r.origin&ddiastOriginGenerationMask == 0 {
				item.origin, item.marks = 0, 0
			}
			if record.kind == 2 {
				verified = uint64(item.length)
				if verified > budget {
					verified = budget
				}
				snapshot := ddiastSnapshotAddress(r, lo-uint64(r.offset), verified)
				if snapshot == 0 || !ddiastSnapshotEqual(uintptr(source)+uintptr(item.offset), snapshot, verified) {
					item.origin, item.marks = 0, 0
				}
				budget -= verified
				if verified == 0 {
					item.origin, item.marks = 0, 0
				} else if verified < uint64(item.length) {
					item.length = uint32(verified)
				}
			}
			var ok bool
			count, ok = ddiastAppendRange(output, count, item, length)
			if !ok {
				return count
			}
			if record.kind == 2 && verified != 0 && verified < hi-lo {
				tail := ddiastOutputRange{offset: item.offset + item.length, length: uint32(hi - lo - verified), flags: r.flags}
				count, ok = ddiastAppendRange(output, count, tail, length)
				if !ok {
					return count
				}
			}
		}
		entry = record.next
	}
	if entry != 0 {
		return ddiastUnknownRange(output, length)
	}
	return count
}

//go:linkname ddiastRanges github.com/DataDog/dd-iast-go/internal/taint/heapranges.wovenRanges
//go:nosplit
func ddiastRanges(p ddheapunsafe.Pointer, n uintptr, out ddheapunsafe.Pointer) uint32 {
	if gate := ddiastHeapGate.Load(); gate != 1 {
		if gate != 0 {
			return 0
		}
		start, end := ddiastProbeStart.Load(), ddiastProbeEnd.Load()
		address := uintptr(p)
		if start == 0 || address < start || address >= end || n > end-address {
			return 0
		}
	}
	span, offset, index := ddiastClassify(p, n)
	if span == nil {
		return 0
	}
	output := (*[65]ddiastOutputRange)(out)
	mp, processor := ddiastEnter()
	entry := ddiastReadEntry(span, index)
	var count uint32
	if entry != 0 && entry != ddiastEntryPrivate {
		if mp == nil || entry == ddiastEntryPoison {
			count = ddiastUnknownRange(output, n)
		} else {
			count = ddiastChainRanges(entry, offset, n, p, output)
		}
	}
	if mp != nil {
		ddiastLeave(mp, processor)
	}
	KeepAlive(p)
	return count
}

//go:linkname ddiastTestRecord github.com/DataDog/dd-iast-go/internal/taint/heapranges.testRecord
func ddiastTestRecord(offset, length, next uint32) uint32 {
	entry := ddiastAllocateUnits(2)
	if entry == 0 {
		return 0
	}
	address := ddiastSlabAddress(entry)
	if address == 0 {
		return 0
	}
	record := (*ddiastRecord)(ddheapunsafe.Pointer(address))
	record.next = next
	record.count = 1
	record.ranges[0].offset = offset
	record.ranges[0].length = length
	return entry
}

//go:linkname ddiastTestRecordDetails github.com/DataDog/dd-iast-go/internal/taint/heapranges.testRecordDetails
func ddiastTestRecordDetails(entry uint32, origin uint64, marks, flags, kind uint8, snapshot uint32) bool {
	address := ddiastSlabAddress(entry)
	if address == 0 {
		return false
	}
	record := (*ddiastRecord)(ddheapunsafe.Pointer(address))
	record.kind = kind
	record.ranges[0].origin = origin
	record.ranges[0].marks = marks
	record.ranges[0].flags = flags
	record.ranges[0].snapshot = snapshot
	return true
}

//go:linkname ddiastTestSpanPoison github.com/DataDog/dd-iast-go/internal/taint/heapranges.testSpanPoison
func ddiastTestSpanPoison(p ddheapunsafe.Pointer, set bool) bool {
	span, _, _ := ddiastClassify(p, 1)
	if span == nil {
		return false
	}
	if set {
		return span.ddiastTaint.CompareAndSwap(0, ddiastSpanPoison)
	}
	return span.ddiastTaint.CompareAndSwap(ddiastSpanPoison, 0)
}

//go:linkname ddiastTestRecordRange github.com/DataDog/dd-iast-go/internal/taint/heapranges.testRecordRange
func ddiastTestRecordRange(entry, index, offset, length uint32, origin uint64, marks, flags uint8, snapshot uint32) bool {
	address := ddiastSlabAddress(entry)
	if address == 0 || index >= 4 {
		return false
	}
	record := (*ddiastRecord)(ddheapunsafe.Pointer(address))
	record.ranges[index] = ddiastRange{offset: offset, length: length, origin: origin, marks: marks, flags: flags, snapshot: snapshot}
	if record.count <= uint8(index) {
		record.count = uint8(index) + 1
	}
	return true
}

//go:linkname ddiastTestRangeLimit github.com/DataDog/dd-iast-go/internal/taint/heapranges.testRangeLimit
func ddiastTestRangeLimit(limit uint32) { ddiastRangeLimit.Store(limit) }

//go:linkname ddiastTestRangeCollapses github.com/DataDog/dd-iast-go/internal/taint/heapranges.testRangeCollapses
func ddiastTestRangeCollapses() uint64 { return ddiastRangesCollapsed.Load() }

//go:linkname ddiastTestSnapshot github.com/DataDog/dd-iast-go/internal/taint/heapranges.testSnapshot
func ddiastTestSnapshot(slot uint32, generation uint64, data ddheapunsafe.Pointer, length uintptr) bool {
	if slot >= uint32(len(ddiastSnapshotAreas)) || generation == 0 || generation > ddiastOriginGenerationMask || uint64(length) > ddiastSnapshotSize {
		return false
	}
	entry := ddiastAllocateUnits(1024)
	address := ddiastSlabAddress(entry)
	if entry == 0 || address == 0 {
		return false
	}
	for i := uintptr(0); i < length; i++ {
		*(*byte)(ddheapunsafe.Pointer(address + i)) = *(*byte)(ddheapunsafe.Pointer(uintptr(data) + i))
	}
	KeepAlive(data)
	return ddiastSnapshotAreas[slot].CompareAndSwap(0, generation<<24|uint64(entry))
}

//go:linkname ddiastTestSetGate github.com/DataDog/dd-iast-go/internal/taint/heapranges.testSetGate
func ddiastTestSetGate(value uint32) { ddiastHeapGate.Store(value) }

//go:linkname ddiastTestSetProbe github.com/DataDog/dd-iast-go/internal/taint/heapranges.testSetProbe
func ddiastTestSetProbe(p ddheapunsafe.Pointer, n uintptr) {
	start := uintptr(p)
	if start == 0 || n == 0 || n > ^uintptr(0)-start {
		ddiastProbeStart.Store(0)
		ddiastProbeEnd.Store(0)
		return
	}
	ddiastProbeEnd.Store(start + n)
	ddiastProbeStart.Store(start)
}

//go:linkname ddiastInspectClassify github.com/DataDog/dd-iast-go/internal/taint/heapranges.inspectClassify
func ddiastInspectClassify(p ddheapunsafe.Pointer, n uintptr) (uintptr, uintptr, uint32, bool) {
	span, offset, index := ddiastClassify(p, n)
	if span == nil {
		return 0, 0, 0, false
	}
	return offset, span.elemsize, index, true
}

//go:linkname ddiastStackClassify github.com/DataDog/dd-iast-go/internal/taint/heapranges.stackClassify
func ddiastStackClassify() bool {
	var value [64]byte
	address := uintptr(ddheapunsafe.Pointer(&value[0]))
	g := getg()
	span, _, _ := ddiastClassify(ddheapunsafe.Pointer(&value[0]), 1)
	return address >= g.stack.lo && address < g.stack.hi && span == nil
}

const (
	ddiastSlabCount = 1024
	ddiastSlabUnits = 1 << 14
	ddiastSlabBusy  = ^uint32(0)
)

type ddiastSlab struct {
	base uintptr
	bump ddheapatomic.Uint32
	next uint32
}

var (
	ddiastSlabs        [ddiastSlabCount]ddiastSlab
	ddiastSlabsUsed    ddheapatomic.Uint32
	ddiastReadyHead    ddheapatomic.Uint32
	ddiastReadyCount   ddheapatomic.Uint32
	ddiastCurrentSlab  ddheapatomic.Uint32
	ddiastSlabTailLost ddheapatomic.Uint64
	ddiastRefill       ddheapatomic.Uint32
	ddiastQueues       [ddiastSlabCount]ddheapatomic.Uint32
)

//go:linkname ddiastPublishSlab github.com/DataDog/dd-iast-go/internal/taint/heapranges.publishSlab
func ddiastPublishSlab(base uintptr) bool {
	if base == 0 || base&63 != 0 {
		return false
	}
	for {
		count := ddiastReadyCount.Load()
		if count >= 2 {
			return false
		}
		if ddiastReadyCount.CompareAndSwap(count, count+1) {
			break
		}
	}
	var index uint32
	for {
		index = ddiastSlabsUsed.Load()
		if index >= ddiastSlabCount {
			ddiastReadyCount.Add(-1)
			return false
		}
		if ddiastSlabsUsed.CompareAndSwap(index, index+1) {
			break
		}
	}
	slab := &ddiastSlabs[index]
	slab.base = base
	for {
		head := ddiastReadyHead.Load()
		slab.next = head
		if ddiastReadyHead.CompareAndSwap(head, index+1) {
			return true
		}
	}
}

//go:linkname ddiastReadySlabs github.com/DataDog/dd-iast-go/internal/taint/heapranges.readySlabs
func ddiastReadySlabs() uint32 { return ddiastReadyCount.Load() }

//go:linkname ddiastTakeRefill github.com/DataDog/dd-iast-go/internal/taint/heapranges.takeRefill
func ddiastTakeRefill() bool { return ddiastRefill.Swap(0) != 0 }

//go:linkname ddiastTailUnits github.com/DataDog/dd-iast-go/internal/taint/heapranges.tailUnits
func ddiastTailUnits() uint64 { return ddiastSlabTailLost.Load() }

//go:linkname ddiastAllocateUnits github.com/DataDog/dd-iast-go/internal/taint/heapranges.allocateUnits
//go:nosplit
func ddiastAllocateUnits(units uint32) uint32 {
	if units == 0 || units > ddiastSlabUnits {
		return 0
	}
	current := ddiastCurrentSlab.Load()
	if current == ddiastSlabBusy || current > ddiastSlabCount {
		return 0
	}
	if current != 0 {
		slab := &ddiastSlabs[current-1]
		if slab.bump.Load() <= ddiastSlabUnits-units {
			start := slab.bump.Add(int32(units)) - units
			if start <= ddiastSlabUnits-units {
				return ((current-1)<<14 | start) + 1
			}
		}
	}
	if !ddiastCurrentSlab.CompareAndSwap(current, ddiastSlabBusy) {
		return 0
	}
	head := ddiastReadyHead.Load()
	if head == 0 || head > ddiastSlabCount || !ddiastReadyHead.CompareAndSwap(head, ddiastSlabs[head-1].next) {
		ddiastCurrentSlab.Store(current)
		ddiastRefill.Store(1)
		return 0
	}
	ddiastReadyCount.Add(-1)
	if current != 0 {
		// A late writer must not use a tail that is counted as lost.
		used := ddiastSlabs[current-1].bump.Swap(ddiastSlabUnits)
		if used < ddiastSlabUnits {
			ddiastSlabTailLost.Add(int64(ddiastSlabUnits - used))
		}
	}
	ddiastCurrentSlab.Store(head)
	ddiastRefill.Store(1)
	start := ddiastSlabs[head-1].bump.Add(int32(units)) - units
	if start > ddiastSlabUnits-units {
		return 0
	}
	return ((head-1)<<14 | start) + 1
}

//go:linkname ddiastSlabAddress github.com/DataDog/dd-iast-go/internal/taint/heapranges.slabAddress
//go:nosplit
func ddiastSlabAddress(entry uint32) uintptr {
	if entry == 0 {
		return 0
	}
	index := entry - 1
	slab := index >> 14
	if slab >= ddiastSlabCount || slab >= ddiastSlabsUsed.Load() {
		return 0
	}
	return ddiastSlabs[slab].base + uintptr(index&(ddiastSlabUnits-1))*64
}

//go:linkname ddiastSetQueue github.com/DataDog/dd-iast-go/internal/taint/heapranges.setQueue
func ddiastSetQueue(index, entry uint32) bool {
	if index >= ddiastSlabCount || entry == 0 {
		return false
	}
	return ddiastQueues[index].CompareAndSwap(0, entry)
}

//go:linkname ddiastQueue github.com/DataDog/dd-iast-go/internal/taint/heapranges.queueEntry
func ddiastQueue(index uint32) uint32 {
	if index >= ddiastSlabCount {
		return 0
	}
	return ddiastQueues[index].Load()
}

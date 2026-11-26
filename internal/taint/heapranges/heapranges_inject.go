// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package heapranges

import (
	ddheapknobs "github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
	ddheapunsafe "unsafe"
)

//go:linkname runtimeGate
func runtimeGate() uint32

//go:linkname needWovenRuntime runtime.ddiastHeapRangesNeedTheWovenRuntime
func needWovenRuntime()

//go:linkname accountSlab
func accountSlab()

//go:linkname initEpoch
func initEpoch()

//go:linkname testEpoch
func testEpoch() bool

//go:linkname wovenAny
//go:noescape
func wovenAny(ddheapunsafe.Pointer, uintptr) bool

//go:linkname wovenRanges
//go:noescape
func wovenRanges(ddheapunsafe.Pointer, uintptr, ddheapunsafe.Pointer) uint32

//go:linkname wovenClear
//go:noescape
func wovenClear(ddheapunsafe.Pointer, uintptr, ddheapunsafe.Pointer)

//go:linkname wovenSet
//go:noescape
func wovenSet(ddheapunsafe.Pointer, uintptr, Origin, Kind, ddheapunsafe.Pointer) bool

//go:linkname wovenCopy
//go:noescape
func wovenCopy(ddheapunsafe.Pointer, ddheapunsafe.Pointer, uintptr, Kind, Owner, ddheapunsafe.Pointer) bool

//go:linkname testRecord
func testRecord(uint32, uint32, uint32) uint32

//go:linkname testRecordDetails
func testRecordDetails(uint32, uint64, uint8, uint8, uint8, uint32) bool

//go:linkname wovenStartOwner
func wovenStartOwner(uint32, uint64) bool

//go:linkname wovenEndOwner
func wovenEndOwner(uint32, uint64) bool

//go:linkname wovenOwnerLive
func wovenOwnerLive(uint32, uint64) bool

//go:linkname wovenAttachSnapshot
func wovenAttachSnapshot(uint32, uint64) bool

//go:linkname wovenRetireSnapshot
func wovenRetireSnapshot(uint32, uint64) bool

//go:linkname testRetire
func testRetire(uint32, uint32, uint32) bool

//go:linkname testRetirement
func testRetirement(uint32, uint32) (uint32, uint32, uint64, uint32, uint64)

//go:linkname testSpanPoison
//go:noescape
func testSpanPoison(ddheapunsafe.Pointer, bool) bool

//go:linkname testRecordRange
func testRecordRange(uint32, uint32, uint32, uint32, uint64, uint8, uint8, uint32) bool

//go:linkname testClearFailures
func testClearFailures(uint32)

//go:linkname testSetFailures
func testSetFailures(uint32)

//go:linkname testCopyFailures
func testCopyFailures(uint32)

//go:linkname testSnapshotsOff
func testSnapshotsOff(uint32)

//go:linkname testRangeLimit
func testRangeLimit(uint32)

//go:linkname testRangeCollapses
func testRangeCollapses() uint64

//go:linkname testStoreSnapshot
//go:noescape
func testStoreSnapshot(uint32, uint64, ddheapunsafe.Pointer, uintptr) (uint32, bool)

//go:linkname testSnapshot
//go:noescape
func testSnapshot(uint32, uint64, ddheapunsafe.Pointer, uintptr) bool

//go:linkname wovenMayHaveTaint
//go:noescape
func wovenMayHaveTaint(ddheapunsafe.Pointer, uintptr) bool

//go:linkname testSetGate
func testSetGate(uint32)

//go:linkname testSetProbe
func testSetProbe(ddheapunsafe.Pointer, uintptr)

//go:linkname testPublishEntry
//go:noescape
func testPublishEntry(ddheapunsafe.Pointer, uint32, uint32) bool

//go:linkname testRetireOwn
func testRetireOwn(uint32) bool

//go:linkname testPoisonEntry
//go:noescape
func testPoisonEntry(ddheapunsafe.Pointer) (uint32, uint32, bool)

//go:linkname testCompareEntry
//go:noescape
func testCompareEntry(ddheapunsafe.Pointer, uint32, uint32) bool

//go:linkname testReadEntry
//go:noescape
func testReadEntry(ddheapunsafe.Pointer) uint32

//go:linkname testSpanState
//go:noescape
func testSpanState(ddheapunsafe.Pointer) uint64

//go:linkname testCloneSpanTable
//go:noescape
func testCloneSpanTable(ddheapunsafe.Pointer, ddheapunsafe.Pointer) bool

//go:linkname testBindTable
func testBindTable(uint32, uintptr) bool

//go:linkname testSpanRead
func testSpanRead(uint32) bool

//go:linkname testTableBase
func testTableBase(uint32) uint64

//go:linkname testTableEntry
func testTableEntry(uint32, uint32, uint32, bool) uint32

//go:linkname inspectClassify
//go:noescape
func inspectClassify(ddheapunsafe.Pointer, uintptr) (uintptr, uintptr, uint32, bool)

//go:linkname stackClassify
func stackClassify() bool

//go:linkname publishSlab
func publishSlab(uintptr) bool

//go:linkname readySlabs
func readySlabs() uint32

//go:linkname takeRefill
func takeRefill() bool

//go:linkname tailUnits
func tailUnits() uint64

//go:linkname allocateUnits
func allocateUnits(uint32) uint32

//go:linkname slabAddress
func slabAddress(uint32) uintptr

//go:linkname setQueue
func setQueue(uint32, uint32) bool

//go:linkname queueEntry
func queueEntry(uint32) uint32

var _ = func() bool {
	needWovenRuntime()
	initEpoch()
	ddheapknobs.CheckEpoch = testEpoch
	ddheapknobs.Gate = runtimeGate
	ddheapknobs.OffReason = func() string { return offReason }
	ddheapknobs.MapSlab = func(skipAccounting bool) (bool, uint64) {
		allocator := newSlabAllocator(slabSize)
		if skipAccounting {
			allocator.account = func() {}
		}
		_, ok := allocator.allocate()
		return ok, allocator.mapped.Load()
	}
	ddheapknobs.InitSlabWorker = func(limit uint64) (uint32, uint64, bool) {
		worker, ok := newSlabWorker(limit)
		if !ok {
			return 0, 0, false
		}
		ddheapknobs.RefillOnce = worker.refillOnce
		ddheapknobs.StartRefiller = func() { go worker.run() }
		ddheapknobs.PauseRefiller = func(paused bool) { worker.paused.Store(paused) }
		ddheapknobs.WorkerStats = func() (uint32, uint64) {
			return worker.queues.Load(), worker.allocator.mapped.Load()
		}
		return worker.queues.Load(), worker.allocator.mapped.Load(), true
	}
	runtimeAny = wovenAny
	runtimeRanges = wovenRanges
	runtimeClear = wovenClear
	runtimeSet = wovenSet
	runtimeCopy = wovenCopy
	runtimeStartOwner = wovenStartOwner
	runtimeEndOwner = wovenEndOwner
	runtimeOwnerLive = wovenOwnerLive
	runtimeAttachSnapshot = wovenAttachSnapshot
	runtimeRetireSnapshot = wovenRetireSnapshot
	ddheapknobs.MakeRecord = testRecord
	ddheapknobs.RecordDetails = testRecordDetails
	ddheapknobs.RecordRange = testRecordRange
	ddheapknobs.SpanPoison = testSpanPoison
	ddheapknobs.SetRangeLimit = testRangeLimit
	ddheapknobs.ClearFailures = testClearFailures
	ddheapknobs.SetFailures = testSetFailures
	ddheapknobs.CopyFailures = testCopyFailures
	ddheapknobs.SnapshotsOff = testSnapshotsOff
	ddheapknobs.RangeCollapses = testRangeCollapses
	ddheapknobs.Snapshot = testSnapshot
	ddheapknobs.StoreSnapshot = testStoreSnapshot
	ddheapknobs.Retire = testRetire
	ddheapknobs.Retirement = testRetirement
	runtimeMayHaveTaint = wovenMayHaveTaint
	ddheapknobs.SetGate = testSetGate
	ddheapknobs.SetProbe = testSetProbe
	ddheapknobs.CompareEntry = testCompareEntry
	ddheapknobs.PoisonEntry = testPoisonEntry
	ddheapknobs.PublishEntry = testPublishEntry
	ddheapknobs.RetireOwn = testRetireOwn
	ddheapknobs.ReadEntry = testReadEntry
	ddheapknobs.SpanState = testSpanState
	ddheapknobs.CloneSpanTable = testCloneSpanTable
	ddheapknobs.BindTable = testBindTable
	ddheapknobs.SpanRead = testSpanRead
	ddheapknobs.TableBase = testTableBase
	ddheapknobs.TableEntry = testTableEntry
	ddheapknobs.Classify = inspectClassify
	ddheapknobs.ClassifyStack = stackClassify
	ddheapknobs.QueueEntry = queueEntry
	ddheapknobs.PublishSlab = publishSlab
	ddheapknobs.AllocateUnits = allocateUnits
	ddheapknobs.TailUnits = tailUnits
	ddheapknobs.SlabAddress = slabAddress
	ddheapknobs.ReadySlabs = readySlabs
	runtimeAccountSlab = accountSlab
	runtimePublishSlab = publishSlab
	runtimeReadySlabs = readySlabs
	runtimeTakeRefill = takeRefill
	runtimeAllocateUnits = allocateUnits
	runtimeSlabAddress = slabAddress
	runtimeSetQueue = setQueue
	runtimeQueueEntry = queueEntry
	runtimeEnabled = func() bool { return runtimeGate() == 1 }
	return true
}()

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"encoding/json"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func validQueues(count uint32) bool {
	if knobs.QueueEntry == nil || knobs.SlabAddress == nil {
		return false
	}
	addresses := make(map[uintptr]bool)
	for index := uint32(0); index < count; index++ {
		entry := knobs.QueueEntry(index)
		address := knobs.SlabAddress(entry)
		if entry == 0 || address == 0 || address%64 != 0 {
			return false
		}
		for other := range addresses {
			if address < other+(16<<10) && other < address+(16<<10) {
				return false
			}
		}
		addresses[address] = true
	}
	return true
}

func main() {
	settings := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "-race", "-asan", "-msan":
				settings[setting.Key] = setting.Value
			}
		}
	}
	result := struct {
		Enabled      bool              `json:"enabled"`
		Gate         uint32            `json:"gate"`
		Reason       string            `json:"reason"`
		Settings     map[string]string `json:"settings"`
		Mapped       uint64            `json:"mapped"`
		OtherSys     uint64            `json:"other_sys"`
		OtherBefore  uint64            `json:"other_before"`
		MapOK        bool              `json:"map_ok"`
		Queues       uint32            `json:"queues"`
		QueuesValid  bool              `json:"queues_valid"`
		Ready        uint32            `json:"ready"`
		PoolCount    int               `json:"pool_count"`
		PoolValid    bool              `json:"pool_valid"`
		PauseValid   bool              `json:"pause_valid"`
		RangeValid   bool              `json:"range_valid"`
		RetireValid  bool              `json:"retire_valid"`
		PoisonValid  bool              `json:"poison_valid"`
		SnapValid    bool              `json:"snapshot_valid"`
		PublishValid bool              `json:"publish_valid"`
		ClearValid   bool              `json:"clear_valid"`
		OwnerValid   bool              `json:"owner_valid"`
		SetValid     bool              `json:"set_valid"`
		CopyValid    bool              `json:"copy_valid"`
		MappingValid bool              `json:"mapping_valid"`
	}{Enabled: heapranges.Enabled(), Settings: settings}
	if knobs.Gate != nil {
		result.Gate = knobs.Gate()
	}
	if knobs.OffReason != nil {
		result.Reason = knobs.OffReason()
	}
	if len(os.Args) > 1 && (os.Args[1] == "slab" || os.Args[1] == "slab-negative") && knobs.MapSlab != nil {
		debug.SetGCPercent(-1)
		debug.SetMemoryLimit(math.MaxInt64)
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		result.OtherBefore = stats.OtherSys
		result.MapOK, result.Mapped = knobs.MapSlab(os.Args[1] == "slab-negative")
		runtime.ReadMemStats(&stats)
		result.OtherSys = stats.OtherSys
	}
	if len(os.Args) > 2 && (os.Args[1] == "worker" || os.Args[1] == "worker-refill" || os.Args[1] == "worker-grow" || os.Args[1] == "worker-pause") && knobs.InitSlabWorker != nil {
		limit, err := strconv.ParseUint(os.Args[2], 10, 64)
		if err != nil {
			os.Exit(2)
		}
		result.Queues, result.Mapped, result.MapOK = knobs.InitSlabWorker(limit)
		if result.MapOK && os.Args[1] != "worker" && knobs.StartRefiller != nil && knobs.WorkerStats != nil && knobs.ReadySlabs != nil {
			if os.Args[1] == "worker-grow" {
				runtime.GOMAXPROCS(32)
			}
			if os.Args[1] == "worker-pause" && knobs.PauseRefiller != nil {
				knobs.PauseRefiller(true)
			}
			knobs.StartRefiller()
			if os.Args[1] == "worker-pause" && knobs.PauseRefiller != nil {
				time.Sleep(50 * time.Millisecond)
				queues, mapped := knobs.WorkerStats()
				result.PauseValid = queues == result.Queues && mapped == result.Mapped && knobs.ReadySlabs() == 0
				knobs.PauseRefiller(false)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				queues, _ := knobs.WorkerStats()
				if knobs.ReadySlabs() >= 2 && (os.Args[1] != "worker-grow" || queues >= 32) {
					break
				}
				time.Sleep(time.Millisecond)
			}
			result.Queues, result.Mapped = knobs.WorkerStats()
		}
		result.QueuesValid = result.MapOK && validQueues(result.Queues)
		if knobs.ReadySlabs != nil {
			result.Ready = knobs.ReadySlabs()
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "pool" {
		result.PoolCount, result.PoolValid = exerciseSlabPool()
	}
	if len(os.Args) > 1 && os.Args[1] == "tail" {
		result.PoolValid = exerciseSlabTail()
	}
	if len(os.Args) > 1 && os.Args[1] == "table" {
		result.PoolValid = exerciseTable()
	}
	if len(os.Args) > 2 && os.Args[1] == "ranges" {
		result.RangeValid = exerciseRanges(os.Args[2])
	}
	if len(os.Args) > 1 && os.Args[1] == "retire" {
		result.RetireValid = exerciseRetirement()
	}
	if len(os.Args) > 1 && os.Args[1] == "poison" {
		result.PoisonValid = exercisePoison()
	}
	if len(os.Args) > 1 && os.Args[1] == "snapshot" {
		result.SnapValid = exerciseSnapshot()
	}
	if len(os.Args) > 1 && os.Args[1] == "snapshot-bytes" {
		result.SnapValid = exerciseSnapshotBytes()
	}
	if len(os.Args) > 1 && os.Args[1] == "publish" {
		result.PublishValid = exercisePublish()
	}
	if len(os.Args) > 1 && os.Args[1] == "clear" {
		result.ClearValid = exerciseClear()
	}
	if len(os.Args) > 1 && os.Args[1] == "owner" {
		result.OwnerValid = exerciseOwner()
	}
	if len(os.Args) > 2 && os.Args[1] == "set" {
		result.SetValid = exerciseSet(os.Args[2])
	}
	if len(os.Args) > 2 && os.Args[1] == "copy" {
		result.CopyValid = exerciseCopy(os.Args[2])
	}
	if len(os.Args) > 2 && os.Args[1] == "mapping" {
		result.MappingValid = exerciseMap(os.Args[2])
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}

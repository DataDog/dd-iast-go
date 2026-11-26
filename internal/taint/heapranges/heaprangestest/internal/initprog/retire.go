// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package main

import (
	"math"
	"runtime/debug"

	"github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
)

func exerciseRetirement() bool {
	if knobs.InitSlabWorker == nil || knobs.Retire == nil || knobs.Retirement == nil {
		return false
	}
	debug.SetGCPercent(-1)
	debug.SetMemoryLimit(math.MaxInt64)
	count, _, ok := knobs.InitSlabWorker(1 << 20)
	if !ok || count != 2 {
		return false
	}
	if knobs.Retire(0, 0, 1) || knobs.Retire(0, ^uint32(0), 1) || knobs.Retire(0, ^uint32(1), 1) {
		return false
	}
	_, _, _, producer, lost := knobs.Retirement(0, 0)
	if producer != 0 || lost != 0 {
		return false
	}
	for i := uint32(0); i < 1024; i++ {
		kind := i%2 + 1
		if !knobs.Retire(0, i+1, kind) {
			return false
		}
	}
	for _, position := range []uint32{0, 1, 1023} {
		entry, kind, epoch, producer, lost := knobs.Retirement(0, position)
		if entry != position+1 || kind != position%2+1 || epoch != 1 || producer != 1024 || lost != 0 {
			return false
		}
	}
	if knobs.Retire(0, 1025, 1) {
		return false
	}
	entry, _, _, producer, lost := knobs.Retirement(0, 0)
	if entry != 1 || producer != 1024 || lost != 1 {
		return false
	}
	if knobs.Retire(2, 1, 1) || knobs.Retire(1024, 1, 1) {
		return false
	}
	_, _, _, _, missing := knobs.Retirement(2, 0)
	_, _, _, _, noP := knobs.Retirement(1024, 0)
	return missing == 1 && noP == 1
}

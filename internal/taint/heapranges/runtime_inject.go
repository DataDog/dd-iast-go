// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package runtime

import (
	ddheapatomic "internal/runtime/atomic"
	_ "unsafe"
)

var (
	ddiastHeapGate ddheapatomic.Uint32
	_              *sysMemStat                              = &memstats.other_sys
	_              *ddheapatomic.Uint64                     = &gcController.mappedReady
	_              func(*sysMemStat, int64)                 = (*sysMemStat).add
	_              func(*ddheapatomic.Uint64, int64) uint64 = (*ddheapatomic.Uint64).Add
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

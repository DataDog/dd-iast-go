// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package runtime

import (
	"internal/runtime/atomic"
	_ "unsafe"
)

var ddiastSweepCount atomic.Uint64

//go:linkname ddiastNeed runtime.ddiastHeapRangesNeedTheWovenRuntime
func ddiastNeed() {}

//go:linkname ddiastSpike github.com/DataDog/dd-iast-go/internal/taint/heapranges.spikeRuntime
func ddiastSpike() uint64 {
	return 42 + ddiastSweepCount.Load()
}

//go:linkname ddiastAccount github.com/DataDog/dd-iast-go/internal/taint/heapranges.spikeAccount
func ddiastAccount(n int64) {
	memstats.other_sys.add(n)
	gcController.mappedReady.Add(n)
}

//go:nosplit
func ddiastSweepProbe(s *mspan) {
	_ = s.ddiastSpike.Load()
	ddiastSweepCount.Add(1)
}

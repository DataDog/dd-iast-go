// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package heapranges

import _ "unsafe"

//go:linkname spikeRuntime
func spikeRuntime() uint64

//go:linkname needWovenRuntime runtime.ddiastHeapRangesNeedTheWovenRuntime
func needWovenRuntime()

//go:linkname spikeAccount
func spikeAccount(int64)

var _ = func() bool {
	needWovenRuntime()
	runtimeProbe = spikeRuntime
	runtimeAccount = spikeAccount
	return true
}()

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

package heapranges

import (
	ddheapknobs "github.com/DataDog/dd-iast-go/internal/taint/heapranges/internal/knobs"
	_ "unsafe"
)

//go:linkname runtimeGate
func runtimeGate() uint32

//go:linkname needWovenRuntime runtime.ddiastHeapRangesNeedTheWovenRuntime
func needWovenRuntime()

var _ = func() bool {
	needWovenRuntime()
	ddheapknobs.Gate = runtimeGate
	ddheapknobs.OffReason = func() string { return offReason }
	runtimeEnabled = func() bool { return runtimeGate() == 1 }
	return true
}()

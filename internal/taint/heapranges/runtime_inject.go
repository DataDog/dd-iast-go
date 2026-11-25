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

var ddiastHeapGate ddheapatomic.Uint32

//go:linkname ddiastHeapRangesNeedRuntime runtime.ddiastHeapRangesNeedTheWovenRuntime
func ddiastHeapRangesNeedRuntime() {}

//go:linkname ddiastHeapRangesGate github.com/DataDog/dd-iast-go/internal/taint/heapranges.runtimeGate
func ddiastHeapRangesGate() uint32 {
	return ddiastHeapGate.Load()
}

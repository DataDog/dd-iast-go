// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heaprangestest

import (
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-iast-go/internal/taint/heapranges"
)

func TestRuntimeProbe(t *testing.T) {
	if !build.Instrumented() {
		t.Skip("not woven")
	}
	before := heapranges.Probe()
	if before < 42 {
		t.Fatalf("probe = %d, want at least 42", before)
	}
	for i := 0; i < 8 && heapranges.Probe() == before; i++ {
		for j := 0; j < 10000; j++ {
			_ = new([1024]byte)
		}
		runtime.GC()
	}
	if got := heapranges.Probe(); got <= before {
		t.Fatalf("sweep hook count did not advance: before=%d after=%d", before, got)
	}
}

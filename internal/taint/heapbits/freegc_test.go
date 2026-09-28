// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"runtime/debug"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// With GOEXPERIMENT=runtimefreegc, the runtime can free an object at once
// (no GC) and give its memory to the next allocation. That memory must not
// keep the taint. The size given to freegc (60) is smaller than the slot (64),
// and the taint is in the last bytes of the slot: the hook must clear the
// whole slot.
func TestNoTaintAfterFreegc(t *testing.T) {
	need(t)
	if !heapbitstest.Enabled() {
		t.Fatal("test knobs are not enabled")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	freed, reused, bad := 0, 0, 0
	for range 1000 {
		b := heapBytes(64)
		p := unsafe.Pointer(unsafe.SliceData(b))
		heapbits.SetBytes(b[60:64])
		if !heapbitstest.Freegc(p, 60) {
			continue
		}
		freed++
		n := heapBytes(64)
		if unsafe.Pointer(unsafe.SliceData(n)) == p {
			reused++
		}
		if heapbits.AnyBytes(n) {
			bad++
		}
	}
	if freed == 0 {
		t.Skip("freegc is not active (GOEXPERIMENT=runtimefreegc not set)")
	}
	if reused == 0 {
		t.Fatalf("freegc freed %d objects, but no address was used again: the test is not valid", freed)
	}
	if bad != 0 {
		t.Fatalf("%d of %d freegc reuses inherited taint", bad, reused)
	}
}

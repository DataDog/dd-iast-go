package heapbits_test

import (
	"runtime/debug"
	"testing"
	"unsafe"

	"example.com/allocbits/heapbits"
)

// With GOEXPERIMENT=runtimefreegc, the runtime can free an object at once
// (no GC) and give its memory to the next allocation. That memory must not
// keep the taint.
func TestNoTaintAfterFreegc(t *testing.T) {
	need(t)
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	freed, bad := 0, 0
	for range 1000 {
		b := heapBytes(64)
		heapbits.TaintBytes(b)
		if !heapbits.FreegcForTest(unsafe.Pointer(unsafe.SliceData(b)), 64) {
			continue
		}
		freed++
		if heapbits.IsTaintedBytes(heapBytes(64)) {
			bad++
		}
	}
	if freed == 0 {
		t.Skip("freegc is not active (GOEXPERIMENT=runtimefreegc not set)")
	}
	if bad != 0 {
		t.Fatalf("%d of %d freegc reuses inherited taint", bad, freed)
	}
}

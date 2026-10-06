// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// freshTainted returns a new heap string of n bytes, with the bytes [lo, hi)
// tainted, or "" when Set dropped the taint (Set never waits, so it can drop
// the taint while the collector runs). No other variable keeps its memory: when it is an operand of a
// concatenation, only the operand array of the runtime keeps it alive.
//
//go:noinline
func freshTainted(n, lo, hi int, fill byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	if !heapbits.Set(unsafe.Pointer(&b[lo]), uintptr(hi-lo)) {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// freshClean returns a new heap string of n bytes, without taint.
//
//go:noinline
func freshClean(n int, fill byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// TestConcatTemporaryOperandsUnderGC checks that the concatenation hooks copy
// the exact bits of temporary operands while other goroutines force garbage
// collections and allocate memory of the same size. The tainted operand is the
// last operand, and only the operand array of the runtime keeps it alive
// during the bit copy (__dd_iast_copyparts). When this memory is not live
// during the copy, the collector can free its slot (and clear its bits): then
// the result has no taint (without a storage drop) or the bits of a new value.
//
// The storage of the bits never waits: under this load, Set and Copy can drop
// the taint (the storage counts each drop). A result without taint is thus
// correct only when the storage counted a drop for it.
func TestConcatTemporaryOperandsUnderGC(t *testing.T) {
	requireWoven(t)
	rounds, size := 3000, 8<<10
	if testing.Short() {
		rounds = 300
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	gc0 := ms.NumGC
	drops0 := storageDrops()

	stop := make(chan struct{})
	var bg sync.WaitGroup
	bg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	})
	for range 2 {
		bg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					// Garbage of the size class of the operands: a freed
					// operand slot is quickly used again.
					for range 16 {
						sinkChurn(freshClean(size, 'g'))
					}
				}
			}
		})
	}

	var wg sync.WaitGroup
	var notSet, lost atomic.Int64
	errs := make(chan string, 16)
	// check returns false (and reports an error) when the result has wrong
	// taint. A result without taint counts as lost.
	check := func(op string, round, n, wantLen int, got []span, want []span) bool {
		switch {
		case n == wantLen-size:
			notSet.Add(1) // Set dropped the taint of the operand
		case n != wantLen:
			errs <- fmt.Sprintf("%s round %d: len %d, want %d", op, round, n, wantLen)
			return false
		case len(got) == 0:
			lost.Add(1)
		case !slices.Equal(got, want):
			errs <- fmt.Sprintf("%s round %d: spans %s, want %s", op, round, spansString(got), spansString(want))
			return false
		}
		return true
	}
	for w := range 4 {
		wg.Go(func() {
			for i := range rounds {
				lo := (w + i) % 64
				hi := size - lo
				pre := strings.Repeat("p", 1+(w+i)%5)

				// The temporary is the last of 3 operands (concatstring3
				// builds the operand array on its stack).
				got := heapConcat3(pre, freshClean(7, 'c'), freshTainted(size, lo, hi, 't'))
				if !check("concatstrings", i, len(got), len(pre)+7+size, stringSpans(got), []span{{len(pre) + 7 + lo, len(pre) + 7 + hi}}) {
					return
				}
				gotB := heapConcatBytes(pre, freshTainted(size, lo, hi, 't'))
				if !check("concatbytes", i, len(gotB), len(pre)+size, bytesSpans(gotB), []span{{len(pre) + lo, len(pre) + hi}}) {
					return
				}
			}
		})
	}
	wg.Wait()
	close(stop)
	bg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}

	total := int64(2 * 4 * rounds)
	drops := storageDrops() - drops0
	if n := notSet.Load() + lost.Load(); uint64(n) > drops {
		t.Errorf("%d operands or results without taint, but the storage counted only %d drops: the hooks lost taint", n, drops)
	}
	if n := notSet.Load() + lost.Load(); n > total/2 {
		t.Errorf("%d of %d operations without taint: the test checked too few operations", n, total)
	}
	runtime.ReadMemStats(&ms)
	if ms.NumGC-gc0 < 2 {
		t.Errorf("only %d garbage collections ran during the test: the test did not check the hooks under GC", ms.NumGC-gc0)
	}
	t.Logf("%d garbage collections, %d operations; taint not set: %d, results without taint: %d, storage drops: %d",
		ms.NumGC-gc0, total, notSet.Load(), lost.Load(), drops)
}

// storageDrops returns the number of refused bit operations of the storage.
func storageDrops() uint64 {
	d := heapbitstest.Stats().Drops
	return d.Budget + d.RefillBusy + d.Contention + d.Mmap + d.SlotBusy + d.Span
}

// churnSink keeps the last garbage value of the churn goroutines (a new value
// each time: the old values are garbage).
var churnSink atomic.Pointer[byte]

//go:noinline
func sinkChurn(s string) { churnSink.Store(unsafe.StringData(s)) }

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// new16 and new48 allocate on the heap (a new object that does not escape
// would be on the stack).
//
//go:noinline
func new16() *[16]byte { return new([16]byte) }

//go:noinline
func new48() *[48]byte { return new([48]byte) }

// Two objects in one bitmap word: one live (tainted again in a loop), one
// dead. The sweeper clears the dead one while the live one gets Set calls;
// the live bits must stay, and the dead memory must be clean when it is used
// again.
func TestDeadNeighbourInSameWord(t *testing.T) {
	need(t)
	const n = 4096
	objs := make([]*[16]byte, n) // size class 16: 4 objects in one 64-byte word
	for i := range objs {
		objs[i] = new([16]byte)
		if !heapbits.SetBytes(objs[i][:]) {
			t.Fatal("Set failed")
		}
	}
	var live []*[16]byte
	dead := make(map[uintptr]bool)
	for i := 1; i < n; i++ {
		a, b := objs[i-1], objs[i]
		if a == nil || b == nil || uintptr(unsafe.Pointer(a))/64 != uintptr(unsafe.Pointer(b))/64 {
			continue
		}
		live = append(live, a)
		dead[uintptr(unsafe.Pointer(b))] = true
		objs[i-1], objs[i] = nil, nil
	}
	objs = nil
	if len(live) < 100 {
		t.Fatalf("only %d pairs in one word", len(live))
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	var rounds atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			for _, o := range live {
				if !heapbits.SetBytes(o[:]) {
					t.Error("Set failed")
					return
				}
			}
			rounds.Add(1)
		}
	}()
	for rounds.Load() == 0 {
		runtime.Gosched()
	}
	before := rounds.Load()
	for range 4 {
		runtime.GC()
	}
	stop.Store(true)
	wg.Wait()
	if rounds.Load() == before {
		t.Fatal("no Set round ran during the GC cycles")
	}
	for i, o := range live {
		for j := range o {
			if !heapbits.AnyBytes(o[j : j+1]) {
				t.Fatalf("live object %d lost its taint at byte %d", i, j)
			}
		}
	}
	reused := 0
	for range 2 * n {
		o := new16()
		if dead[uintptr(unsafe.Pointer(o))] {
			reused++
			if heapbits.AnyBytes(o[:]) {
				t.Fatal("a new object in the memory of a dead neighbour has old taint")
			}
		}
	}
	if reused == 0 {
		t.Fatal("no dead address was used again: the test is not valid")
	}
	runtime.KeepAlive(live)
}

// The flag protocol, with forced interleavings: the sweep of a span waits
// after its flag reset (flag = 0) or after its live check, and a Set on a
// clean live object of that span runs there. The flag must be 1 after the
// sweep (else the bits of the object would never be cleared when it dies).
func TestFlagProtocolInterleaving(t *testing.T) {
	need(t)
	if runtime.GOMAXPROCS(0) < 2 {
		t.Skip("needs 2 Ps: the sweep waits without yield")
	}
	defer heapbitstest.SweepKnobs(nil, heapbitstest.NoPause, false)
	for name, point := range map[string]uint32{"after reset": heapbitstest.PauseAfterReset, "after checks": heapbitstest.PauseAfterChecks} {
		t.Run(name, func(t *testing.T) { flagInterleaving(t, point) })
	}
}

func flagInterleaving(t *testing.T, point uint32) {
	for attempt := range 5 {
		objs := make([]*[48]byte, 64)
		for i := range objs {
			objs[i] = new48()
		}
		// Allocate more objects of the size class: the span of objs is then
		// full and not in an mcache (a cached span is swept at a safe point
		// of its P, where the other goroutine could not run).
		more := make([]*[48]byte, 2048)
		for i := range more {
			more[i] = new48()
		}
		o, other := objs[10], objs[20]
		if b1, _ := heapbitstest.SpanInfo(unsafe.Pointer(o)); b1 == 0 {
			t.Fatal("no span")
		} else if b2, _ := heapbitstest.SpanInfo(unsafe.Pointer(other)); b1 != b2 {
			continue // not in one span: try again
		}
		// The span gets its flag; no bit stays.
		if !heapbits.SetBytes(other[:]) {
			t.Fatal("Set failed")
		}
		heapbits.ClearBytes(other[:])
		heapbitstest.SweepKnobs(unsafe.Pointer(o), point, false)
		var wg sync.WaitGroup
		var inWindow atomic.Bool
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, w := heapbitstest.SweepKnobs(unsafe.Pointer(o), point, false); w == heapbitstest.SweepWaiting {
					heapbits.SetBytes(o[:])
					inWindow.Store(true)
					heapbitstest.SweepKnobs(unsafe.Pointer(o), point, true)
					return
				}
				runtime.Gosched()
			}
		}()
		runtime.GC()
		wg.Wait()
		sweeps, waiting := heapbitstest.SweepKnobs(unsafe.Pointer(o), heapbitstest.NoPause, false)
		if !inWindow.Load() || waiting != heapbitstest.SweepContinued || sweeps == 0 {
			t.Logf("attempt %d: the Set did not run in the window (sweeps %d, waiting %d)", attempt, sweeps, waiting)
			runtime.KeepAlive(objs)
			runtime.KeepAlive(more)
			continue
		}
		runtime.KeepAlive(more)
		if !heapbits.AnyBytes(o[:]) {
			t.Fatal("the object lost its taint")
		}
		if got := heapbitstest.SpanFlag(unsafe.Pointer(o)); got != 1 {
			t.Fatalf("span flag %d after a Set in the reset window, want 1", got)
		}
		runtime.KeepAlive(objs)
		return
	}
	t.Fatal("the Set never ran in the reset window")
}

// Set on live objects while the GC runs (smoke test of the flag protocol).
// When these objects die, their bits must be cleared: a new object never gets
// their taint.
func TestFlagProtocolUnderGC(t *testing.T) {
	need(t)
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			runtime.GC()
		}
	}()
	const n = 20000
	objs := make([]*[48]byte, n)
	addrs := make(map[uintptr]bool, n)
	for i := range objs {
		objs[i] = new48()
		if !heapbits.SetBytes(objs[i][:]) {
			t.Fatal("Set failed")
		}
		addrs[uintptr(unsafe.Pointer(objs[i]))] = true
	}
	stop.Store(true)
	wg.Wait()
	for i, o := range objs {
		if !heapbits.AnyBytes(o[:]) {
			t.Fatalf("live object %d lost its taint", i)
		}
	}
	objs = nil
	runtime.GC()
	runtime.GC()
	reused := 0
	// Keep the new objects: each one gets a new address (else the
	// allocator, or freegc, can give the same slot again and again).
	fresh := make([]*[48]byte, 0, 2*n)
	defer runtime.KeepAlive(fresh)
	for range 2 * n {
		o := new48()
		fresh = append(fresh, o)
		if addrs[uintptr(unsafe.Pointer(o))] {
			reused++
			if heapbits.AnyBytes(o[:]) {
				t.Fatal("a new object has the taint of a dead object (flag lost?)")
			}
		}
	}
	if reused == 0 {
		t.Fatal("no dead address was used again: the test is not valid")
	}
}

// ptrObj is 8 bytes with a pointer: it is not in a tiny block.
type ptrObj struct{ p *byte }

//go:noinline
func newPtrObj() *ptrObj { return new(ptrObj) }

// The live check of the sweep hook reads the bits of each run of live
// objects, with a work limit (1024 units: one for each chunk and one for
// each word, thus at most 129 for a span of 8 KiB): for a span of small
// objects without taint, the flag goes back to 0, with many or few live
// objects; for a span of large slots with one live slot, it reads only the
// live slot; for a larger live object without taint (more than 1024
// words), the flag stays 1 (safe).
func TestBoundedFlagReset(t *testing.T) {
	need(t)
	defer heapbitstest.SweepKnobs(nil, heapbitstest.NoPause, false)
	check := func(t *testing.T, objs []*ptrObj, o *ptrObj, want int) {
		t.Helper()
		base, nelems := heapbitstest.SpanInfo(unsafe.Pointer(o))
		live := 0
		for _, x := range objs {
			if a := uintptr(unsafe.Pointer(x)); a >= base && a < base+nelems*8 {
				live++
			}
		}
		// Taint then clear o: the span gets its flag, no bit stays.
		b := unsafe.Slice((*byte)(unsafe.Pointer(o)), 8)
		if !heapbits.SetBytes(b) {
			t.Fatal("Set failed")
		}
		heapbits.ClearBytes(b)
		heapbitstest.SweepKnobs(unsafe.Pointer(o), heapbitstest.NoPause, false)
		runtime.GC()
		runtime.GC()
		sweeps, _ := heapbitstest.SweepKnobs(unsafe.Pointer(o), heapbitstest.NoPause, false)
		if sweeps == 0 {
			t.Fatal("the sweep hook did not run for the span")
		}
		if got := heapbitstest.SpanFlag(unsafe.Pointer(o)); got != want {
			t.Errorf("%d live objects in the span (of %d): flag %d, want %d", live, nelems, got, want)
		}
		t.Logf("%d live objects in the span (of %d)", live, nelems)
		runtime.KeepAlive(objs)
	}
	t.Run("many", func(t *testing.T) {
		objs := make([]*ptrObj, 4096)
		for i := range objs {
			objs[i] = newPtrObj()
		}
		o := objs[2048]
		base, nelems := heapbitstest.SpanInfo(unsafe.Pointer(o))
		live := 0
		for _, x := range objs {
			if a := uintptr(unsafe.Pointer(x)); a >= base && a < base+nelems*8 {
				live++
			}
		}
		if live < 600 {
			t.Fatalf("only %d live objects in the span", live)
		}
		check(t, objs, o, 0)
	})
	t.Run("large slots, one live", func(t *testing.T) {
		// Slots of 27264 bytes: 3 in a span of 10 pages (1280 words, more
		// than the limit); the live slot has 426 words.
		const size = 27264
		objs := make([][]byte, 30)
		for i := range objs {
			objs[i] = heapBytes(size)
		}
		o := objs[len(objs)/2]
		base, nelems := heapbitstest.SpanInfo(ptr(o))
		if nelems != 3 {
			t.Skipf("span of %d objects of %d bytes, want 3", nelems, size)
		}
		clear(objs) // only o stays live
		if !heapbits.SetBytes(o) {
			t.Fatal("Set failed")
		}
		heapbits.ClearBytes(o)
		heapbitstest.SweepKnobs(ptr(o), heapbitstest.NoPause, false)
		runtime.GC()
		runtime.GC()
		sweeps, _ := heapbitstest.SweepKnobs(ptr(o), heapbitstest.NoPause, false)
		if sweeps == 0 {
			t.Fatal("the sweep hook did not run for the span")
		}
		if got := heapbitstest.SpanFlag(ptr(o)); got != 0 {
			t.Errorf("flag %d, want 0 (span at %#x: one live slot without taint)", got, base)
		}
		runtime.KeepAlive(o)
	})
	t.Run("limit", func(t *testing.T) {
		// 96 KiB: 1536 words, more than the limit, and no whole chunk
		// inside (see the large-object rule of the hook).
		b := heapBytes(96 << 10)
		if !heapbits.SetBytes(b) {
			t.Fatal("Set failed")
		}
		heapbits.ClearBytes(b)
		heapbitstest.SweepKnobs(ptr(b), heapbitstest.NoPause, false)
		runtime.GC()
		runtime.GC()
		sweeps, _ := heapbitstest.SweepKnobs(ptr(b), heapbitstest.NoPause, false)
		if sweeps == 0 {
			t.Fatal("the sweep hook did not run for the span")
		}
		if got := heapbitstest.SpanFlag(ptr(b)); got != 1 {
			t.Errorf("flag %d, want 1 (the limit of the live check)", got)
		}
		runtime.KeepAlive(b)
	})
	t.Run("few", func(t *testing.T) {
		// A fresh span: allocate (and keep live) until an object is the
		// first object of a span, then take it and the next 3 objects if
		// they are in the same span (else try again).
		var filler []*ptrObj
		var objs []*ptrObj
		for try := 0; try < 16 && objs == nil; try++ {
			for range 8192 {
				x := newPtrObj()
				if b, _ := heapbitstest.SpanInfo(unsafe.Pointer(x)); b == uintptr(unsafe.Pointer(x)) {
					cand := []*ptrObj{x, newPtrObj(), newPtrObj(), newPtrObj()}
					ok := true
					for _, y := range cand {
						if by, _ := heapbitstest.SpanInfo(unsafe.Pointer(y)); by != b {
							ok = false
						}
					}
					if ok {
						objs = cand
						break
					}
					filler = append(filler, cand...)
					continue
				}
				filler = append(filler, x)
			}
		}
		if objs == nil {
			t.Fatal("no fresh span found")
		}
		check(t, objs, objs[2], 0)
		runtime.KeepAlive(filler)
	})
}

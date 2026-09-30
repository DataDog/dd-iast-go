// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

func TestRecycle(t *testing.T) {
	need(t)
	if os.Getenv(storageChildEnv) != "" {
		t.Skip("in a child process")
	}
	t.Logf("child:\n%s", runChild(t, "TestRecycleChild", "recycle"))
}

// gc runs two cycles: the first one frees the dead objects, and the sweep
// of the second one is complete too.
func gc() {
	runtime.GC()
	runtime.GC()
}

//go:noinline
func taintedObject(t testing.TB, n int) uintptr {
	b := heapBytes(n)
	if !heapbits.SetBytes(b) {
		t.Fatalf("Set of %d bytes failed: %+v", n, heapbitstest.Stats())
	}
	return addr(b)
}

func TestRecycleChild(t *testing.T) {
	need(t)
	if os.Getenv(storageChildEnv) != "recycle" {
		t.Skip("runs in the child process of TestRecycle")
	}
	if !heapbits.SetBudget(childBudget) {
		t.Fatal("SetBudget failed before the first Set")
	}
	tainted = freshRegion()
	if !heapbits.SetBytes(tainted[:1]) {
		t.Fatal("first Set failed")
	}

	t.Run("dead large object gives back its chunks, and they are zeroed", func(t *testing.T) {
		fillFreeChunks(t)
		// The chunks of this object come from a new slab: they are the
		// lowest free bits, and they are taken first when they are free.
		taintedObject(t, 1<<20)
		before := heapbitstest.Stats()
		gc()
		after := heapbitstest.Stats()
		// 1 MiB covers at least 7 whole chunks.
		got := after.Recycled - before.Recycled
		if got < 7 || before.ChunksInUse-after.ChunksInUse != got {
			t.Fatalf("recycled %d chunks, chunks in use %d -> %d", got, before.ChunksInUse, after.ChunksInUse)
		}
		// The next new chunk is a recycled one: it must be clean.
		r := freshRegion()
		if !heapbits.SetBytes(r[100:101]) {
			t.Fatal("Set failed")
		}
		if st := heapbitstest.Stats(); st.Slabs != after.Slabs || st.ChunksInUse != after.ChunksInUse+1 {
			t.Fatalf("the Set did not use a recycled chunk: %+v", st)
		}
		if heapbits.AnyBytes(r[:100]) || heapbits.AnyBytes(r[101:]) || !heapbits.AnyBytes(r[100:101]) {
			t.Error("a recycled chunk was not zeroed")
		}
	})

	t.Run("failed Set: the chunks it got are recycled when the object dies", func(t *testing.T) {
		// Only the chunks of one slab are free (a new slab for a dead
		// 1 MiB object), and mmap fails: a Set of a 16 MiB object (128
		// chunks) gets them, then fails.
		fillFreeChunks(t)
		taintedObject(t, 1<<20)
		gc()
		free := freeChunks()
		if free < 7 {
			t.Fatalf("only %d free chunks", free)
		}
		before := heapbitstest.Stats()
		heapbitstest.AllocKnobs(true, false, false, false)
		ok := failedSet(16 << 20)
		heapbitstest.AllocKnobs(false, false, false, false)
		if ok {
			t.Fatal("Set of 16 MiB succeeded with a failing mmap")
		}
		mid := heapbitstest.Stats()
		if mid.ChunksInUse-before.ChunksInUse != free {
			t.Fatalf("the failed Set took %d chunks, want %d", mid.ChunksInUse-before.ChunksInUse, free)
		}
		gc()
		after := heapbitstest.Stats()
		// All but at most 3: a new directory stays with its arena, and the
		// first chunk is shared with other objects when the object does
		// not start on a chunk boundary (one more directory and edge if it
		// crosses an arena boundary: counted in the 3 with some margin).
		// Without the fix, none: the span had no flag.
		if after.Recycled-mid.Recycled+3 < free || after.ChunksInUse > before.ChunksInUse+3 {
			t.Fatalf("recycled %d chunks after the death, want about %d (chunks in use %d, before the Set %d)",
				after.Recycled-mid.Recycled, free, after.ChunksInUse, before.ChunksInUse)
		}
	})

	t.Run("cleared live large object: its chunks are recycled when it dies", func(t *testing.T) {
		b := heapBytes(1 << 20)
		if !heapbits.SetBytes(b) {
			t.Fatal("Set failed")
		}
		heapbits.ClearBytes(b)
		gc() // live: the flag must stay (whole chunks inside)
		if f := heapbitstest.SpanFlag(ptr(b)); f != 1 {
			t.Fatalf("flag of the live cleared object: %d, want 1", f)
		}
		before := heapbitstest.Stats()
		runtime.KeepAlive(b)
		b = nil
		gc()
		if got := heapbitstest.Stats().Recycled - before.Recycled; got < 7 {
			t.Fatalf("recycled %d chunks after the death, want at least 7", got)
		}
	})

	t.Run("live neighbour in an edge chunk keeps its taint", func(t *testing.T) {
		// A dead large object D, and a live object in the chunk of the end
		// of D (after D): that chunk is not fully inside D, so it is not
		// recycled, and the bits of the neighbour stay.
		for range 16 {
			dead := heapBytes(1<<20 + 8<<10) // the end is not chunk-aligned
			end := addr(dead) + uintptr(len(dead))
			chunkEnd := (end + heapbitstest.ChunkHeapBytes - 1) &^ (heapbitstest.ChunkHeapBytes - 1)
			var neighbour []byte
			for range 64 {
				b := keepBytes(4 << 10)
				if addr(b) >= end && addr(b)+4<<10 <= chunkEnd {
					neighbour = b
					break
				}
			}
			if neighbour == nil {
				continue
			}
			if !heapbits.SetBytes(dead) || !heapbits.SetBytes(neighbour) {
				t.Fatalf("Set failed: %+v", heapbitstest.Stats())
			}
			dead = nil
			gc()
			for i := range neighbour {
				if !heapbits.AnyBytes(neighbour[i : i+1]) {
					t.Fatalf("the live neighbour lost its taint at byte %d", i)
				}
			}
			return
		}
		t.Fatal("no live neighbour found in the edge chunk")
	})

	t.Run("largest taintable span", func(t *testing.T) {
		before := heapbitstest.Stats()
		tooBig := heapBytes(heapbitstest.MaxSpanBytes + 1)
		if heapbits.SetBytes(tooBig[:1]) {
			t.Error("Set in a span larger than 64 MiB succeeded")
		}
		if st := heapbitstest.Stats(); st.Drops.Span != before.Drops.Span+1 {
			t.Errorf("span drops: %d, want %d", st.Drops.Span, before.Drops.Span+1)
		}
		runtime.KeepAlive(tooBig)
		// Exactly 64 MiB is accepted; when it dies, its chunks come back.
		taintedObject(t, heapbitstest.MaxSpanBytes)
		mid := heapbitstest.Stats()
		gc()
		if got := heapbitstest.Stats().Recycled - mid.Recycled; got < 511 {
			t.Errorf("a dead 64 MiB object gave back %d chunks, want at least 511", got)
		}
	})

	t.Run("full budget: a Set uses a recycled chunk", func(t *testing.T) {
		// A tainted 1 MiB object, then the whole budget in use.
		large := heapBytes(1 << 20)
		if !heapbits.SetBytes(large) {
			t.Fatal("Set failed")
		}
		fillBudget(t)
		full := heapbitstest.Stats()
		if heapbits.SetBytes(freshRegion()[:1]) {
			t.Fatal("Set succeeded with a full budget")
		}
		// The object dies: its chunks are free again, and the next Set
		// gets one without a new slab.
		runtime.KeepAlive(large)
		large = nil
		gc()
		if heapbitstest.Stats().Recycled == full.Recycled {
			t.Fatal("no chunk was recycled")
		}
		r := freshRegion()
		if !heapbits.SetBytes(r[:1]) || !heapbits.AnyBytes(r[:1]) {
			t.Fatalf("Set failed after the recycle: %+v", heapbitstest.Stats())
		}
		if st := heapbitstest.Stats(); st.Slabs != full.Slabs || st.Mapped != full.Mapped {
			t.Errorf("a new slab was mapped: %+v", st)
		}
	})
}

// Stress: large tainted objects die and their chunks are used again, while
// other goroutines taint fresh memory and the GC runs. Invariants: live
// objects keep their taint, new objects never have old taint, and the
// storage counters stay consistent.
func TestRecycleStress(t *testing.T) {
	need(t)
	if testing.Short() {
		t.Skip("stress test")
	}
	before := heapbitstest.Stats()
	var stop atomic.Bool
	var wg sync.WaitGroup
	var sets, reused atomic.Int64
	errs := make(chan string, 16)
	report := func(msg string) {
		select {
		case errs <- msg:
		default:
		}
	}
	for w := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var live [][]byte
			dead := make(map[uintptr]bool) // addresses of dropped tainted objects
			for i := 0; !stop.Load(); i++ {
				size := (1 + (w+i)%4) << 20 // 1 to 4 MiB: large objects
				b := heapBytes(size)
				if dead[addr(b)] {
					reused.Add(1)
					delete(dead, addr(b))
				}
				if heapbits.AnyBytes(b) {
					report("a new object has old taint")
					return
				}
				if !heapbits.SetBytes(b) {
					continue // a drop is permitted
				}
				sets.Add(1)
				live = append(live, b)
				if len(live) > 4 {
					for j, o := range live[:2] {
						if !heapbits.AnyBytes(o[:1]) || !heapbits.AnyBytes(o[len(o)-1:]) {
							report("a live object lost its taint")
							return
						}
						dead[addr(o)] = true
						live[j] = nil
					}
					live = live[2:]
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			runtime.GC()
		}
	}()
	// Run until enough reuse happened (at least 1 s, at most 10 s).
	start := time.Now()
	for time.Since(start) < time.Second || (reused.Load() < 20 && time.Since(start) < 10*time.Second) {
		time.Sleep(50 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
	st := heapbitstest.Stats()
	if st.ChunksInUse > st.Slabs*heapbitstest.ChunksPerSlab || st.UsedMax > st.Budget || st.Used != st.Mapped {
		t.Errorf("inconsistent storage: %+v", st)
	}
	if st.Recycled == before.Recycled {
		t.Error("no chunk was recycled during the test")
	}
	if reused.Load() == 0 {
		t.Error("no address of a dead tainted object was used again: the test proves little")
	}
	t.Logf("%d Sets, %d addresses used again, %d chunks recycled", sets.Load(), reused.Load(), st.Recycled-before.Recycled)
}

// freeChunks returns the number of free chunks in the mapped slabs.
func freeChunks() uint64 {
	st := heapbitstest.Stats()
	return st.Slabs*heapbitstest.ChunksPerSlab - st.ChunksInUse
}

// failedSet taints a new object of n bytes, which then dies.
//
//go:noinline
func failedSet(n int) bool {
	return heapbits.SetBytes(heapBytes(n))
}

// fillBudget uses all the budget: no free chunk, no new slab. Regions in a
// new arena need 2 chunks (the directory and the bits): when a Set of a
// fresh region fails, it uses a region whose arena has a directory (it
// needs 1 chunk). The GCs that the fill starts can recycle chunks of dead
// objects: it fills again after a GC, until the budget stays full.
func fillBudget(t *testing.T) {
	t.Helper()
	spare := withDirectory(t, 8)
	full := func() bool {
		st := heapbitstest.Stats()
		return st.Mapped == st.Budget && st.ChunksInUse == st.Slabs*heapbitstest.ChunksPerSlab
	}
	for range 8 {
		for range 8192 {
			if full() {
				break
			}
			if !heapbits.SetBytes(freshRegion()[:1]) {
				if len(spare) == 0 {
					t.Fatalf("no spare region left: %+v", heapbitstest.Stats())
				}
				if !heapbits.SetBytes(spare[0][:1]) {
					t.Fatalf("Set of a region with a directory failed: %+v", heapbitstest.Stats())
				}
				spare = spare[1:]
			}
		}
		gc()
		if full() {
			return
		}
	}
	t.Fatalf("could not fill the budget: %+v", heapbitstest.Stats())
}

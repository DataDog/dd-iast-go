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
func taintedObject(t *testing.T, n int) uintptr {
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

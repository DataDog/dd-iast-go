// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// Worst-case benchmarks of plan section 7.1 (they need the test knobs). The
// micro benchmarks are in package microbench; the overhead against an
// application without the feature is in benchmarks/overhead (section 7.2).

func needBench(b *testing.B) {
	b.Helper()
	if !heapbits.Enabled() {
		b.Skip("feature is not enabled")
	}
}

// gcWorkload measures one operation: prepare (allocations and Set, in
// set-ns/op) then one GC (ns/op: the GC only). It also reports the time in
// the sweep hook (hook-ns/op: all hooks from the start of prepare to the end
// of the GC, thus also the hooks of GCs that the allocations of prepare
// start), the number of hooks, and the p99 wait to stop the world.
func gcWorkload(b *testing.B, prepare func()) {
	b.Helper()
	stw0 := stwCounts()
	n0, _ := heapbitstest.SweepDurations()
	var hookNs uint64
	var setNs time.Duration
	b.ResetTimer()
	for b.Loop() {
		b.StopTimer()
		before, _ := heapbitstest.SweepDurations()
		start := time.Now()
		prepare()
		setNs += time.Since(start)
		b.StartTimer()
		runtime.GC()
		b.StopTimer()
		after, ring := heapbitstest.SweepDurations()
		if after-before > uint64(len(ring)) {
			b.Fatalf("%d sweep hooks in one operation: more than the ring (%d)", after-before, len(ring))
		}
		for i := before; i < after; i++ {
			hookNs += ring[i%uint64(len(ring))]
		}
		b.StartTimer()
	}
	b.StopTimer()
	n1, _ := heapbitstest.SweepDurations()
	b.ReportMetric(float64(setNs.Nanoseconds())/float64(b.N), "set-ns/op")
	b.ReportMetric(float64(hookNs)/float64(b.N), "hook-ns/op")
	b.ReportMetric(float64(n1-n0)/float64(b.N), "hooks/op")
	b.ReportMetric(p99Wait(stw0, stwCounts())*1e9, "stw-p99-ns")
}

// chunkHeap is the heap size that one chunk of bits covers (128 KiB).
const chunkHeap = 128 << 10

// p99Wait returns the upper bound of the bucket of the 99th percentile of
// the new waits between two histograms.
func p99Wait(before, after *metrics.Float64Histogram) float64 {
	var total uint64
	for i, c := range after.Counts {
		total += c - before.Counts[i]
	}
	if total == 0 {
		return 0
	}
	var seen uint64
	for i, c := range after.Counts {
		seen += c - before.Counts[i]
		if seen*100 >= total*99 {
			return after.Buckets[i+1]
		}
	}
	return 0
}

// BenchmarkSweepWorstCase runs the worst cases of plan section 7.1 for the
// sweep hook: the GC cost with the hook (hook-ns/op: time in the hook) and
// the wait to stop the world. The "clean" variants are the same workloads
// without taint.
func BenchmarkSweepWorstCase(b *testing.B) {
	needBench(b)
	for _, taint := range []bool{true, false} {
		mode := "tainted"
		if !taint {
			mode = "clean"
		}
		set := func(x []byte) {
			if taint {
				heapbits.SetBytes(x)
			}
		}
		b.Run("small-alternating-sparse/"+mode, func(b *testing.B) {
			// Alternating live and dead small objects, 1 in 64 tainted.
			var live [][]byte
			gcWorkload(b, func() {
				live = live[:0]
				for i := range 16384 {
					x := heapBytes(64)
					if i%64 == 0 {
						set(x)
					}
					if i%2 == 0 {
						live = append(live, x)
					}
				}
			})
			runtime.KeepAlive(live)
		})
		// Large objects of 1 MiB and of 64 MiB (the largest taintable
		// span). The runtime chooses their address: the benchmark cannot
		// select objects that start on a chunk boundary or not (tries to
		// move the address with padding objects were not reliable). It
		// reports the fraction of objects that started on a chunk boundary
		// (aligned/op); an object that does not has 2 partial chunks, which
		// the sweep hook clears word by word.
		for _, size := range []int{1 << 20, 64 << 20} {
			name := fmt.Sprintf("large-%dMiB", size>>20)
			large := func(b *testing.B, use func(x []byte)) {
				aligned := 0
				gcWorkload(b, func() {
					x := heapBytes(size)
					if uintptr(unsafe.Pointer(unsafe.SliceData(x)))%chunkHeap == 0 {
						aligned++
					}
					use(x)
				})
				b.ReportMetric(float64(aligned)/float64(b.N), "aligned/op")
			}
			b.Run(name+"-late-byte/"+mode, func(b *testing.B) {
				large(b, func(x []byte) { set(x[len(x)-1:]) })
			})
			b.Run(name+"-full/"+mode, func(b *testing.B) {
				large(b, set)
			})
			b.Run(name+"-taint-then-clear/"+mode, func(b *testing.B) {
				large(b, func(x []byte) {
					set(x)
					heapbits.ClearBytes(x)
				})
			})
		}
		b.Run("parallel-set-and-sweep/"+mode, func(b *testing.B) {
			// All Ps allocate and taint 64 KiB objects that die at once:
			// the Sets get chunks while the sweepers (background sweeper and
			// allocations) give chunks back.
			gcWorkload(b, func() {
				var wg sync.WaitGroup
				for range runtime.GOMAXPROCS(0) {
					wg.Go(func() {
						for range 64 {
							set(heapBytes(64 << 10))
						}
					})
				}
				wg.Wait()
			})
		})
		b.Run("taint-then-clear-live/"+mode, func(b *testing.B) {
			objs := make([]*ptrObj, 65536)
			for i := range objs {
				objs[i] = newPtrObj()
				if taint && i%512 == 0 {
					x := unsafe.Slice((*byte)(unsafe.Pointer(objs[i])), 8)
					heapbits.SetBytes(x)
					heapbits.ClearBytes(x)
				}
			}
			gcWorkload(b, func() {})
			runtime.KeepAlive(objs)
		})
		b.Run("finalizers/"+mode, func(b *testing.B) {
			gcWorkload(b, func() {
				for range 1024 {
					x := &box{}
					set(x.data[:])
					runtime.SetFinalizer(x, func(*box) {})
				}
			})
		})
	}
}

// BenchmarkAllocationLatency measures the latency of allocations while the
// sweep of tainted spans happens during allocation (the allocator sweeps
// spans before it uses them): p50 and p99 of 1000 allocations, the GC count,
// the sweep hooks during the timed allocations, and the memory that the
// runtime holds (runtime-rss-bytes: mapped and not released, which includes
// the taint storage), with a memory limit.
func BenchmarkAllocationLatency(b *testing.B) {
	needBench(b)
	for _, taint := range []bool{true, false} {
		mode := "tainted"
		if !taint {
			mode = "clean"
		}
		b.Run(mode, func(b *testing.B) {
			defer debug.SetMemoryLimit(debug.SetMemoryLimit(256 << 20))
			var ms0, ms1 runtime.MemStats
			runtime.ReadMemStats(&ms0)
			lat := make([]time.Duration, 0, 1000)
			var p50, p99 []time.Duration
			var mu sync.Mutex
			h0, _ := heapbitstest.SweepDurations()
			var inAlloc uint64
			for b.Loop() {
				lat = lat[:0]
				for i := range 1000 {
					h, _ := heapbitstest.SweepDurations()
					start := time.Now()
					x := heapBytes(4096)
					lat = append(lat, time.Since(start))
					h2, _ := heapbitstest.SweepDurations()
					inAlloc += h2 - h
					if taint && i%4 == 0 {
						heapbits.SetBytes(x)
					}
				}
				slices.Sort(lat)
				mu.Lock()
				p50, p99 = append(p50, lat[500]), append(p99, lat[990])
				mu.Unlock()
			}
			runtime.ReadMemStats(&ms1)
			slices.Sort(p50)
			slices.Sort(p99)
			b.ReportMetric(float64(p50[len(p50)/2]), "alloc-p50-ns")
			b.ReportMetric(float64(p99[len(p99)/2]), "alloc-p99-ns")
			b.ReportMetric(float64(ms1.NumGC-ms0.NumGC)/float64(b.N), "gc/op")
			h1, _ := heapbitstest.SweepDurations()
			b.ReportMetric(float64(heapbitstest.Stats().Mapped), "taint-mapped-bytes")
			// The sweep hooks in the timed allocations (allocation-driven
			// sweep; also hooks of other threads in the same time), and all
			// the hooks.
			b.ReportMetric(float64(inAlloc)/float64(b.N), "alloc-hooks/op")
			b.ReportMetric(float64(h1-h0)/float64(b.N), "hooks/op")
			b.ReportMetric(float64(runtimeRSS()), "runtime-rss-bytes")
		})
	}
}

// runtimeRSS returns the memory that the Go runtime has mapped and not
// released to the OS (an upper bound of its part of the RSS).
func runtimeRSS() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

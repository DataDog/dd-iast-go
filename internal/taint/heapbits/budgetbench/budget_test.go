// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package budgetbench_test has the benchmarks of package heapbits for a
// storage budget that is fully used (plan section 7.1). They are in their own package (their own test
// binary) because they need a small budget, which must be set before the
// first Set of the process.
package budgetbench_test

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

// budget is small, so that the benchmarks fill it quickly: 4 slabs of 1 MiB.
const budget = 4 << 20

// chunkHeap is the heap size that one chunk of bits covers (128 KiB).
const chunkHeap = 128 << 10

func TestMain(m *testing.M) {
	if heapbits.Enabled() && !heapbits.SetBudget(budget) {
		println("budgetbench: cannot set the budget")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

//go:noinline
func heapBytes(n int) []byte { return make([]byte, n) }

func needBench(b *testing.B) {
	b.Helper()
	if !heapbits.Enabled() {
		b.Skip("feature is not enabled (build with Orchestrion)")
	}
}

// filled holds the objects that use the budget.
var (
	fillOnce, releaseOnce sync.Once
	filled                [][]byte
)

// fill uses all the budget: it taints one byte in each chunk of 4 MiB
// objects (32 chunks each; not written, thus mostly not resident) until a
// Set fails, and
// keeps the objects. After the release of recycle-and-set, the budget is
// not full again.
func fill(b *testing.B) {
	b.Helper()
	fillOnce.Do(func() {
		for range 256 {
			x := heapBytes(4 << 20)
			filled = append(filled, x)
			for off := 0; off < len(x); off += chunkHeap {
				if !heapbits.SetBytes(x[off : off+1]) {
					return
				}
			}
		}
	})
}

// BenchmarkBudgetFull measures Set when the budget is fully used.
func BenchmarkBudgetFull(b *testing.B) {
	needBench(b)
	b.Run("set-drop/parallel", func(b *testing.B) {
		// Set needs a new chunk and drops (the refill fails).
		fill(b)
		if probe := heapBytes(256 << 10); heapbits.SetBytes(probe[chunkHeap : chunkHeap+1]) {
			b.Fatal("the budget is not full")
		}
		b.RunParallel(func(pb *testing.PB) {
			x := heapBytes(256 << 10)
			for pb.Next() {
				heapbits.SetBytes(x[chunkHeap : chunkHeap+1])
			}
		})
	})
	b.Run("recycle-and-set/parallel", func(b *testing.B) {
		// Quota saturation with recovery: half of the budget becomes free
		// again (its objects die); then all Ps taint 1 MiB objects (8
		// chunks each) that die at once, while the sweepers give the
		// chunks back. ok/op is the fraction of Sets that kept the taint.
		fill(b)
		if len(filled) < 4 {
			b.Fatalf("the budget holds only %d objects", len(filled))
		}
		releaseOnce.Do(func() {
			half := len(filled) / 2
			clear(filled[half:])
			filled = filled[:half]
			runtime.GC()
			runtime.GC()
		})
		var ok, total atomic.Int64
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				x := heapBytes(1 << 20)
				for off := 0; off < len(x); off += chunkHeap {
					if heapbits.SetBytes(x[off : off+1]) {
						ok.Add(1)
					}
					total.Add(1)
				}
			}
		})
		b.ReportMetric(float64(ok.Load())/float64(total.Load()), "ok/op")
	})
}

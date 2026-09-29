// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package microbench_test has the micro benchmarks of package heapbits
// (plan section 7.1). They are in their own package, which does not link
// heapbitstest: with the test knobs active, every entry point writes a
// global test probe, which would distort the measures (a store on one
// shared cache line for each call). The worst-case sweep benchmarks, which
// need the knobs, are in package heapbits.
package microbench_test

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

//go:noinline
func heapString(n int) string { return strings.Repeat("x", n) }

//go:noinline
func heapBytes(n int) []byte { return make([]byte, n) }

func ptr(b []byte) unsafe.Pointer { return unsafe.Pointer(unsafe.SliceData(b)) }

func needBench(b *testing.B) {
	b.Helper()
	if !heapbits.Enabled() {
		b.Skip("feature is not enabled (build with Orchestrion)")
	}
}

var sinkBool bool

// BenchmarkAny measures the quick check.
func BenchmarkAny(b *testing.B) {
	needBench(b)
	for _, size := range []int{16, 256, 4096} {
		clean := heapString(size)
		cases := map[string]string{"clean": clean}
		last, middle := heapString(size), heapString(size)
		heapbits.SetString(last[size-1:])
		heapbits.SetString(middle[size/2 : size/2+1])
		cases["tainted-last"] = last
		cases["tainted-middle"] = middle
		cases["substring-of-tainted"] = middle[size/4 : size/2+1]
		for _, name := range []string{"clean", "tainted-last", "tainted-middle", "substring-of-tainted"} {
			s := cases[name]
			b.Run(fmt.Sprintf("%s/%d", name, size), func(b *testing.B) {
				for b.Loop() {
					sinkBool = heapbits.AnyString(s)
				}
			})
		}
		b.Run(fmt.Sprintf("clean/%d/parallel", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				own := heapString(size)
				heapbits.SetString(own[:1]) // storage exists
				heapbits.ClearString(own[:1])
				for pb.Next() {
					heapbits.AnyString(own)
				}
			})
		})
		b.Run(fmt.Sprintf("clean/%d/parallel-same-value", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					heapbits.AnyString(clean)
				}
			})
		})
	}
	b.Run("stack", func(b *testing.B) {
		var local [64]byte
		for b.Loop() {
			sinkBool = heapbits.AnyBytes(local[:])
		}
	})
	b.Run("literal", func(b *testing.B) {
		for b.Loop() {
			sinkBool = heapbits.AnyString("a string literal in read-only data")
		}
	})
}

// BenchmarkMapBaseline models the exact-key index of an external store
// (internal/taint/store of the taint-tracking branch: 256 shards of 128
// slots, TryRLock, linear probe), for comparison with BenchmarkAny. It
// cannot answer for a sub-string.
func BenchmarkMapBaseline(b *testing.B) {
	var m mapStore
	m.add(0x1000, 16)
	for _, size := range []int{16, 256, 4096} {
		s := heapString(size)
		b.Run(fmt.Sprintf("miss/%d", size), func(b *testing.B) {
			for b.Loop() {
				sinkBool = m.mayContainString(s)
			}
		})
		b.Run(fmt.Sprintf("miss/%d/parallel-same-value", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					m.mayContainString(s)
				}
			})
		})
	}
}

// BenchmarkSet measures the cost of tainting (the storage exists).
func BenchmarkSet(b *testing.B) {
	needBench(b)
	for _, size := range []int{16, 256, 4096} {
		x := heapBytes(size)
		heapbits.SetBytes(x)
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			for b.Loop() {
				heapbits.SetBytes(x)
			}
		})
	}
}

// BenchmarkNext measures the ranges loop of a value with 4 tainted ranges.
func BenchmarkNext(b *testing.B) {
	needBench(b)
	for _, size := range []int{256, 4096} {
		x := heapBytes(size)
		for i := range 4 {
			off := i * size / 4
			heapbits.SetBytes(x[off : off+size/8])
		}
		p, n := ptr(x), uintptr(size)
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			for b.Loop() {
				for off := heapbits.Next(p, n, 0); off < n; {
					off = heapbits.Next(p, n, heapbits.NextClean(p, n, off))
				}
			}
		})
	}
}

// BenchmarkCopy measures Copy from a tainted source (aligned and shifted by
// 3 bytes) and from a clean source (a clear).
func BenchmarkCopy(b *testing.B) {
	needBench(b)
	for _, size := range []int{16, 256, 4096} {
		src, clean, dst := heapBytes(size+8), heapBytes(size+8), heapBytes(size+8)
		heapbits.SetBytes(src)
		heapbits.SetBytes(dst)
		for name, s := range map[string]unsafe.Pointer{"tainted": ptr(src), "tainted-shifted": ptr(src[3:]), "clean": ptr(clean)} {
			b.Run(fmt.Sprintf("%s/%d", name, size), func(b *testing.B) {
				for b.Loop() {
					heapbits.Copy(ptr(dst), s, uintptr(size))
				}
			})
		}
	}
}

// BenchmarkSetFreshChunk measures a Set that needs new storage: the first
// writer of a chunk (with contention between goroutines, and with a full
// budget, where Set drops).
func BenchmarkSetFreshChunk(b *testing.B) {
	needBench(b)
	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				r := heapBytes(256 << 10) // at least one whole new chunk
				heapbits.SetBytes(r[128<<10 : 128<<10+1])
			}
		})
	})
}

// BenchmarkFirstChunkContention measures Set when all Ps taint bytes of the
// same new chunk: one of them gets the chunk, the others drop (a Set never
// waits). Every 64 Sets, a goroutine makes a new object the current one.
func BenchmarkFirstChunkContention(b *testing.B) {
	needBench(b)
	var cur atomic.Pointer[[]byte]
	x := heapBytes(256 << 10)
	cur.Store(&x)
	var ok, total atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			p := *cur.Load()
			if heapbits.SetBytes(p[128<<10+i%4096 : 128<<10+i%4096+1]) {
				ok.Add(1)
			}
			total.Add(1)
			if i++; i%64 == 0 {
				n := heapBytes(256 << 10)
				cur.Store(&n)
			}
		}
	})
	b.ReportMetric(float64(ok.Load())/float64(total.Load()), "ok/op")
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

// The HeapBits workloads measure the allocator-backed taint bits (plan
// _docs/plans/allocator-taint-bits.md, section 7.2). They do the same work in
// the three variants of the runner:
//
//   - control: dd-trace-go only (the taint bits do nothing);
//   - iast: dd-iast-go woven, but no taint (the runtime hooks are woven
//     and inert);
//   - active: the iast binary with DD_IAST_BENCH_HEAPBITS=active: the
//     workloads taint 1 object in 4 (until the taint package uses the bits,
//     this benchmark-only helper is the only source of taint).
var heapbitsActive = os.Getenv("DD_IAST_BENCH_HEAPBITS") == "active"

func taintBench(b []byte) {
	if heapbitsActive {
		heapbits.SetBytes(b)
	}
}

var heapbitsRing [4096][]byte

// BenchmarkHeapBitsAllocChurn allocates objects that die soon (a ring of
// 4096): the allocation and GC cost, with the sweep hook in the active
// variant.
func BenchmarkHeapBitsAllocChurn(b *testing.B) {
	for _, size := range []int{16, 64, 512, 4096} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				x := make([]byte, size)
				if i%4 == 0 {
					taintBench(x)
				}
				heapbitsRing[i%len(heapbitsRing)] = x
			}
		})
	}
}

type heapbitsNode struct {
	data [48]byte
	next *heapbitsNode
}

var heapbitsLive []*heapbitsNode

// BenchmarkHeapBitsGC runs one full GC of a heap with 1 Mi live 64-byte
// objects and 256 KiB of garbage for each operation; in the active variant,
// 1 object in 4 is tainted. It also reports the 99th percentile of the wait
// to stop the world (stw-p99-ns).
func BenchmarkHeapBitsGC(b *testing.B) {
	heapbitsLive = make([]*heapbitsNode, 1<<20)
	for i := range heapbitsLive {
		heapbitsLive[i] = &heapbitsNode{}
		if i%4 == 0 {
			taintBench(heapbitsLive[i].data[:])
		}
	}
	runtime.GC()
	before := stopTheWorldWaits()
	b.ResetTimer()
	for b.Loop() {
		for j := range 4096 {
			n := &heapbitsNode{}
			if j%4 == 0 {
				taintBench(n.data[:])
			}
			heapbitsRing[j] = n.data[:]
		}
		runtime.GC()
	}
	b.StopTimer()
	b.ReportMetric(p99Wait(before, stopTheWorldWaits())*1e9, "stw-p99-ns")
	heapbitsLive = nil
}

func stopTheWorldWaits() *metrics.Float64Histogram {
	s := []metrics.Sample{{Name: "/sched/pauses/stopping/gc:seconds"}}
	metrics.Read(s)
	return s[0].Value.Float64Histogram()
}

// p99Wait returns the upper bound of the bucket of the 99th percentile of
// the waits to stop the world between two histograms (the resolution of the
// runtime histogram).
func p99Wait(before, after *metrics.Float64Histogram) float64 {
	var total uint64
	for i, c := range after.Counts {
		total += c - before.Counts[i]
	}
	var seen uint64
	for i, c := range after.Counts {
		seen += c - before.Counts[i]
		if total > 0 && seen*100 >= total*99 {
			return after.Buckets[i+1]
		}
	}
	return 0
}

type heapbitsPayload struct {
	Name    string            `json:"name"`
	Email   string            `json:"email"`
	Tags    []string          `json:"tags"`
	Attrs   map[string]string `json:"attrs"`
	Comment string            `json:"comment"`
}

// BenchmarkHeapBitsJSON is allocation-heavy application work; in the active
// variant, the input is tainted.
func BenchmarkHeapBitsJSON(b *testing.B) {
	in, err := json.Marshal(heapbitsPayload{
		Name: "John Doe", Email: "john@example.com",
		Tags:    []string{"a", "b", "c", "d"},
		Attrs:   map[string]string{"k1": "v1", "k2": "v2", "k3": strings.Repeat("v", 100)},
		Comment: strings.Repeat("lorem ipsum ", 20),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		buf := append([]byte(nil), in...)
		taintBench(buf)
		var p heapbitsPayload
		if err := json.Unmarshal(buf, &p); err != nil {
			b.Fatal(err)
		}
		out, err := json.Marshal(&p)
		if err != nil {
			b.Fatal(err)
		}
		heapbitsRing[0] = out
	}
}

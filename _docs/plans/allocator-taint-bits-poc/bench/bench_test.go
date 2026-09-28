package bench

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"example.com/allocbits/heapbits"
)

// active is true when the workloads must taint data (mode "active").
var active = os.Getenv("ALLOCBITS_MODE") == "active"

func TestMode(t *testing.T) {
	t.Logf("woven=%v active=%v", heapbits.Available(), active)
}

var ring [4096][]byte

// BenchmarkAllocChurn: allocation + GC cost. Active: 1 in 4 objects tainted.
func BenchmarkAllocChurn(b *testing.B) {
	for _, size := range []int{16, 64, 512, 4096} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				x := make([]byte, size)
				if active && i%4 == 0 {
					heapbits.TaintBytes(x)
				}
				ring[i%len(ring)] = x
			}
		})
	}
}

type node struct {
	data [48]byte
	next *node
}

var live []*node

// BenchmarkGC: one full GC of a heap with 1M live 64-byte objects, plus
// 256 KiB of garbage. Active: 1 in 4 objects tainted (live and garbage).
func BenchmarkGC(b *testing.B) {
	live = make([]*node, 1<<20)
	for i := range live {
		live[i] = &node{}
		if active && i%4 == 0 {
			heapbits.TaintBytes(live[i].data[:])
		}
	}
	runtime.GC()
	b.ResetTimer()
	for b.Loop() {
		for j := 0; j < 4096; j++ {
			n := &node{}
			if active && j%4 == 0 {
				heapbits.TaintBytes(n.data[:])
			}
			ring[j] = n.data[:]
		}
		runtime.GC()
	}
	b.StopTimer()
	live = nil
}

type payload struct {
	Name    string            `json:"name"`
	Email   string            `json:"email"`
	Tags    []string          `json:"tags"`
	Attrs   map[string]string `json:"attrs"`
	Comment string            `json:"comment"`
}

// BenchmarkJSON: realistic allocation-heavy work. Active: input is tainted.
func BenchmarkJSON(b *testing.B) {
	in, _ := json.Marshal(payload{
		Name: "John Doe", Email: "john@example.com",
		Tags:    []string{"a", "b", "c", "d"},
		Attrs:   map[string]string{"k1": "v1", "k2": "v2", "k3": strings.Repeat("v", 100)},
		Comment: strings.Repeat("lorem ipsum ", 20),
	})
	b.ReportAllocs()
	for b.Loop() {
		buf := append([]byte(nil), in...)
		if active {
			heapbits.TaintBytes(buf)
		}
		var p payload
		if err := json.Unmarshal(buf, &p); err != nil {
			b.Fatal(err)
		}
		out, _ := json.Marshal(&p)
		ring[0] = out
	}
}

//go:noinline
func heapString(n int) string { return strings.Repeat("x", n) }

// BenchmarkCheck: the quick "has any taint" check (woven builds only).
func BenchmarkCheck(b *testing.B) {
	if !heapbits.Available() {
		b.Skip("not woven")
	}
	for _, size := range []int{16, 256, 4096} {
		clean, tainted := heapString(size), heapString(size)
		heapbits.TaintString(tainted[size-1:]) // last byte only (the check reads the last word early)
		var m mapStore
		m.add(0x1000, 16) // non-empty store
		b.Run(fmt.Sprintf("bits/clean/%d", size), func(b *testing.B) {
			for b.Loop() {
				if heapbits.IsTainted(clean) {
					b.Fatal("bad")
				}
			}
		})
		b.Run(fmt.Sprintf("bits/tainted-last-byte/%d", size), func(b *testing.B) {
			for b.Loop() {
				if !heapbits.IsTainted(tainted) {
					b.Fatal("bad")
				}
			}
		})
		b.Run(fmt.Sprintf("bits/substring/%d", size), func(b *testing.B) {
			sub := tainted[size/2:]
			for b.Loop() {
				if !heapbits.IsTainted(sub) {
					b.Fatal("bad")
				}
			}
		})
		b.Run(fmt.Sprintf("map/miss/%d", size), func(b *testing.B) {
			for b.Loop() {
				if m.mayContainString(clean) {
					b.Fatal("bad")
				}
			}
		})
		b.Run(fmt.Sprintf("bits/clean/parallel/%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					heapbits.IsTainted(clean)
				}
			})
		})
		b.Run(fmt.Sprintf("bits/distinct/parallel/%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				own := heapString(size)
				for pb.Next() {
					heapbits.IsTainted(own)
				}
			})
		})
		b.Run(fmt.Sprintf("map/distinct/parallel/%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				own := heapString(size)
				for pb.Next() {
					m.mayContainString(own)
				}
			})
		})
		b.Run(fmt.Sprintf("map/miss/parallel/%d", size), func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					m.mayContainString(clean)
				}
			})
		})
	}
	b.Run("bits/stack", func(b *testing.B) {
		var local [64]byte
		for b.Loop() {
			heapbits.IsTaintedBytes(local[:])
		}
	})
	b.Run("bits/rodata", func(b *testing.B) {
		for b.Loop() {
			heapbits.IsTainted("a string literal in rodata")
		}
	})
}

// BenchmarkSet: cost of tainting (woven builds only).
func BenchmarkSet(b *testing.B) {
	if !heapbits.Available() {
		b.Skip("not woven")
	}
	for _, size := range []int{16, 256, 4096} {
		x := make([]byte, size)
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			for b.Loop() {
				heapbits.TaintBytes(x)
			}
		})
	}
}

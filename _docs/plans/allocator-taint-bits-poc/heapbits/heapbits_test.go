package heapbits_test

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"example.com/allocbits/heapbits"
)

func need(t *testing.T) {
	t.Helper()
	if !heapbits.Available() {
		t.Skip("runtime not woven")
	}
}

//go:noinline
func heapBytes(n int) []byte { return make([]byte, n) }

func TestByteGranularity(t *testing.T) {
	need(t)
	b := heapBytes(256)
	for off := 0; off < 24; off++ {
		for n := 1; n < 24; n++ {
			heapbits.ClearBytes(b)
			if !heapbits.TaintBytes(b[64+off : 64+off+n]) {
				t.Fatalf("set refused off=%d n=%d", off, n)
			}
			for i := 0; i < 160; i++ {
				want := i >= 64+off && i < 64+off+n
				if got := heapbits.IsTaintedBytes(b[i : i+1]); got != want {
					t.Fatalf("off=%d n=%d byte %d: got %v want %v", off, n, i, got, want)
				}
			}
			// Ranges that touch only the edges.
			if !heapbits.IsTaintedBytes(b[0 : 64+off+1]) {
				t.Fatalf("left overlap missed off=%d n=%d", off, n)
			}
			if heapbits.IsTaintedBytes(b[0 : 64+off]) {
				t.Fatalf("left neighbour off=%d n=%d", off, n)
			}
			if heapbits.IsTaintedBytes(b[64+off+n:]) {
				t.Fatalf("right neighbour off=%d n=%d", off, n)
			}
		}
	}
	heapbits.ClearBytes(b)
	if heapbits.IsTaintedBytes(b) {
		t.Fatal("clear failed")
	}
}

var global = [64]byte{1}

func TestRefusesNonHeap(t *testing.T) {
	need(t)
	var local [64]byte
	if heapbits.TaintBytes(local[:]) {
		t.Error("stack memory was accepted")
	}
	if heapbits.TaintBytes(global[:]) {
		t.Error("global memory was accepted")
	}
	if heapbits.TaintString("a literal string") {
		t.Error("rodata was accepted")
	}
	if heapbits.IsTaintedBytes(local[:]) || heapbits.IsTaintedBytes(global[:]) {
		t.Error("non-heap reported as tainted")
	}
}

func TestLiveObjectKeepsTaint(t *testing.T) {
	need(t)
	s := strings.Repeat("x", 100)
	heapbits.TaintString(s)
	for range 3 {
		runtime.GC()
	}
	if !heapbits.IsTainted(s) {
		t.Fatal("live object lost taint after GC")
	}
	runtime.KeepAlive(s)
}

// reuse taints many objects, drops them, runs the GC, and allocates new
// objects of the same size. It returns how many new objects are tainted.
func reuse(size, count int) int {
	keep := make([][]byte, count)
	for i := range keep {
		keep[i] = heapBytes(size)
		heapbits.TaintBytes(keep[i])
	}
	keep = nil
	runtime.GC()
	runtime.GC()
	bad := 0
	fresh := make([][]byte, count)
	for i := range fresh {
		fresh[i] = heapBytes(size)
		if heapbits.IsTaintedBytes(fresh[i]) {
			bad++
		}
	}
	runtime.KeepAlive(fresh)
	return bad
}

var sizes = []int{8, 16, 24, 48, 64, 500, 4096, 30000, 40000, 1 << 20}

func TestNoTaintAfterReuse(t *testing.T) {
	need(t)
	for _, size := range sizes {
		if bad := reuse(size, 2000); bad != 0 {
			t.Errorf("size %d: %d new objects inherited taint", size, bad)
		}
	}
}

// Negative control: without the sweep hook, the reuse test must fail. It
// runs in a child process: the stale bits it makes must not reach other tests.
func TestNoTaintAfterReuseNegativeControl(t *testing.T) {
	need(t)
	if os.Getenv("HEAPBITS_NEGATIVE_CONTROL") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestNoTaintAfterReuseNegativeControl$", "-test.v")
		cmd.Env = append(os.Environ(), "HEAPBITS_NEGATIVE_CONTROL=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		t.Logf("child:\n%s", out)
		return
	}
	heapbits.SetNoSweepForTest(true)
	total := 0
	for _, size := range sizes[:6] {
		total += reuse(size, 2000)
	}
	if total == 0 {
		t.Fatal("negative control: expected inherited taint without the sweep hook")
	}
	t.Logf("negative control: %d inherited taints without the sweep hook", total)
}

func TestTinyAllocatorNeighbours(t *testing.T) {
	need(t)
	// Small pointer-free objects share 16-byte blocks.
	objs := make([]*[3]byte, 1000)
	for i := range objs {
		objs[i] = new([3]byte)
	}
	for i := 0; i < len(objs); i += 2 {
		heapbits.TaintBytes(objs[i][:])
	}
	for i := range objs {
		want := i%2 == 0
		if got := heapbits.IsTaintedBytes(objs[i][:]); got != want {
			t.Fatalf("obj %d at %p: got %v want %v", i, objs[i], got, want)
		}
	}
}

func TestCrossArena(t *testing.T) {
	need(t)
	const arena = 64 << 20
	b := heapBytes(3 * arena)
	base := uintptr(unsafe.Pointer(&b[0]))
	// First arena boundary inside b.
	cut := int((base+arena)&^(arena-1) - base)
	heapbits.TaintBytes(b[cut-3 : cut+5])
	for i := cut - 8; i < cut+8; i++ {
		want := i >= cut-3 && i < cut+5
		if got := heapbits.IsTaintedBytes(b[i : i+1]); got != want {
			t.Fatalf("byte %d (cut %+d): got %v want %v", i, i-cut, got, want)
		}
	}
	if !heapbits.IsTaintedBytes(b) {
		t.Fatal("whole range missed")
	}
	heapbits.ClearBytes(b)
	if heapbits.IsTaintedBytes(b) {
		t.Fatal("clear failed")
	}
	bm, _ := heapbits.Stats()
	t.Logf("bitmaps allocated: %d", bm)
}

func TestConcurrentNeighbours(t *testing.T) {
	need(t)
	b := heapBytes(4096)
	var wg sync.WaitGroup
	const workers = 8
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				// Each worker owns byte offsets w, w+8, w+16, ...: all share bitmap bytes.
				j := (i%512)*8 + w
				heapbits.TaintBytes(b[j : j+1])
				if !heapbits.IsTaintedBytes(b[j : j+1]) {
					t.Errorf("lost update at %d", j)
					return
				}
				heapbits.ClearBytes(b[j : j+1])
				if heapbits.IsTaintedBytes(b[j : j+1]) {
					t.Errorf("lost clear at %d", j)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	runtime.KeepAlive(b)
}

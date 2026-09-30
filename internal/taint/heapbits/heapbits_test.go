// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
	"github.com/DataDog/orchestrion/runtime/built"
)

// supported reports whether the feature must be enabled in a woven build.
// It must stay in sync with the gate of the injected init function
// (orchestrion.yml, aspect "taint os alloc").
func supported() bool {
	return !sanitizer &&
		(runtime.GOOS == "linux" || runtime.GOOS == "darwin") &&
		(runtime.GOARCH == "amd64" || (runtime.GOARCH == "arm64" && arm64Atomics()))
}

// arm64Atomics reports whether the runtime sees the LSE atomics (the feature
// is off without them): not turned off by GODEBUG, and present in the CPU.
// All Apple arm64 CPUs have them; on Linux, the kernel lists them as
// "atomics" in /proc/cpuinfo.
func arm64Atomics() bool {
	// GODEBUG can turn CPU features off (the runtime then has no LSE).
	for opt := range strings.SplitSeq(os.Getenv("GODEBUG"), ",") {
		if opt == "cpu.atomics=off" || opt == "cpu.all=off" {
			return false
		}
	}
	if runtime.GOOS != "linux" {
		return true
	}
	info, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	for line := range strings.SplitSeq(string(info), "\n") {
		if strings.HasPrefix(line, "Features") && slices.Contains(strings.Fields(line), "atomics") {
			return true
		}
	}
	return false
}

// need skips the test without Orchestrion. In a woven build on a supported
// platform, it fails when the feature is off: an aspect that stops to match
// must not give a test run where all tests are skipped.
func need(t *testing.T) {
	t.Helper()
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if !heapbits.Enabled() {
		if supported() {
			t.Fatal("woven build on a supported platform, but heapbits is not enabled")
		}
		t.Skip("platform not supported")
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
			if !heapbits.SetBytes(b[64+off : 64+off+n]) {
				t.Fatalf("set refused off=%d n=%d", off, n)
			}
			for i := 0; i < 160; i++ {
				want := i >= 64+off && i < 64+off+n
				if got := heapbits.AnyBytes(b[i : i+1]); got != want {
					t.Fatalf("off=%d n=%d byte %d: got %v want %v", off, n, i, got, want)
				}
			}
			// Ranges that touch only the edges.
			if !heapbits.AnyBytes(b[0 : 64+off+1]) {
				t.Fatalf("left overlap missed off=%d n=%d", off, n)
			}
			if heapbits.AnyBytes(b[0 : 64+off]) {
				t.Fatalf("left neighbour off=%d n=%d", off, n)
			}
			if heapbits.AnyBytes(b[64+off+n:]) {
				t.Fatalf("right neighbour off=%d n=%d", off, n)
			}
		}
	}
	heapbits.ClearBytes(b)
	if heapbits.AnyBytes(b) {
		t.Fatal("clear failed")
	}
}

var global = [64]byte{1}

func TestRefusesNonHeap(t *testing.T) {
	need(t)
	var local [64]byte
	if heapbits.SetBytes(local[:]) {
		t.Error("stack memory was accepted")
	}
	if heapbits.SetBytes(global[:]) {
		t.Error("global memory was accepted")
	}
	if heapbits.SetString("a literal string") {
		t.Error("rodata was accepted")
	}
	if heapbits.AnyBytes(local[:]) || heapbits.AnyBytes(global[:]) {
		t.Error("non-heap reported as tainted")
	}
}

func TestLiveObjectKeepsTaint(t *testing.T) {
	need(t)
	s := strings.Repeat("x", 100)
	heapbits.SetString(s)
	for range 3 {
		runtime.GC()
	}
	if !heapbits.AnyString(s) {
		t.Fatal("live object lost taint after GC")
	}
	runtime.KeepAlive(s)
}

// reuse taints many objects, drops half of them (runs of 64 objects, so that
// spans stay in use and whole tiny blocks die), runs the GC,
// and allocates new objects of the same size. It returns how many new objects
// use the address of a dropped object, and how many new objects are tainted.
func reuse(size, count int) (reused, bad int) {
	dropped := make(map[uintptr]struct{}, count)
	objs := make([][]byte, 2*count)
	for i := range objs {
		objs[i] = heapBytes(size)
		if !heapbits.SetBytes(objs[i]) {
			panic("Set failed: storage budget used?")
		}
		if (i/64)%2 == 0 {
			dropped[uintptr(unsafe.Pointer(unsafe.SliceData(objs[i])))] = struct{}{}
		}
	}
	for i := range objs {
		if (i/64)%2 == 0 {
			objs[i] = nil
		}
	}
	runtime.GC()
	runtime.GC()
	fresh := make([][]byte, count)
	for i := range fresh {
		fresh[i] = heapBytes(size)
		if _, ok := dropped[uintptr(unsafe.Pointer(unsafe.SliceData(fresh[i])))]; ok {
			reused++
		}
		if heapbits.AnyBytes(fresh[i]) {
			bad++
		}
	}
	runtime.KeepAlive(objs)
	runtime.KeepAlive(fresh)
	return reused, bad
}

var sizes = []int{8, 16, 24, 48, 64, 500, 4096, 30000, 40000, 1 << 20}

// reuseSome is reuse, tried up to 20 times until at least one address is used
// again: for large objects (own spans), the page allocator does not always
// give the same address back.
func reuseSome(size, count int) (reused, bad int) {
	for range 20 {
		r, b := reuse(size, count)
		reused, bad = reused+r, bad+b
		if reused > 0 {
			break
		}
	}
	return reused, bad
}

func TestNoTaintAfterReuse(t *testing.T) {
	need(t)
	for _, size := range sizes {
		reused, bad := reuseSome(size, 2000)
		if bad != 0 {
			t.Errorf("size %d: %d new objects inherited taint", size, bad)
		}
		// The test proves nothing if no address was used again.
		if reused == 0 {
			t.Errorf("size %d: no address was used again, the test is not valid", size)
		}
		t.Logf("size %d: %d of 2000 addresses used again", size, reused)
	}
}

// Negative control: without the sweep hook, the reuse test must fail. It
// runs in a child process: the stale bits it makes must not reach other tests.
func TestNoTaintAfterReuseNegativeControl(t *testing.T) {
	need(t)
	if os.Getenv("HEAPBITS_NEGATIVE_CONTROL") != "1" {
		cmd := exec.Command(os.Args[0], childArgs("^TestNoTaintAfterReuseNegativeControl$")...)
		cmd.Env = append(os.Environ(), "HEAPBITS_NEGATIVE_CONTROL=1", childEnv+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		t.Logf("child:\n%s", out)
		return
	}
	heapbits.SetBudget(heapbits.MaxBudget)
	heapbitstest.SetNoSweep(true)
	total := 0
	for _, size := range sizes {
		reused, bad := reuseSome(size, 2000)
		// Each size must show the failure that the hook prevents.
		if reused == 0 {
			t.Errorf("size %d: no address was used again, the negative control is not valid", size)
		} else if bad == 0 {
			t.Errorf("size %d: %d addresses used again, but no inherited taint without the sweep hook", size, reused)
		}
		total += bad
	}
	t.Logf("negative control: %d inherited taints without the sweep hook", total)
}

func TestTinyAllocatorNeighbours(t *testing.T) {
	need(t)
	if raceBuild {
		t.Skip("the race detector turns the tiny allocator off")
	}
	// Small pointer-free objects share 16-byte blocks.
	objs := make([]*[3]byte, 1000)
	for i := range objs {
		objs[i] = new([3]byte)
	}
	shared := 0
	for i := 1; i < len(objs); i++ {
		if uintptr(unsafe.Pointer(objs[i]))/16 == uintptr(unsafe.Pointer(objs[i-1]))/16 {
			shared++
		}
	}
	if shared == 0 {
		t.Fatal("no two objects share a 16-byte tiny block: the test is not valid")
	}
	for i := 0; i < len(objs); i += 2 {
		heapbits.SetBytes(objs[i][:])
	}
	for i := range objs {
		want := i%2 == 0
		if got := heapbits.AnyBytes(objs[i][:]); got != want {
			t.Fatalf("obj %d at %p: got %v want %v", i, objs[i], got, want)
		}
	}
}

// crossingKeep holds the objects of crossingObject.
var crossingKeep [][]byte

// crossingObject returns a 48 MiB heap object (a span smaller than the 64 MiB
// taintable limit) that crosses a boundary of the 64 MiB heap arenas with at
// least margin bytes on the two sides, and the offset of that boundary in it.
func crossingObject(t *testing.T, margin int) ([]byte, int) {
	t.Helper()
	const arena = 64 << 20
	for range 16 {
		b := heapBytes(48 << 20)
		crossingKeep = append(crossingKeep, b)
		base := uintptr(unsafe.Pointer(&b[0]))
		next := (base + arena) &^ (arena - 1)
		if off := int(next - base); next > base && off >= margin && len(b)-off >= margin {
			return b, off
		}
	}
	t.Fatal("no object crosses an arena boundary")
	return nil, 0
}

func TestCrossArena(t *testing.T) {
	need(t)
	b, cut := crossingObject(t, 4096)
	heapbits.SetBytes(b[cut-3 : cut+5])
	for i := cut - 8; i < cut+8; i++ {
		want := i >= cut-3 && i < cut+5
		if got := heapbits.AnyBytes(b[i : i+1]); got != want {
			t.Fatalf("byte %d (cut %+d): got %v want %v", i, i-cut, got, want)
		}
	}
	if !heapbits.AnyBytes(b) {
		t.Fatal("whole range missed")
	}
	heapbits.ClearBytes(b)
	if heapbits.AnyBytes(b) {
		t.Fatal("clear failed")
	}
	t.Logf("storage: %+v", heapbitstest.Stats())
}

func TestConcurrentNeighbours(t *testing.T) {
	need(t)
	b := heapBytes(4096)
	// Get the storage first: concurrent first writers of one chunk drop
	// (Set never waits), which is not what this test checks.
	if !heapbits.SetBytes(b) {
		t.Fatal("Set failed")
	}
	heapbits.ClearBytes(b)
	// The baseline is taken after the first write, when the span of b has
	// its flag. The counter is global: an increase proves that a sweep of a
	// tainted span ran while the workers changed bits, not that it was the
	// span of b.
	var sweepsBefore atomic.Uint64
	var firstWrite sync.Once
	written := make(chan struct{})
	sweptDuring := func() bool {
		return heapbitstest.Stats().Sweeps > sweepsBefore.Load()
	}
	var wg, gcDone sync.WaitGroup
	const workers = 8
	start := make(chan struct{})
	stop := make(chan struct{})
	gcDone.Add(1)
	go func() {
		defer gcDone.Done()
		<-written
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
			<-start
			// Run at least 20000 iterations, and continue until a sweep of
			// a tainted span happened while the workers change bits (at
			// most 5 000 000 iterations).
			for i := 0; i < 20000 || !sweptDuring(); i++ {
				if i >= 5_000_000 {
					t.Error("no sweep of a tainted span while the workers ran")
					return
				}
				// Each worker owns byte offsets w, w+8, w+16, ...: the
				// workers share every bitmap word.
				j := (i%512)*8 + w
				if !heapbits.SetBytes(b[j : j+1]) {
					t.Errorf("Set failed at %d", j)
					return
				}
				firstWrite.Do(func() {
					sweepsBefore.Store(heapbitstest.Stats().Sweeps)
					close(written)
				})
				if !heapbits.AnyBytes(b[j : j+1]) {
					t.Errorf("lost update at %d", j)
					return
				}
				heapbits.ClearBytes(b[j : j+1])
				if heapbits.AnyBytes(b[j : j+1]) {
					t.Errorf("lost clear at %d", j)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(stop)
	gcDone.Wait()
	// The live object keeps its taint through the sweeps.
	heapbits.SetBytes(b[:1])
	runtime.GC()
	runtime.GC()
	if !heapbits.AnyBytes(b[:1]) {
		t.Error("live object lost its taint")
	}
	runtime.KeepAlive(b)
}

func TestNotWovenOrDisabledIsInert(t *testing.T) {
	if built.WithOrchestrion && supported() {
		if !heapbits.Enabled() {
			t.Fatal("woven build on a supported platform, but heapbits is not enabled")
		}
		t.Skip("feature is enabled (expected)")
	}
	// Not woven, or a platform that is not supported: the feature must be off.
	if heapbits.Enabled() {
		t.Fatalf("heapbits is enabled (woven=%v, supported=%v)", built.WithOrchestrion, supported())
	}
	b := heapBytes(16)
	if heapbits.SetBytes(b) {
		t.Fatal("Set must fail when the feature is off")
	}
	if heapbits.AnyBytes(b) {
		t.Fatal("Any must report clean when the feature is off")
	}
	heapbits.ClearBytes(b)
	p := unsafe.Pointer(&b[0])
	if got := heapbits.Next(p, 16, 3); got != 16 {
		t.Fatalf("Next = %d, want 16", got)
	}
	if got := heapbits.NextClean(p, 16, 3); got != 3 {
		t.Fatalf("NextClean = %d, want 3", got)
	}
	if heapbits.Next(p, 16, 16) != 16 || heapbits.NextClean(p, 16, 20) != 16 {
		t.Fatal("from >= n must return n")
	}
	if heapbits.Copy(p, unsafe.Pointer(&heapBytes(16)[0]), 16) {
		t.Fatal("Copy must fail when the feature is off")
	}
}

func TestEmpty(t *testing.T) {
	if heapbits.SetBytes(nil) || heapbits.AnyBytes(nil) || heapbits.SetString("") || heapbits.AnyString("") {
		t.Fatal("empty ranges are never tainted")
	}
	heapbits.ClearString("")
}

func TestBoundaries(t *testing.T) {
	need(t)
	b := heapBytes(64)
	p := unsafe.Pointer(unsafe.SliceData(b))

	// Zero length with a valid pointer.
	if heapbits.Set(p, 0) {
		t.Error("Set with n == 0 must fail")
	}
	if heapbits.Any(p, 0) {
		t.Error("Any with n == 0 must report clean")
	}

	// Ranges that wrap the address space.
	if heapbits.Set(p, ^uintptr(0)) {
		t.Error("Set of a wrapping range must fail")
	}
	if heapbits.Any(p, ^uintptr(0)) {
		t.Error("Any of a wrapping range must report clean")
	}
	heapbits.Clear(p, ^uintptr(0))

	// Clear of non-heap memory is ignored.
	var local [64]byte
	heapbits.ClearBytes(local[:])
	heapbits.ClearBytes(global[:])
	heapbits.ClearString("a literal string")
	if heapbits.AnyBytes(b) {
		t.Error("b was never tainted")
	}
	runtime.KeepAlive(b)
}

// A range that starts in one object and ends in the next object of the same
// span must not change the bits of the neighbour.
func TestRefusesRangeAcrossObjects(t *testing.T) {
	need(t)
	objs := make([]*[64]byte, 256)
	for i := range objs {
		objs[i] = new([64]byte)
	}
	for i := 1; i < len(objs); i++ {
		a, n := objs[i-1], objs[i]
		if uintptr(unsafe.Pointer(n)) != uintptr(unsafe.Pointer(a))+64 {
			continue // not neighbours
		}
		heapbits.SetBytes(n[:])
		across := unsafe.Pointer(&a[32])
		if heapbits.Set(across, 64) {
			t.Fatal("Set across two objects must fail")
		}
		heapbits.Clear(across, 64)
		if !heapbits.AnyBytes(n[:1]) {
			t.Fatal("Clear across two objects removed the taint of the neighbour")
		}
		if heapbits.AnyBytes(a[:]) {
			t.Fatal("Set across two objects tainted the first object")
		}
		return
	}
	t.Fatal("no neighbour objects found: the test is not valid")
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"context"
	"math/rand/v2"
	"os"
	"os/exec"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

func ptr(b []byte) unsafe.Pointer { return unsafe.Pointer(unsafe.SliceData(b)) }

// bitsOf returns the taint bit of each byte of b.
func bitsOf(b []byte) []bool {
	r := make([]bool, len(b))
	for i := range b {
		r[i] = heapbits.AnyBytes(b[i : i+1])
	}
	return r
}

// setPattern makes the bits of b equal to pattern.
func setPattern(t *testing.T, b []byte, pattern []bool) {
	t.Helper()
	heapbits.ClearBytes(b)
	for i := 0; i < len(b); {
		if !pattern[i] {
			i++
			continue
		}
		j := i
		for j < len(b) && pattern[j] {
			j++
		}
		if !heapbits.SetBytes(b[i:j]) {
			t.Fatal("Set failed")
		}
		i = j
	}
}

func randomPattern(r *rand.Rand, n int) []bool {
	p := make([]bool, n)
	on := false
	for i := range p {
		if r.IntN(8) == 0 { // runs of about 8 bytes
			on = !on
		}
		p[i] = on
	}
	return p
}

func equalBits(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNext(t *testing.T) {
	need(t)
	r := rand.New(rand.NewPCG(1, 2))
	// 256 KiB: the buffer covers at least 2 chunks.
	buf := heapBytes(256 << 10)
	for range 50 {
		off := r.IntN(len(buf) - 4096)
		n := 1 + r.IntN(4096)
		b := buf[off : off+n]
		pattern := randomPattern(r, n)
		setPattern(t, b, pattern)
		for range 20 {
			from := r.IntN(n + 2)
			wantNext, wantClean := uintptr(n), uintptr(n)
			for i := from; i < n; i++ {
				if pattern[i] && wantNext == uintptr(n) {
					wantNext = uintptr(i)
				}
				if !pattern[i] && wantClean == uintptr(n) {
					wantClean = uintptr(i)
				}
			}
			if got := heapbits.Next(ptr(b), uintptr(n), uintptr(from)); got != wantNext {
				t.Fatalf("off=%d n=%d from=%d: Next = %d, want %d", off, n, from, got, wantNext)
			}
			if got := heapbits.NextClean(ptr(b), uintptr(n), uintptr(from)); got != wantClean {
				t.Fatalf("off=%d n=%d from=%d: NextClean = %d, want %d", off, n, from, got, wantClean)
			}
		}
	}
	heapbits.ClearBytes(buf)
	// The ranges loop of the documentation gives the pattern back.
	b := buf[100:1100]
	pattern := randomPattern(r, len(b))
	setPattern(t, b, pattern)
	got := make([]bool, len(b))
	n := uintptr(len(b))
	for off := heapbits.Next(ptr(b), n, 0); off < n; {
		end := heapbits.NextClean(ptr(b), n, off)
		for i := off; i < end; i++ {
			got[i] = true
		}
		off = heapbits.Next(ptr(b), n, end)
	}
	if !equalBits(got, pattern) {
		t.Fatal("the ranges loop does not give the pattern")
	}
}

func TestNextEdgeCases(t *testing.T) {
	need(t)
	var local [64]byte
	b := heapBytes(64)
	for name, p := range map[string]unsafe.Pointer{
		"stack":              unsafe.Pointer(&local),
		"global":             unsafe.Pointer(&global),
		"heap without taint": ptr(heapBytes(64)),
	} {
		if got := heapbits.Next(p, 64, 3); got != 64 {
			t.Errorf("%s: Next = %d, want 64", name, got)
		}
		if got := heapbits.NextClean(p, 64, 3); got != 3 {
			t.Errorf("%s: NextClean = %d, want 3", name, got)
		}
	}
	heapbits.SetBytes(b)
	if got := heapbits.NextClean(ptr(b), 64, 0); got != 64 {
		t.Errorf("fully tainted: NextClean = %d, want 64", got)
	}
	for _, from := range []uintptr{64, 65, 1000} {
		if heapbits.Next(ptr(b), 64, from) != 64 || heapbits.NextClean(ptr(b), 64, from) != 64 {
			t.Errorf("from %d >= n must return n", from)
		}
	}
	// A wrapping range finds nothing.
	if got := heapbits.Next(ptr(b), ^uintptr(0), 0); got != ^uintptr(0) {
		t.Errorf("wrapping range: Next = %d", got)
	}
	runtime.KeepAlive(local)
}

// copyCase copies n bits from src to dst (both in buf, possibly
// overlapping) and checks the result against a memmove of a model.
func copyCase(t *testing.T, r *rand.Rand, buf []byte, dstOff, srcOff, n int) {
	t.Helper()
	model := randomPattern(r, len(buf))
	setPattern(t, buf, model)
	want := append([]bool(nil), model...)
	copy(want[dstOff:dstOff+n], model[srcOff:srcOff+n]) // memmove semantics
	if !heapbits.Copy(ptr(buf[dstOff:]), ptr(buf[srcOff:]), uintptr(n)) {
		t.Fatalf("Copy(dst=%d, src=%d, n=%d) failed", dstOff, srcOff, n)
	}
	if got := bitsOf(buf); !equalBits(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("Copy(dst=%d, src=%d, n=%d): byte %d: got %v, want %v", dstOff, srcOff, n, i, got[i], want[i])
			}
		}
	}
}

func TestCopy(t *testing.T) {
	need(t)
	r := rand.New(rand.NewPCG(3, 4))
	buf := heapBytes(2048)
	// All alignments of dst and src in a word, and lengths across words.
	for _, dstOff := range []int{0, 1, 7, 63, 64, 65, 130} {
		for _, srcOff := range []int{300, 301, 363, 364, 431} {
			for _, n := range []int{1, 2, 63, 64, 65, 127, 200} {
				copyCase(t, r, buf, dstOff, srcOff, n)
			}
		}
	}
	// Overlap, in the two directions, and dst == src.
	for range 300 {
		n := 1 + r.IntN(500)
		src := r.IntN(len(buf) - n)
		d := r.IntN(130) - 65
		dst := src + d
		if dst < 0 || dst+n > len(buf) {
			continue
		}
		copyCase(t, r, buf, dst, src, n)
	}
	copyCase(t, r, buf, 100, 100, 300)
}

// All 64x64 alignments of dst and src in a word, for a few lengths.
func TestCopyAllAlignments(t *testing.T) {
	need(t)
	r := rand.New(rand.NewPCG(7, 8))
	buf := heapBytes(512)
	for d := range 64 {
		for sOff := range 64 {
			for _, n := range []int{1, 70, 130} {
				copyCase(t, r, buf, d, 256+sOff, n)
			}
		}
	}
}

func TestCopyAcrossChunks(t *testing.T) {
	need(t)
	r := rand.New(rand.NewPCG(5, 6))
	buf := heapBytes(1 << 20) // 8 chunks
	a := int(addr(buf))
	cut := ((a+128<<10-1)&^(128<<10-1) - a) + 128<<10 // a chunk boundary in buf
	src := heapBytes(4096)
	other := heapBytes(4096)
	for _, n := range []int{100, 3000} {
		// Destination across a chunk boundary.
		pattern := randomPattern(r, n)
		setPattern(t, src[:n], pattern)
		dst := buf[cut-n/2 : cut-n/2+n]
		if !heapbits.Copy(ptr(dst), ptr(src), uintptr(n)) {
			t.Fatal("Copy failed")
		}
		if !equalBits(bitsOf(dst), pattern) {
			t.Fatalf("n=%d: copy to a range across a chunk boundary is wrong", n)
		}
		// Source across a chunk boundary.
		pattern = randomPattern(r, n)
		setPattern(t, dst, pattern)
		if !heapbits.Copy(ptr(other), ptr(dst), uintptr(n)) {
			t.Fatal("Copy failed")
		}
		if !equalBits(bitsOf(other[:n]), pattern) {
			t.Fatalf("n=%d: copy from a range across a chunk boundary is wrong", n)
		}
		// Both across the same boundary, with a shift (overlap).
		for _, d := range []int{-65, -3, 3, 65} {
			copyCase(t, r, buf[cut-4096:cut+4096], 4096-n/2+d, 4096-n/2, n)
		}
	}
}

func TestCopyEdgeCases(t *testing.T) {
	need(t)
	var local [64]byte
	dst := heapBytes(64)
	src := heapBytes(64)
	heapbits.SetBytes(src)
	if heapbits.Copy(unsafe.Pointer(&local), ptr(src), 64) {
		t.Error("Copy to stack memory succeeded")
	}
	if heapbits.Copy(ptr(dst), ptr(src), 0) {
		t.Error("Copy of 0 bytes succeeded")
	}
	// Across two objects: refused.
	objs := make([]*[64]byte, 256)
	for i := range objs {
		objs[i] = new([64]byte)
	}
	for i := 1; i < len(objs); i++ {
		if uintptr(unsafe.Pointer(objs[i])) == uintptr(unsafe.Pointer(objs[i-1]))+64 {
			if heapbits.Copy(unsafe.Pointer(&objs[i-1][32]), ptr(src), 64) {
				t.Error("Copy across two objects succeeded")
			}
			break
		}
	}
	// A source that is not heap memory is clean: dst loses its taint.
	heapbits.SetBytes(dst)
	if !heapbits.Copy(ptr(dst), unsafe.Pointer(&local), 64) || heapbits.AnyBytes(dst) {
		t.Error("Copy from stack memory must clear dst")
	}
	// A clean source clears dst too, without new storage.
	heapbits.SetBytes(dst)
	clean := heapBytes(64)
	if !heapbits.Copy(ptr(dst), ptr(clean), 64) || heapbits.AnyBytes(dst) {
		t.Error("Copy from a clean source must clear dst")
	}
	// Ranges that wrap the address space are refused.
	if heapbits.Copy(ptr(dst), ptr(src), ^uintptr(0)) {
		t.Error("Copy of a wrapping range succeeded")
	}
	// A span larger than 64 MiB is refused.
	big := heapBytes(64<<20 + 1)
	if heapbits.Copy(ptr(big), ptr(src), 64) {
		t.Error("Copy into a span larger than 64 MiB succeeded")
	}
	runtime.KeepAlive(big)
	runtime.KeepAlive(objs)
	runtime.KeepAlive(local)
}

// A destination that got its taint only from Copy: when it dies, its memory
// must be clean (Copy must set the span flag).
func TestCopyOnlyDestinationReuse(t *testing.T) {
	need(t)
	src := heapBytes(64)
	heapbits.SetBytes(src)
	const n = 4096
	dsts := make([]*[64]byte, n)
	addrs := make(map[uintptr]bool, n)
	for i := range dsts {
		dsts[i] = new64()
		if !heapbits.Copy(unsafe.Pointer(dsts[i]), ptr(src), 64) {
			t.Fatal("Copy failed")
		}
	}
	for i, d := range dsts {
		if !heapbits.AnyBytes(d[:]) {
			t.Fatalf("destination %d has no taint", i)
		}
	}
	// Drop runs of 64 objects: the spans stay in use, so the dead slots are
	// used again.
	for i := range dsts {
		if (i/64)%2 == 0 {
			addrs[uintptr(unsafe.Pointer(dsts[i]))] = true
			dsts[i] = nil
		}
	}
	runtime.GC()
	runtime.GC()
	reused := 0
	for range 2 * n {
		o := new64()
		if addrs[uintptr(unsafe.Pointer(o))] {
			reused++
			if heapbits.AnyBytes(o[:]) {
				t.Fatal("a new object has the taint of a Copy-only destination")
			}
		}
	}
	if reused == 0 {
		t.Fatal("no address was used again: the test is not valid")
	}
	runtime.KeepAlive(dsts)
}

//go:noinline
func new64() *[64]byte { return new([64]byte) }

// Copy into an object while another goroutine writes a neighbour object in
// the same bitmap word: no update of the neighbour is lost.
func TestCopyConcurrentNeighbour(t *testing.T) {
	need(t)
	// Two 16-byte objects in one bitmap word (64 bytes).
	var a, b *[16]byte
	for range 1024 {
		x, y := new([16]byte), new([16]byte)
		if uintptr(unsafe.Pointer(x))/64 == uintptr(unsafe.Pointer(y))/64 {
			a, b = x, y
			break
		}
	}
	if a == nil {
		t.Fatal("no two objects in one word")
	}
	tainted, clean := heapBytes(16), heapBytes(16)
	if !heapbits.SetBytes(tainted) || !heapbits.SetBytes(b[:]) { // b: get the storage
		t.Fatal("Set failed")
	}
	var stop atomic.Bool
	var copies atomic.Int64
	var wg sync.WaitGroup
	started := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			src := clean
			if i%2 == 0 {
				src = tainted
			}
			if heapbits.Copy(unsafe.Pointer(a), ptr(src), 16) {
				if copies.Add(1) == 1 {
					close(started)
				}
			}
		}
	}()
	select {
	case <-started: // the Copy goroutine works: the loop runs with it
	case <-time.After(10 * time.Second):
		stop.Store(true)
		wg.Wait()
		t.Fatal("no Copy succeeded")
	}
	for i := range 100000 {
		if i%10000 == 0 {
			// Let the Copy goroutine run between the rounds (also with
			// GOMAXPROCS=1 or a loaded machine): wait until it did one
			// more Copy.
			c, deadline := copies.Load(), time.Now().Add(10*time.Second)
			for copies.Load() == c {
				if time.Now().After(deadline) {
					stop.Store(true)
					wg.Wait()
					t.Fatal("the Copy goroutine stopped")
				}
				runtime.Gosched()
			}
		}
		heapbits.SetBytes(b[:])
		if !heapbits.AnyBytes(b[:1]) || !heapbits.AnyBytes(b[15:]) {
			t.Fatalf("round %d: a Set of the neighbour was lost", i)
		}
		heapbits.ClearBytes(b[:])
		if heapbits.AnyBytes(b[:]) {
			t.Fatalf("round %d: a Clear of the neighbour was lost", i)
		}
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("%d Copy calls", copies.Load())
	runtime.KeepAlive(a)
}

// stwCounts returns the histogram of the waits to stop the world for the GC.
func stwCounts() *metrics.Float64Histogram {
	s := []metrics.Sample{{Name: "/sched/pauses/stopping/gc:seconds"}}
	metrics.Read(s)
	return s[0].Value.Float64Histogram()
}

// maxNewWait returns the upper bound of the highest bucket that got new
// counts between the two histograms.
func maxNewWait(before, after *metrics.Float64Histogram) float64 {
	m := 0.0
	for i, c := range after.Counts {
		if c > before.Counts[i] {
			m = after.Buckets[i+1]
		}
	}
	return m
}

var progressWord atomic.Uint64

//go:noinline
func progressBaselineOp(i int) { progressWord.Or(1 << (i % 64)) }

// Progress: goroutines Copy into partial words of one shared bitmap word (a
// CAS retry loop, with competing clean and tainted sources), and one
// goroutine copies a long range; with asynchronous preemption off, a
// stop-the-world must still be fast. The test uses half of the Ps (the GC
// needs CPUs too), and it alternates rounds with a baseline (the same
// goroutines do atomic operations in plain Go code): on a loaded machine,
// the OS can delay a stop-the-world by tens of milliseconds without any
// runtime code of the feature. Rounds with a slow baseline are inconclusive;
// the limit for the others is 10 ms.
func TestCopyProgress(t *testing.T) {
	need(t)
	if testing.Short() {
		t.Skip("progress test")
	}
	if moveMode(t) {
		t.Skip("the stack moves at every call in this build: the timing is not meaningful")
	}
	if os.Getenv("HEAPBITS_PROGRESS_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCopyProgress$", "-test.v")
		cmd.Env = append(os.Environ(), "HEAPBITS_PROGRESS_CHILD=1", childEnv+"=1", "GODEBUG=asyncpreemptoff=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child failed: %v\n%s", err, out)
		}
		t.Logf("child:\n%s", out)
		if strings.Contains(string(out), "--- SKIP: TestCopyProgress") {
			t.Skip("inconclusive in the child (machine too loaded)")
		}
		return
	}
	heapbits.SetBudget(heapbits.MaxBudget)
	// At least 3: goroutine 0 does the long Copy, the others write the
	// shared word (at least 2, so that their CAS compete).
	workers := max(3, runtime.GOMAXPROCS(0)/2)
	// run runs work on the goroutines (each one calls started after its
	// first operation) during 6 GC cycles, and returns the longest new wait
	// to stop the world.
	run := func(work func(w int, stop *atomic.Bool, started func())) float64 {
		var stop atomic.Bool
		var wg, ready sync.WaitGroup
		for w := range workers {
			wg.Add(1)
			ready.Add(1)
			go func() {
				defer wg.Done()
				var once sync.Once
				work(w, &stop, func() { once.Do(ready.Done) })
			}()
		}
		ready.Wait() // all goroutines are at work
		before := stwCounts()
		for range 6 {
			runtime.GC()
		}
		after := stwCounts()
		stop.Store(true)
		wg.Wait()
		return maxNewWait(before, after)
	}
	baselineWork := func(w int, stop *atomic.Bool, started func()) {
		for i := w; !stop.Load(); i++ {
			progressBaselineOp(i)
			started()
		}
	}

	// 4 objects of 16 bytes in one word, shared by the goroutines.
	var objs []*[16]byte
	for len(objs) < 4 {
		objs = objs[:0]
		first := new([16]byte)
		objs = append(objs, first)
		for range 3 {
			x := new([16]byte)
			if uintptr(unsafe.Pointer(x))/64 != uintptr(unsafe.Pointer(first))/64 {
				break
			}
			objs = append(objs, x)
		}
	}
	tainted, clean := heapBytes(16), heapBytes(16)
	longDst, longSrc := heapBytes(32<<20), heapBytes(32<<20)
	// The sources must be tainted: else Copy is only a clear.
	if !heapbits.SetBytes(tainted) || !heapbits.SetBytes(longSrc) ||
		!heapbits.AnyBytes(tainted) || !heapbits.AnyBytes(longSrc[len(longSrc)-1:]) {
		t.Fatal("could not taint the sources")
	}
	var copies atomic.Int64
	copyWork := func(w int, stop *atomic.Bool, started func()) {
		if w == 0 {
			for !stop.Load() {
				if !heapbits.Copy(ptr(longDst), ptr(longSrc), uintptr(len(longDst))) {
					t.Error("the long Copy failed")
					started()
					return
				}
				copies.Add(1)
				started()
			}
			return
		}
		o := objs[w%4]
		// Competing patterns: tainted and clean sources, so that the CAS
		// of neighbours in the shared word fail and retry.
		for i := 0; !stop.Load(); i++ {
			src := tainted
			if (i+w)%2 == 0 {
				src = clean
			}
			if !heapbits.Copy(unsafe.Pointer(o), ptr(src), 16) {
				t.Error("Copy failed")
				started()
				return
			}
			started()
		}
	}
	// Alternate rounds of the baseline and of the Copy work, so that a
	// change of the machine load affects both. A round pair with a slow
	// baseline (more than 5 ms) is inconclusive: the machine is too loaded.
	// At most 5 pairs; at least 3 conclusive ones, else the test skips.
	const limit = 0.010
	conclusive := 0
	worst, worstBaseline := 0.0, 0.0
	for range 5 {
		baseline := run(baselineWork)
		got := run(copyWork)
		worstBaseline = max(worstBaseline, baseline)
		if baseline > 0.005 {
			continue
		}
		conclusive++
		worst = max(worst, got)
	}
	t.Logf("%d goroutines, %d conclusive rounds of 5, %d long copies; longest wait to stop the world: baseline at most %.3f ms, with Copy at most %.3f ms (limit %.0f ms)",
		workers, conclusive, copies.Load(), worstBaseline*1e3, worst*1e3, limit*1e3)
	if conclusive < 3 {
		t.Skip("the machine is too loaded (slow baseline): the result is inconclusive")
	}
	if copies.Load() == 0 {
		t.Error("no long Copy completed")
	}
	if worst > limit {
		t.Errorf("a stop-the-world waited up to %.3f ms (limit %.0f ms)", worst*1e3, limit*1e3)
	}
	runtime.KeepAlive(objs)
}

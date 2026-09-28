// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"runtime/metrics"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// The storage tests run in a child process with a small budget: they need a
// heap where no memory had taint before (so that a new object has no chunk),
// and a budget that no other test used. Note: the coverage of the child is
// not in the coverage profile of the parent.
const (
	storageChildEnv = "HEAPBITS_STORAGE_CHILD"
	childBudget     = 32 << 20 // 32 slabs, 2048 chunks
	arenaBytes      = 64 << 20
)

// runChild runs one test of this binary in a child process.
func runChild(t *testing.T, test, mode string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), storageChildEnv+"="+mode, childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	return string(out)
}

func TestStorage(t *testing.T) {
	need(t)
	if os.Getenv(storageChildEnv) != "" {
		t.Skip("in a child process")
	}
	t.Logf("child:\n%s", runChild(t, "TestStorageChild", "1"))
}

// keep holds all objects of the child process: nothing is freed, so every
// new object is memory that never had taint.
var keep [][]byte

func keepBytes(n int) []byte {
	b := heapBytes(n)
	keep = append(keep, b)
	return b
}

func addr(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

// regionAt returns the chunk-aligned 128 KiB region at or after offset off
// of obj.
func regionAt(obj []byte, off int) []byte {
	start := (addr(obj) + uintptr(off) + heapbitstest.ChunkHeapBytes - 1) &^ (heapbitstest.ChunkHeapBytes - 1)
	o := int(start - addr(obj))
	return obj[o : o+heapbitstest.ChunkHeapBytes]
}

// pool gives consecutive 128 KiB regions of large objects.
var pool struct {
	obj  []byte
	next int
}

// freshRegion returns a 128 KiB region (one chunk) of heap memory that never
// had taint: in the child process, no chunk exists for it.
func freshRegion() []byte {
	if pool.obj == nil || pool.next+2*heapbitstest.ChunkHeapBytes > len(pool.obj) {
		pool.obj, pool.next = keepBytes(16<<20), 0
	}
	r := regionAt(pool.obj, pool.next)
	pool.next = int(addr(r)-addr(pool.obj)) + heapbitstest.ChunkHeapBytes
	return r
}

// tainted is a region with a chunk, for "existing chunk" checks.
var tainted []byte

// withDirectory returns n adjacent fresh regions whose arena already has a
// directory: the directory is made with a Set in another region of the same
// object. The caller must call fillFreeChunks after it if needed.
func withDirectory(t *testing.T, n int) [][]byte {
	t.Helper()
	for range 16 {
		obj := keepBytes((n + 3) * heapbitstest.ChunkHeapBytes)
		first := regionAt(obj, 0)
		regions := make([][]byte, n)
		for i := range regions {
			regions[i] = regionAt(obj, int(addr(first)-addr(obj))+i*heapbitstest.ChunkHeapBytes)
		}
		seed := regionAt(obj, int(addr(first)-addr(obj))+n*heapbitstest.ChunkHeapBytes)
		// All in one arena: then one Set makes the directory for all.
		if addr(seed)/arenaBytes != addr(first)/arenaBytes {
			continue
		}
		if !heapbits.SetBytes(seed[:1]) {
			t.Fatalf("Set failed: %+v", heapbitstest.Stats())
		}
		return regions
	}
	t.Fatal("no object in one arena")
	return nil
}

// fillFreeChunks takes all free chunks of the mapped slabs, without a new
// slab. There must be at least one slab.
func fillFreeChunks(t *testing.T) {
	t.Helper()
	if heapbitstest.Stats().Slabs == 0 {
		t.Fatal("fillFreeChunks needs at least one slab")
	}
	for range 4096 {
		st := heapbitstest.Stats()
		if st.ChunksInUse == st.Slabs*heapbitstest.ChunksPerSlab {
			return
		}
		if !heapbits.SetBytes(freshRegion()[:1]) {
			t.Fatalf("Set failed while filling free chunks: %+v", heapbitstest.Stats())
		}
	}
	t.Fatalf("free chunks remain: %+v", heapbitstest.Stats())
}

// near reports whether a and b differ by less than half a slab (512 KiB).
// Other runtime metadata also counts in OtherSys (for example a new 256 KiB
// chunk of persistentalloc); a slab is 1 MiB. The exact check uses the
// Accounted counter.
func near(a, b uint64) bool {
	d := int64(a - b)
	return d > -(512<<10) && d < 512<<10
}

func otherSys() (memstats, metric uint64) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := []metrics.Sample{{Name: "/memory/classes/other:bytes"}}
	metrics.Read(s)
	return ms.OtherSys, s[0].Value.Uint64()
}

// waitParked waits until the goroutine given by want parks.
func waitParked(t *testing.T, fail, park, parkSlot, parkScan bool, want uint32) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for heapbitstest.AllocKnobs(fail, park, parkSlot, parkScan) != want {
		if time.Now().After(deadline) {
			heapbitstest.AllocKnobs(false, false, false, false)
			t.Fatal("the goroutine did not park")
		}
		runtime.Gosched()
	}
}

func waitDone(t *testing.T, done <-chan bool) bool {
	t.Helper()
	select {
	case ok := <-done:
		return ok
	case <-time.After(10 * time.Second):
		t.Fatal("the parked goroutine did not finish")
		return false
	}
}

func TestStorageChild(t *testing.T) {
	need(t)
	if os.Getenv(storageChildEnv) != "1" {
		t.Skip("runs in the child process of TestStorage")
	}
	defer heapbitstest.AllocKnobs(false, false, false, false)
	if !heapbits.SetBudget(childBudget) {
		t.Fatal("SetBudget failed before the first Set")
	}
	if st := heapbitstest.Stats(); st.Budget != childBudget || st.Slabs != 0 {
		t.Fatalf("unexpected storage at start: %+v", st)
	}
	// A large object over 3 arenas, for the cross-arena cases.
	big := keepBytes(3 * arenaBytes)
	tainted = freshRegion()
	if !heapbits.SetBytes(tainted[:1]) {
		t.Fatal("first Set failed")
	}

	t.Run("accounting", func(t *testing.T) {
		regions := make([][]byte, 200) // 200 chunks: more than 3 slabs
		// Take the free chunks of the first slab first: then every slab
		// of the loop below is new.
		fillFreeChunks(t)
		for i := range regions {
			regions[i] = freshRegion()
		}
		before := heapbitstest.Stats()
		ms0, m0 := otherSys()
		for _, r := range regions {
			if !heapbits.SetBytes(r[:1]) {
				t.Fatalf("Set failed: %+v", heapbitstest.Stats())
			}
		}
		after := heapbitstest.Stats()
		ms1, m1 := otherSys()
		added := (after.Slabs - before.Slabs) * heapbitstest.SlabBytes
		if added == 0 {
			t.Fatal("no slab was mapped")
		}
		// Exact: the bytes charged at the accounting call.
		if after.Accounted-before.Accounted != added || after.Accounted != after.Mapped {
			t.Errorf("charged %d bytes for %d new slabs (total charged %d, mapped %d)",
				after.Accounted-before.Accounted, after.Slabs-before.Slabs, after.Accounted, after.Mapped)
		}
		// The public runtime metrics show it too (with other noise).
		if !near(ms1, ms0+added) || !near(m1, m0+added) {
			t.Errorf("OtherSys grew by %d, metric by %d; want %d", int64(ms1-ms0), int64(m1-m0), added)
		}
		if after.Mapped != after.Slabs*heapbitstest.SlabBytes || after.Used != after.Mapped {
			t.Errorf("inconsistent counters: %+v", after)
		}
	})

	t.Run("mmap failure", func(t *testing.T) {
		// Chunk slot (the directory exists) and directory slot (a new
		// arena): both must be given back.
		chunkSlot := withDirectory(t, 1)[0]
		dirSlot := big[arenaBytes+arenaBytes/2 : arenaBytes+arenaBytes/2+64] // middle arena of big
		fillFreeChunks(t)
		for name, r := range map[string][]byte{"chunk slot": chunkSlot, "directory slot": dirSlot} {
			before := heapbitstest.Stats()
			ms0, m0 := otherSys()
			heapbitstest.AllocKnobs(true, false, false, false)
			ok := heapbits.SetBytes(r[:1])
			heapbitstest.AllocKnobs(false, false, false, false)
			after := heapbitstest.Stats()
			ms1, m1 := otherSys()
			if ok {
				t.Fatalf("%s: Set succeeded with a failing mmap", name)
			}
			if heapbits.AnyBytes(r) {
				t.Errorf("%s: a bit changed after a failed Set", name)
			}
			if after.Drops.Mmap != before.Drops.Mmap+1 {
				t.Errorf("%s: mmap drops: %d, want %d", name, after.Drops.Mmap, before.Drops.Mmap+1)
			}
			if after.Slabs != before.Slabs || after.Used != before.Used || after.Accounted != before.Accounted ||
				!near(ms1, ms0) || !near(m1, m0) {
				t.Errorf("%s: a failed mmap changed the accounting: before %+v (OtherSys %d, metric %d), after %+v (OtherSys %d, metric %d)",
					name, before, ms0, m0, after, ms1, m1)
			}
			// The slot was given back: the next Set gets the chunk.
			if !heapbits.SetBytes(r[:1]) || !heapbits.AnyBytes(r[:1]) {
				t.Errorf("%s: Set failed after the mmap failure (slot not released?)", name)
			}
			fillFreeChunks(t)
		}
	})

	t.Run("refill owner parked", func(t *testing.T) {
		regions := withDirectory(t, 2)
		owner, other := regions[0], regions[1]
		fillFreeChunks(t)
		heapbitstest.AllocKnobs(false, true, false, false)
		done := make(chan bool)
		go func() { done <- heapbits.SetBytes(owner[:1]) }()
		waitParked(t, false, true, false, false, heapbitstest.RefillParked)
		parked := heapbitstest.Stats()
		if parked.Used != parked.Mapped+heapbitstest.SlabBytes {
			t.Errorf("the reservation of the parked owner is not visible: %+v", parked)
		}
		// Another goroutine that needs a new slab drops at once, with a
		// refill-busy drop (its directory exists, so it reaches the refill).
		if heapbits.SetBytes(other[:1]) {
			t.Error("Set that needs a new slab succeeded while the owner is parked")
		}
		if st := heapbitstest.Stats(); st.Drops.RefillBusy != parked.Drops.RefillBusy+1 {
			t.Errorf("refill-busy drops: %d, want %d", st.Drops.RefillBusy, parked.Drops.RefillBusy+1)
		}
		// Operations on existing chunks continue.
		if !heapbits.SetBytes(tainted[1:2]) {
			t.Error("Set on an existing chunk failed while the owner is parked")
		}
		heapbitstest.AllocKnobs(false, false, false, false)
		if !waitDone(t, done) {
			t.Error("the parked owner failed")
		}
		if st := heapbitstest.Stats(); st.Used != st.Mapped {
			t.Errorf("reservation not released: %+v", st)
		}
		// The refill flag is free again.
		fillFreeChunks(t)
		if !heapbits.SetBytes(other[:1]) {
			t.Errorf("refill failed after the parked owner: %+v", heapbitstest.Stats())
		}
	})

	t.Run("claimed slot", func(t *testing.T) {
		r := withDirectory(t, 1)[0]
		heapbitstest.AllocKnobs(false, false, true, false)
		done := make(chan bool)
		go func() { done <- heapbits.SetBytes(r[:1]) }()
		waitParked(t, false, false, true, false, heapbitstest.SlotParked)
		before := heapbitstest.Stats()
		// The slot is claimed: another writer of the same chunk drops at
		// once, and a reader sees no taint.
		if heapbits.SetBytes(r[64:65]) {
			t.Error("Set on a claimed slot succeeded")
		}
		if heapbits.AnyBytes(r) {
			t.Error("a claimed slot has bits")
		}
		if st := heapbitstest.Stats(); st.Drops.SlotBusy != before.Drops.SlotBusy+1 {
			t.Errorf("slot-busy drops: %d, want %d", st.Drops.SlotBusy, before.Drops.SlotBusy+1)
		}
		heapbitstest.AllocKnobs(false, false, false, false)
		if !waitDone(t, done) {
			t.Error("the slot owner failed")
		}
		if !heapbits.SetBytes(r[64:65]) || !heapbits.AnyBytes(r[:1]) || !heapbits.AnyBytes(r[64:65]) {
			t.Error("Set after the claim failed")
		}
	})

	t.Run("scan then refill", func(t *testing.T) {
		// B finds no free chunk and waits before the refill flag; A maps a
		// new slab. When B continues, it must take a chunk of that slab,
		// not map another one.
		regions := withDirectory(t, 2)
		a, b := regions[0], regions[1]
		fillFreeChunks(t)
		heapbitstest.AllocKnobs(false, false, false, true)
		done := make(chan bool)
		go func() { done <- heapbits.SetBytes(b[:1]) }()
		waitParked(t, false, false, false, true, heapbitstest.ScanParked)
		before := heapbitstest.Stats()
		if !heapbits.SetBytes(a[:1]) {
			t.Fatalf("A failed: %+v", heapbitstest.Stats())
		}
		heapbitstest.AllocKnobs(false, false, false, false)
		if !waitDone(t, done) {
			t.Fatalf("B failed: %+v", heapbitstest.Stats())
		}
		if after := heapbitstest.Stats(); after.Slabs != before.Slabs+1 {
			t.Errorf("%d new slabs, want 1 (B mapped a slab although A's slab had free chunks)", after.Slabs-before.Slabs)
		}
	})

	t.Run("same chunk contention", func(t *testing.T) {
		// Smoke test (the claimed-slot test above is the exact one).
		r := freshRegion()
		before := heapbitstest.Stats()
		const workers = 18
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]bool, workers)
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				results[w] = heapbits.SetBytes(r[w*64 : w*64+1])
			}()
		}
		close(start)
		wg.Wait()
		after := heapbitstest.Stats()
		won := 0
		for _, ok := range results {
			if ok {
				won++
			}
		}
		if won == 0 {
			t.Fatal("no Set succeeded")
		}
		// One chunk for the region (and at most one for a new directory).
		if got := after.ChunksInUse - before.ChunksInUse; got < 1 || got > 2 {
			t.Errorf("%d chunks taken for one region, want 1 or 2", got)
		}
		if lost := uint64(workers - won); after.Drops.SlotBusy-before.Drops.SlotBusy != lost {
			t.Errorf("%d Set calls failed, but %d slot-busy drops", lost, after.Drops.SlotBusy-before.Drops.SlotBusy)
		}
	})

	t.Run("concurrent refills", func(t *testing.T) {
		// Many goroutines that need new slabs: at most one maps at a time,
		// the others drop; the budget is never exceeded.
		const workers = 18
		var wg sync.WaitGroup
		start := make(chan struct{})
		regions := make([][]byte, workers*8)
		for i := range regions {
			regions[i] = freshRegion()
		}
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for i := w; i < len(regions); i += workers {
					heapbits.SetBytes(regions[i][:1])
				}
			}()
		}
		close(start)
		wg.Wait()
		if st := heapbitstest.Stats(); st.UsedMax > st.Budget || st.Used != st.Mapped || st.Accounted != st.Mapped {
			t.Errorf("inconsistent counters after concurrent refills: %+v", st)
		}
	})

	t.Run("budget", func(t *testing.T) {
		if heapbits.SetBudget(heapbits.MaxBudget) {
			t.Error("SetBudget succeeded after the first slab")
		}
		pair := withDirectory(t, 2)
		fillBudgetButOne(t)
		// All or nothing in one arena: 2 new chunks, 1 free chunk.
		checkAllOrNothing(t, pair[0][heapbitstest.ChunkHeapBytes-8:heapbitstest.ChunkHeapBytes+8])
		final := heapbitstest.Stats()
		if final.UsedMax > final.Budget || final.Mapped != childBudget || final.Accounted != childBudget {
			t.Errorf("budget exceeded: %+v", final)
		}
		// Existing chunks still work.
		if !heapbits.SetBytes(tainted[2:3]) {
			t.Error("Set on an existing chunk failed at the budget limit")
		}
	})
}

// fillBudgetButOne uses the budget and keeps exactly one free chunk.
func fillBudgetButOne(t *testing.T) {
	t.Helper()
	for range 8192 {
		st := heapbitstest.Stats()
		if st.Slabs*heapbitstest.SlabBytes == st.Budget && st.ChunksInUse == st.Slabs*heapbitstest.ChunksPerSlab-1 {
			return
		}
		if !heapbits.SetBytes(freshRegion()[:1]) {
			t.Fatalf("Set failed before the budget was used: %+v", st)
		}
	}
	t.Fatalf("could not reach the budget: %+v", heapbitstest.Stats())
}

// checkAllOrNothing sets a range over 2 new chunks (their directories exist)
// with exactly 1 free chunk: the first chunk is obtained, the second is not,
// Set fails, and no bit changes.
func checkAllOrNothing(t *testing.T, across []byte) {
	t.Helper()
	before := heapbitstest.Stats()
	if before.ChunksInUse != before.Slabs*heapbitstest.ChunksPerSlab-1 || before.Mapped != before.Budget {
		t.Fatalf("setup: want a full budget with 1 free chunk: %+v", before)
	}
	if heapbits.SetBytes(across) {
		t.Fatal("Set over 2 new chunks succeeded with 1 free chunk")
	}
	after := heapbitstest.Stats()
	if heapbits.AnyBytes(across) {
		t.Error("a failed Set changed bits")
	}
	if after.Drops.Budget == before.Drops.Budget {
		t.Error("no budget drop")
	}
	if after.ChunksInUse != before.ChunksInUse+1 {
		t.Errorf("%d chunks obtained before the failure, want 1", after.ChunksInUse-before.ChunksInUse)
	}
	if after.UsedMax > after.Budget {
		t.Errorf("budget exceeded: %+v", after)
	}
}

// All or nothing across 2 arenas (own child process: it needs its own
// last free chunk).
func TestStorageAllOrNothingAcrossArenas(t *testing.T) {
	need(t)
	switch os.Getenv(storageChildEnv) {
	case "":
		runChild(t, "TestStorageAllOrNothingAcrossArenas", "cross")
		return
	case "cross":
	default:
		t.Skip("in another child process")
	}
	if !heapbits.SetBudget(childBudget) {
		t.Fatal("SetBudget failed before the first Set")
	}
	big := keepBytes(3 * arenaBytes)
	cut := (addr(big) + arenaBytes) &^ (arenaBytes - 1) // first arena boundary in big
	c := int(cut - addr(big))
	// The directories of the two arenas.
	if !heapbits.SetBytes(big[c-4*heapbitstest.ChunkHeapBytes:][:1]) || !heapbits.SetBytes(big[c+4*heapbitstest.ChunkHeapBytes:][:1]) {
		t.Fatalf("Set failed: %+v", heapbitstest.Stats())
	}
	fillBudgetButOne(t)
	checkAllOrNothing(t, big[c-8:c+8])
}

// The runtime default budget is heapbits.DefaultBudget; a budget of 0 turns
// the storage off.
func TestBudgetDefaultAndZero(t *testing.T) {
	need(t)
	switch os.Getenv(storageChildEnv) {
	case "default":
		if st := heapbitstest.Stats(); st.Budget != heapbits.DefaultBudget {
			t.Fatalf("runtime default budget %d, heapbits.DefaultBudget %d", st.Budget, heapbits.DefaultBudget)
		}
	case "zero":
		if !heapbits.SetBudget(0) {
			t.Fatal("SetBudget(0) failed")
		}
		if heapbits.SetBytes(heapBytes(64)) {
			t.Fatal("Set succeeded with a budget of 0")
		}
		if st := heapbitstest.Stats(); st.Slabs != 0 || st.Drops.Budget == 0 {
			t.Fatalf("unexpected storage: %+v", st)
		}
	case "":
		runChild(t, "TestBudgetDefaultAndZero", "default")
		runChild(t, "TestBudgetDefaultAndZero", "zero")
	default:
		t.Skip("in another child process")
	}
}

package propagation_test

import (
	"math/rand/v2"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

func heapInuse() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func probeInput(random *rand.Rand) []byte {
	b := make([]byte, 1+random.IntN(sequenceMaxInput))
	for i := range b {
		b[i] = byte(random.Uint64())
	}
	return b
}

// Sequence body only: no subtests, no cleanups (owners finished by defer inside runEngineSequence).
func TestReviewProbeHeapGrowthSequence(t *testing.T) {
	taintStore, _ := beginScope(t)
	random := rand.New(rand.NewPCG(1, 2))
	run := func(n int) {
		for i := 0; i < n; i++ {
			runEngineSequence(t, taintStore, probeInput(random))
		}
	}
	run(20000)
	base := heapInuse()
	charged, values := taintStore.ProcessCharged(), taintStore.ProcessValues()
	for round := 1; round <= 4; round++ {
		run(50000)
		h := heapInuse()
		t.Logf("seq round=%d heapInuse=%d delta=%d charged=%d/%d values=%d/%d", round, h, int64(h)-int64(base),
			taintStore.ProcessCharged(), charged, taintStore.ProcessValues(), values)
	}
}

// Lifecycle cycles; the only harness-side accumulation is t.Cleanup closures (3 per cycle).
func TestReviewProbeHeapGrowthLifecycle(t *testing.T) {
	taintStore, _ := beginScope(t)
	random := rand.New(rand.NewPCG(3, 4))
	var owners int
	run := func(n int) {
		for i := 0; i < n; i++ {
			cursor := newSequenceCursor(probeInput(random))
			runOwnerLifecycleCycleNoCleanup(t, taintStore, cursor, i%8)
			owners += 3
		}
	}
	run(20000)
	base := heapInuse()
	var sink *store.Store = taintStore
	for round := 1; round <= 4; round++ {
		run(50000)
		h := heapInuse()
		t.Logf("life round=%d heapInuse=%d delta=%d cleanupsRegistered~%d charged=%d values=%d", round, h, int64(h)-int64(base), owners, sink.ProcessCharged(), sink.ProcessValues())
	}
}

func runOwnerLifecycleCycleNoCleanup(t *testing.T, taintStore *store.Store, cursor *sequenceCursor, cycle int) {
	t.Helper()
	owner := taintStore.Acquire()
	if owner.Disabled() {
		t.Fatal("primary lifecycle owner admission unexpectedly failed")
	}
	oldIndex, ok := owner.Index()
	if !ok {
		t.Fatal("primary lifecycle owner has no slot index")
	}
	oldID, oldGeneration := owner.ID(), owner.Generation()

	managed, expected := admitLifecycleString(t, owner, cursor, cycle, 1)
	assertLifecycleRanges(t, taintStore, owner, managed, expected)
	nativeCopy := strings.Clone(managed)
	copied := propagation.CopyString(managed, nativeCopy)
	if copied != nativeCopy {
		t.Fatalf("lifecycle copy changed native value: got=%q want=%q", copied, nativeCopy)
	}
	assertLifecycleRanges(t, taintStore, owner, copied, expected)

	beforeDrop := owner.Counters().OneByte
	oneByte, reference, admitted := owner.TaintString("x", 2)
	if admitted || oneByte != "x" || reference != (store.RootRef{}) {
		t.Fatalf("one-byte root was not deterministically dropped: admitted=%v value=%q ref=%v", admitted, oneByte, reference)
	}
	if got := owner.Counters().OneByte; got != beforeDrop+1 {
		t.Fatalf("one-byte drop counter differs: got=%d want=%d", got, beforeDrop+1)
	}

	var sibling *store.Owner
	if cursor.next()&1 != 0 {
		sibling = taintStore.Acquire()
		if sibling.Disabled() {
			t.Fatal("secondary lifecycle owner admission unexpectedly failed")
		}
		siblingValue, siblingRanges := admitLifecycleString(t, sibling, cursor, cycle, 17)
		assertLifecycleRanges(t, taintStore, sibling, siblingValue, siblingRanges)
	}

	owner.Finish()
	assertLifecycleValueReleased(t, taintStore, managed)
	var staleSet ranges.Set
	if !ranges.AdoptCanonical(&staleSet, ranges.DefaultLimit, expected, uint32(len(managed))).Valid {
		t.Fatalf("stale admission fixture is invalid: %v", expected)
	}
	if _, admitted = owner.AdoptString(strings.Clone(managed), &staleSet); admitted {
		t.Fatal("finished owner admitted a new root")
	}

	reused := taintStore.Acquire()
	if reused.Disabled() {
		t.Fatal("reused lifecycle owner admission unexpectedly failed")
	}
	reusedIndex, ok := reused.Index()
	if !ok {
		t.Fatal("reused lifecycle owner has no slot index")
	}
	if reusedIndex != oldIndex {
		t.Fatalf("finished slot was not reused: got=%d want=%d", reusedIndex, oldIndex)
	}
	if reused.ID() == oldID || reused.Generation() == oldGeneration {
		t.Fatalf(
			"slot reuse did not advance identity: old=(%d,%d) new=(%d,%d)",
			oldID,
			oldGeneration,
			reused.ID(),
			reused.Generation(),
		)
	}

	reusedValue, reusedRanges := admitLifecycleString(t, reused, cursor, cycle, 33)
	assertLifecycleRanges(t, taintStore, reused, reusedValue, reusedRanges)
	staleNative := strings.Clone(managed)
	staleOut := propagation.CopyString(managed, staleNative)
	if staleOut != staleNative {
		t.Fatalf("stale copy changed native value: got=%q want=%q", staleOut, staleNative)
	}
	assertLifecycleValueReleased(t, taintStore, staleOut)

	reused.Finish()
	if sibling != nil {
		sibling.Finish()
	}
}

// Minimal independent store-level reproducer for store-stress-F1.
//
// Unlike the phase-2 reproducer it does not pre-fill the other 63 owner slots:
// with a fresh store, owner slot 0 is both the first slot acquired and the
// first dead/unused candidate on every later Acquire, so plain acquire/finish
// cycling reuses slot 0 deterministically. A spinning late goroutine holds
// request A's raw *Owner (the same handle request.Analysis obtains from
// slot.owner) and keeps binding an object / recording builder writes while A
// finishes and B reuses the slot.
package store

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func fxBudget() time.Duration {
	if v, err := time.ParseDuration(os.Getenv("FX_BUDGET")); err == nil {
		return v
	}
	return 60 * time.Second
}

func fxSpinners() int {
	if v, err := strconv.Atoi(os.Getenv("FX_SPINNERS")); err == nil {
		return v
	}
	return 8
}

type fxObj struct{ pad [16]byte }

type fxBuilder struct{ buf []byte }

func TestFXStaleOwnerPublishesIntoReusedSlot(t *testing.T) {
	s := New()
	deadline := time.Now().Add(fxBudget())
	n := fxSpinners()
	for iter := 0; time.Now().Before(deadline); iter++ {
		a := s.Acquire()
		if idx, _ := a.Index(); idx != 0 {
			t.Fatalf("iteration %d: expected slot 0, got %d", iter, idx)
		}
		objs := make([]*fxObj, n)
		builders := make([]*fxBuilder, n)
		for g := 0; g < n; g++ {
			objs[g] = &fxObj{}
			builders[g] = &fxBuilder{buf: make([]byte, 0, 64)}
		}
		var stop atomic.Bool
		var attempts atomic.Int64
		var wg sync.WaitGroup
		for g := 0; g < n; g++ {
			wg.Add(1)
			go func(obj *fxObj, b *fxBuilder) {
				defer wg.Done()
				p := uintptr(unsafe.Pointer(unsafe.SliceData(b.buf)))
				before := WriterView{Pointer: p, Length: 0, Capacity: 64}
				after := WriterView{Pointer: p, Length: 4, Capacity: 64}
				var input ranges.Set
				ranges.AdoptCanonical(&input, ranges.DefaultLimit, []ranges.Range{{Length: 4, SourceID: 42}}, 4)
				for !stop.Load() {
					BindObjectValue(a, obj, BindingURL)
					a.UpdateWriter(b, WriterStringBuilder, before, after, &input, 4, 4)
					attempts.Add(1)
				}
			}(objs[g], builders[g])
		}
		for attempts.Load() < int64(n) {
		}
		a.Finish()
		b := s.Acquire()
		if idx, _ := b.Index(); idx != 0 || b.Generation() == a.Generation() {
			t.Fatalf("iteration %d: slot 0 not reused", iter)
		}
		mark := attempts.Load()
		for attempts.Load() < mark+int64(4*n) {
		}
		stop.Store(true)
		wg.Wait()

		for _, obj := range objs {
			var refs [4]OwnerRef
			if LookupObject(s, obj, refs[:]) == 0 {
				continue
			}
			owner, ok := refs[0].Handle()
			if ok && owner.Generation() == b.Generation() {
				t.Fatalf("iteration %d: object bound only through FINISHED request A (gen %d) is bound to NEW request B (gen %d, id %d): cross-request binding bleed", iter, a.Generation(), b.Generation(), b.ID())
			}
		}
		for _, bld := range builders {
			p := uintptr(unsafe.Pointer(unsafe.SliceData(bld.buf)))
			view := WriterView{Pointer: p, Length: 4, Capacity: 64}
			var wrefs [4]WriterRef
			if LookupWriterValue(s, bld, WriterStringBuilder, view, wrefs[:]) == 0 {
				continue
			}
			owner, ok := wrefs[0].Handle()
			if ok && owner.Generation() == b.Generation() {
				var got ranges.Set
				snap := owner.SnapshotWriter(bld, WriterStringBuilder, view, &got)
				r, _ := got.At(0)
				t.Fatalf("iteration %d: builder written only through FINISHED request A (gen %d) tracked by NEW request B (gen %d, id %d): snapshot=%v ranges=%d first=%+v; B charged=%d", iter, a.Generation(), b.Generation(), b.ID(), snap, got.Len(), r, b.Charged())
			}
		}
		b.Finish()
	}
	t.Log("no cross-request publication observed within budget")
}

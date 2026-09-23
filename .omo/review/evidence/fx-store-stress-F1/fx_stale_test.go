// Independent verification reproducer for store-stress-F1.
//
// It exercises the stale-owner torn-alive() window through the realistic
// internal API surface that woven (orchestrion) hooks call:
//
//   - request.Begin / Scope.Finish            (woven net/http server advice)
//   - request.BindReader / PropagateReader    (registered into iobridge; woven
//                                              io/bufio reader hooks)
//   - Analysis.TaintString                   (woven HTTP source hooks)
//   - propagation.UpdateStringWriter         (woven strings.Builder write hook)
//
// Scenario per iteration: request A is active; application goroutines of A are
// still performing reader propagation / builder-write recording when A's scope
// finishes and the next request B immediately reuses the same store owner slot
// (deterministic with default DD_IAST_MAX_CONCURRENT_REQUESTS=2: A takes
// owner slot 0, B takes slot 0 after A finishes). A late goroutine of A that
// is inside beginWrite when Finish+Acquire complete can pass the torn
// alive() check and publish into B.
package fxstale

import (
	"context"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

func budget() time.Duration {
	if v, err := time.ParseDuration(os.Getenv("FX_BUDGET")); err == nil {
		return v
	}
	return 60 * time.Second
}

func spinners() int {
	if v, err := strconv.Atoi(os.Getenv("FX_SPINNERS")); err == nil {
		return v
	}
	return 16
}

type fxReader struct{ pad [16]byte }

type fxBuilder struct{ buf []byte }

func setup(t *testing.T) {
	t.Helper()
	prevEnabled := config.Enabled
	prevSampling := config.RequestSamplingPct
	prevMax := config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 2
	t.Cleanup(func() {
		config.Enabled = prevEnabled
		config.RequestSamplingPct = prevSampling
		config.MaxConcurrentRequests = prevMax
	})
}

func activeStoreWhileActive(t *testing.T) *store.Store {
	t.Helper()
	_, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("warm-up scope not created")
	}
	s := request.ActiveStore()
	if s == nil {
		t.Fatal("ActiveStore nil while a scope is active")
	}
	scope.Finish()
	return s
}

// TestFXLateReaderBindBleedsIntoNextRequest drives the woven reader path
// (request.BindReader / request.PropagateReader). A late goroutine of a
// finished request binds an output reader into the NEXT request's binding
// table.
func TestFXLateReaderBindBleedsIntoNextRequest(t *testing.T) {
	setup(t)
	s := activeStoreWhileActive(t)
	deadline := time.Now().Add(budget())
	n := spinners()
	for iter := 0; time.Now().Before(deadline); iter++ {
		ctxA, scopeA, created := request.Begin(context.Background())
		if !created {
			t.Fatal("scope A not created")
		}
		aA, ok := scopeA.Analysis()
		if !ok {
			t.Fatal("scope A has no analysis")
		}
		idxA, _, genA, ok := aA.Identity()
		if !ok {
			t.Fatal("no identity A")
		}
		in := &fxReader{}
		if !request.BindReader(ctxA, in) {
			t.Fatal("BindReader(A) failed")
		}

		var stop atomic.Bool
		var attempts atomic.Int64
		var wg sync.WaitGroup
		outs := make([]*fxReader, n)
		for g := 0; g < n; g++ {
			outs[g] = &fxReader{}
			wg.Add(1)
			go func(out *fxReader) {
				defer wg.Done()
				for !stop.Load() {
					request.PropagateReader(in, out)
					attempts.Add(1)
				}
			}(outs[g])
		}
		for attempts.Load() < int64(n) {
		}
		scopeA.Finish()

		_, scopeB, createdB := request.Begin(context.Background())
		if !createdB {
			t.Fatal("scope B not created")
		}
		aB, ok := scopeB.Analysis()
		if !ok {
			t.Fatal("scope B has no analysis")
		}
		idxB, idB, genB, _ := aB.Identity()
		mark := attempts.Load()
		for attempts.Load() < mark+int64(4*n) {
		}
		stop.Store(true)
		wg.Wait()

		if idxB == idxA && genB != genA {
			for _, out := range outs {
				var refs [4]store.OwnerRef
				cnt := store.LookupObjectValue(s, out, store.BindingReader, refs[:])
				for i := 0; i < cnt; i++ {
					owner, ok := refs[i].Handle()
					if !ok {
						continue
					}
					if owner.Generation() == genB {
						t.Fatalf("iteration %d: output reader propagated only through FINISHED request A (slot %d gen %d) is bound to NEW request B (slot %d gen %d, id %d); cross-request binding bleed", iter, idxA, genA, idxB, genB, idB)
					}
				}
			}
		}
		scopeB.Finish()
	}
	t.Log("no cross-request reader binding bleed observed within budget")
}

// TestFXLateWriterUpdateBleedsIntoNextRequest drives the woven writer path
// (propagation.UpdateStringWriter, the strings.Builder write hook) with a real
// request source published through Analysis.TaintString. A late builder write
// of a finished request creates writer state in the NEXT request's owner,
// carrying request A's owner-local source ID and charging request B.
func TestFXLateWriterUpdateBleedsIntoNextRequest(t *testing.T) {
	setup(t)
	s := activeStoreWhileActive(t)
	deadline := time.Now().Add(budget())
	n := spinners()
	for iter := 0; time.Now().Before(deadline); iter++ {
		_, scopeA, created := request.Begin(context.Background())
		if !created {
			t.Fatal("scope A not created")
		}
		aA, ok := scopeA.Analysis()
		if !ok {
			t.Fatal("scope A has no analysis")
		}
		idxA, _, genA, ok := aA.Identity()
		if !ok {
			t.Fatal("no identity A")
		}
		managed, tainted := aA.TaintString(constants.OriginHttpRequestQuery, "q", "evil")
		if !tainted {
			t.Fatal("TaintString failed")
		}
		key, keyOK := store.StringKey(managed)
		if !keyOK {
			t.Fatal("no key for managed string")
		}
		var snap store.Snapshot
		if !s.Lookup(key, &snap) || snap.Len() == 0 {
			t.Fatal("no live entry for managed string")
		}
		entry, _ := snap.At(0)
		first, _ := entry.Ranges.At(0)
		srcA := first.SourceID

		objs := make([]*fxBuilder, n)
		for g := range objs {
			objs[g] = &fxBuilder{buf: make([]byte, 0, 64)}
		}
		view := func(b *fxBuilder, length uint32) store.WriterView {
			return store.WriterView{Pointer: uintptr(unsafe.Pointer(unsafe.SliceData(b.buf))), Length: length, Capacity: 64}
		}
		propagation.UpdateStringWriter(objs[0], store.WriterStringBuilder, view(objs[0], 0), view(objs[0], 4), managed, 4)

		var stop atomic.Bool
		var attempts atomic.Int64
		var wg sync.WaitGroup
		for g := 0; g < n; g++ {
			wg.Add(1)
			go func(obj *fxBuilder) {
				defer wg.Done()
				before := view(obj, 0)
				after := view(obj, 4)
				for !stop.Load() {
					propagation.UpdateStringWriter(obj, store.WriterStringBuilder, before, after, managed, 4)
					attempts.Add(1)
				}
			}(objs[g])
		}
		for attempts.Load() < int64(n) {
		}
		scopeA.Finish()

		_, scopeB, createdB := request.Begin(context.Background())
		if !createdB {
			t.Fatal("scope B not created")
		}
		aB, ok := scopeB.Analysis()
		if !ok {
			t.Fatal("scope B has no analysis")
		}
		idxB, idB, genB, _ := aB.Identity()
		mark := attempts.Load()
		for attempts.Load() < mark+int64(4*n) {
		}
		stop.Store(true)
		wg.Wait()

		if idxB == idxA && genB != genA {
			for _, obj := range objs {
				var refs [4]store.WriterRef
				cnt := store.LookupWriterValue(s, obj, store.WriterStringBuilder, view(obj, 4), refs[:])
				for i := 0; i < cnt; i++ {
					owner, ok := refs[i].Handle()
					if !ok || owner.Generation() != genB {
						continue
					}
					var got ranges.Set
					if !owner.SnapshotWriter(obj, store.WriterStringBuilder, view(obj, 4), &got) || got.Len() == 0 {
						continue
					}
					r, _ := got.At(0)
					t.Fatalf("iteration %d: builder written only through FINISHED request A (slot %d gen %d) has writer state in NEW request B (slot %d gen %d, id %d); B charged=%d; writer range carries A's owner-local SourceID=%d, resolved against B's source table (A's source ID was %d)",
						iter, idxA, genA, idxB, genB, idB, owner.Charged(), r.SourceID, srcA)
				}
			}
		}
		scopeB.Finish()
	}
	t.Log("no cross-request writer state bleed observed within budget")
}

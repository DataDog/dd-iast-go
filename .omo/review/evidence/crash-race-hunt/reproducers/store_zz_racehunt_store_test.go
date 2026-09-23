package store

// crash-race-hunt stress: many owners churn Acquire/Finish while stale handles,
// cross-owner lookups, entry handles, byte mutation, object bindings, writer
// state and buffer invalidation all run concurrently. Run under -race.

import (
	"math/rand/v2"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

type rhShared struct {
	str    string
	bytesK Key
	reader *strings.Reader
	obj    *writerObject
}

func TestRaceHuntStoreChurn(t *testing.T) {
	s := New()
	var writerActive, operatorActive atomic.Int32
	s.BindWriterActive(&writerActive)
	s.BindOperatorActive(&operatorActive)

	const workers = 24
	const iterations = 400
	var acquired, tainted, hits, handles atomic.Int64
	var shared [workers]atomic.Pointer[rhShared]
	stale := make(chan *Owner, 256)
	var wg sync.WaitGroup
	done := make(chan struct{})

	// Late goroutines hammer finished (stale) handles and re-finish them.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range stale {
				v := strings.Repeat("late-value-", 3)
				o.TaintString(v, 1)
				o.TaintBytes([]byte(v), 1)
				k, _ := StringKey(v)
				o.Derive(k, RootRef{ID: 0, Generation: 1})
				obj := &writerObject{id: 7}
				var set ranges.Set
				ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: 4, SourceID: 1}}, 4)
				o.UpdateWriter(obj, WriterStringBuilder, WriterView{}, WriterView{Pointer: 0x4000, Length: 4, Capacity: 8}, &set, 4, 4)
				BindObjectValue(o, strings.NewReader(v), BindingReader)
				o.Finish()
				_ = o.Counters()
			}
		}()
	}

	// Readers do lookups on whatever other owners published.
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var snap Snapshot
			var refs [4]OwnerRef
			var wrefs [4]WriterRef
			for {
				select {
				case <-done:
					return
				default:
				}
				i := rand.IntN(workers)
				p := shared[i].Load()
				if p == nil {
					continue
				}
				k, _ := StringKey(p.str)
				if s.MayContain(k) {
					s.Lookup(k, &snap)
					if snap.Len() > 0 {
						hits.Add(1)
					}
					for e := 0; e < snap.Len(); e++ {
						entry, _ := snap.At(e)
						if h, ok := entry.Handle(s); ok {
							handles.Add(1)
							sub := p.str[1:5]
							sk, _ := StringKey(sub)
							h.Derive(sk, entry.Root)
						}
					}
				}
				s.Lookup(p.bytesK, &snap)
				n := LookupObjectValue(s, p.reader, BindingReader, refs[:])
				for r := 0; r < n; r++ {
					refs[r].Identity()
					refs[r].Handle()
				}
				LookupWriterValue(s, p.obj, WriterStringBuilder, WriterView{}, wrefs[:])
				s.InvalidateWriterPointer(uintptr(unsafe.Pointer(p.obj)))
				s.InvalidateBuffer(0x5000, 0x9000, 64, rand.IntN(2) == 0)
				if rand.IntN(512) == 0 {
					_ = s.Stats()
				}
				_ = s.ProcessCharged()
				runtime.Gosched()
			}
		}()
	}

	var workersWG sync.WaitGroup
	for w := 0; w < workers; w++ {
		workersWG.Add(1)
		go func(w int) {
			defer workersWG.Done()
			for it := 0; it < iterations; it++ {
				o := s.Acquire()
				for retry := 0; o.Disabled() && retry < 64; retry++ {
					runtime.Gosched()
					o = s.Acquire()
				}
				if o.Disabled() {
					continue
				}
				acquired.Add(1)
				value := strings.Repeat("abcdefghij", 1+rand.IntN(4))
				managed, _, root, ok := o.TaintSourceString(value, "name", 1)
				if !ok {
					o.Finish()
					continue
				}
				tainted.Add(1)
				for d := 0; d+3 <= len(managed); d += 3 {
					k, _ := StringKey(managed[d : d+3])
					o.Derive(k, root)
				}
				b, broot, ok := o.TaintBytes([]byte(value), 2)
				var bk Key
				if ok {
					bk, _ = BytesKey(b)
					var set ranges.Set
					ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: uint32(len(b)), SourceID: 2}}, uint32(cap(b)))
					b[0]++
					if next, pub := o.PublishBytesMutation(broot, b, &set); pub {
						broot = next
					}
				}
				reader := strings.NewReader(value)
				BindObjectValue(o, reader, BindingReader)
				obj := &writerObject{id: w}
				var in ranges.Set
				ranges.AdoptCanonical(&in, 10, []ranges.Range{{Length: 4, SourceID: 1}}, 4)
				view := WriterView{Pointer: 0x1000 + uintptr(w)*0x100, Length: 4, Capacity: 16}
				o.UpdateWriter(obj, WriterStringBuilder, WriterView{}, view, &in, 4, 4)
				var snapSet ranges.Set
				o.SnapshotWriter(obj, WriterStringBuilder, view, &snapSet)
				anchor := make([]byte, 32)
				bview := WriterView{Pointer: 0x5000, Length: 4, Capacity: 32, Backing: uintptr(unsafe.Pointer(&anchor[0])), Anchor: &anchor[0]}
				o.AdoptBufferWriter(obj, bview)
				if rand.IntN(3) == 0 {
					o.TruncateWriter(obj, WriterStringBuilder, view, WriterView{Pointer: view.Pointer, Length: 2, Capacity: 16})
				}
				if rand.IntN(3) == 0 {
					o.ResetWriter(obj, WriterStringBuilder)
				}
				shared[w].Store(&rhShared{str: managed, bytesK: bk, reader: reader, obj: obj})
				// Keep the owner live while peers look up / derive into it.
				for spin := 0; spin < 8; spin++ {
					if p := shared[rand.IntN(workers)].Load(); p != nil {
						var snap Snapshot
						k, _ := StringKey(p.str)
						s.Lookup(k, &snap)
						if snap.Len() > 0 {
							hits.Add(1)
						}
					}
					runtime.Gosched()
				}
				if rand.IntN(2) == 0 {
					// Concurrent finish racing with in-flight lookups/derives.
					wg.Add(1)
					go func() { defer wg.Done(); o.Finish() }()
				} else {
					o.Finish()
				}
				select {
				case stale <- o:
				default:
				}
			}
		}(w)
	}
	workersWG.Wait()
	close(done)
	close(stale)
	wg.Wait()
	var states [8]int
	for i := range s.owners {
		states[s.owners[i].state.Load()]++
	}
	after := s.Acquire()
	t.Logf("owner states=%v acquireDrops=%d postAcquireDisabled=%v writerLocked=%v", states, s.AcquireDrops(), after.Disabled(), func() bool {
		ok := s.owners[0].writersMu.TryLock()
		if ok {
			s.owners[0].writersMu.Unlock()
		}
		return !ok
	}())
	after.Finish()
	t.Logf("acquired=%d tainted=%d lookupHits=%d liveHandles=%d charged=%d values=%d", acquired.Load(), tainted.Load(), hits.Load(), handles.Load(), s.ProcessCharged(), s.ProcessValues())
}

package store

// Review-only parallel contention benchmarks (perf-contention node).

import (
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

const pcValues = 256

var setupRetries atomic.Uint64

func pcPopulated(b *testing.B) (*Store, *Owner, []Key) {
	b.Helper()
	s := New()
	o := s.Acquire()
	if o.Disabled() {
		b.Fatal("acquire")
	}
	keys := make([]Key, 0, pcValues)
	for i := 0; i < pcValues; i++ {
		v, _, ok := o.TaintString("populated-value-"+strconv.Itoa(i)+"-padding", ranges.SourceID(i%200))
		if !ok {
			b.Fatalf("taint %d", i)
		}
		k, _ := StringKey(v)
		keys = append(keys, k)
	}
	return s, o, keys
}

func pcAcquire(s *Store) *Owner {
	for {
		if o := s.Acquire(); !o.Disabled() {
			return o
		}
	}
}

// Read-only hot path: operator gate probe.
func BenchmarkPCMayContainHit(b *testing.B) {
	s, o, keys := pcPopulated(b)
	defer o.Finish()
	var misses atomic.Uint64
	var seed atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := int(seed.Add(97))
		var local uint64
		for pb.Next() {
			if !s.MayContain(keys[i%len(keys)]) {
				local++
			}
			i++
		}
		misses.Add(local)
	})
	b.ReportMetric(float64(misses.Load())/float64(b.N), "miss/op")
}

// Read-only slow path: full owner-separated snapshot.
func BenchmarkPCLookupHit(b *testing.B) {
	s, o, keys := pcPopulated(b)
	defer o.Finish()
	var misses atomic.Uint64
	var seed atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := int(seed.Add(97))
		var snap Snapshot
		var local uint64
		for pb.Next() {
			if !s.Lookup(keys[i%len(keys)], &snap) || snap.Len() != 1 {
				local++
			}
			i++
		}
		misses.Add(local)
	})
	b.ReportMetric(float64(misses.Load())/float64(b.N), "miss/op")
}

// Same key looked up from every goroutine: all readers hit one shard RWMutex
// and one owner's lifecycleMu/rootsMu reader counters (cache-line bouncing).
func BenchmarkPCLookupSameKey(b *testing.B) {
	s, o, keys := pcPopulated(b)
	defer o.Finish()
	var misses atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var snap Snapshot
		var local uint64
		for pb.Next() {
			if !s.Lookup(keys[0], &snap) || snap.Len() != 1 {
				local++
			}
		}
		misses.Add(local)
	})
	b.ReportMetric(float64(misses.Load())/float64(b.N), "miss/op")
}

// Each goroutine is a separate request owner that re-derives 32 windows of its
// own root (update path of putWindow: shard write TryLock).
func BenchmarkPCDeriveOwnOwner(b *testing.B) {
	s := New()
	var fails, contention atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		o := pcAcquire(s)
		v, root, ok := o.TaintString("0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1)
		for !ok { // setup can itself lose a TryLock race against another owner
			setupRetries.Add(1)
			v, root, ok = o.TaintString("0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1)
		}
		var windows [32]Key
		for i := range windows {
			windows[i], _ = StringKey(v[i : i+8])
		}
		var local uint64
		i := 0
		for pb.Next() {
			if !o.Derive(windows[i%32], root) {
				local++
			}
			i++
		}
		fails.Add(local)
		contention.Add(o.Counters().Contention)
		o.Finish()
	})
	b.ReportMetric(float64(fails.Load())/float64(b.N), "fail/op")
	b.ReportMetric(float64(contention.Load())/float64(b.N), "contention/op")
}

// Each goroutine is a request: alternates a derive (write) and a gate+lookup
// (read) of a value it knows is tainted. A read miss is a silent false negative
// caused by another request holding the same shard.
func BenchmarkPCMixedReadWrite(b *testing.B) {
	s := New()
	var readMiss, writeFail, reads atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		o := pcAcquire(s)
		v, root, ok := o.TaintString("0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1)
		for !ok { // setup can itself lose a TryLock race against another owner
			setupRetries.Add(1)
			v, root, ok = o.TaintString("0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", 1)
		}
		var windows [32]Key
		for i := range windows {
			windows[i], _ = StringKey(v[i : i+8])
			for !o.Derive(windows[i], root) {
			}
		}
		var snap Snapshot
		var rm, wf, rd uint64
		i := 0
		for pb.Next() {
			k := windows[i%32]
			if i&1 == 0 {
				if !o.Derive(k, root) {
					wf++
				}
			} else {
				rd++
				if !s.MayContain(k) || !s.Lookup(k, &snap) || snap.Len() == 0 {
					rm++
				}
			}
			i++
		}
		readMiss.Add(rm)
		writeFail.Add(wf)
		reads.Add(rd)
		o.Finish()
	})
	b.ReportMetric(float64(readMiss.Load())/float64(max(reads.Load(), 1)), "readmiss/read")
	b.ReportMetric(float64(writeFail.Load())/float64(b.N), "writefail/op")
}

type pcLifecycleStats struct {
	acquireFail, sourceFail, deriveFail, lookupMiss, contention, truncated atomic.Uint64
}

var sink uint64

// pcWork is ~1us of deterministic CPU work standing in for a request handler.
func pcWork(p []byte) uint64 {
	h := uint64(14695981039346656037)
	for r := 0; r < 24; r++ {
		for i := range p {
			h ^= uint64(p[i]) + uint64(r)
			h *= 1099511628211
		}
	}
	return h
}

func pcLifecycle(b *testing.B, rangesPerRoot int) {
	s := New()
	var st pcLifecycleStats
	var seq atomic.Uint64
	var set ranges.Set
	value := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	if rangesPerRoot > 0 {
		raw := make([]ranges.Range, rangesPerRoot)
		for i := range raw {
			raw[i] = ranges.Range{Start: uint32(i * 3), Length: 2, SourceID: ranges.SourceID(i)}
		}
		if !ranges.AdoptCanonical(&set, ranges.Limit(64), raw, uint32(len(value))).Valid {
			b.Fatal("set")
		}
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var snap Snapshot
		buf := make([]byte, 0, 64)
		var sink uint64
		defer func() { _ = sink }()
		for pb.Next() {
			sink += pcWork(buf[:cap(buf)]) // simulated handler body, runs whether or not IAST admitted the request
			o := s.Acquire()
			if o.Disabled() {
				st.acquireFail.Add(1)
				continue
			}
			n := seq.Add(1)
			for j := 0; j < 8; j++ {
				var managed string
				var root RootRef
				var ok bool
				if rangesPerRoot > 0 {
					buf = append(buf[:0], value...)
					buf[0] = byte('a' + j)
					managed = string(buf)
					root, ok = o.AdoptString(managed, &set)
				} else {
					managed, _, root, ok = o.TaintSourceString(value[j:]+strconv.FormatUint(n, 10), "param", ranges.SourceID(j))
				}
				if !ok {
					st.sourceFail.Add(1)
					continue
				}
				sub, _ := StringKey(managed[1:9])
				if !o.Derive(sub, root) {
					st.deriveFail.Add(1)
				}
				if !s.MayContain(sub) || !s.Lookup(sub, &snap) || snap.Len() == 0 {
					st.lookupMiss.Add(1)
				}
			}
			c := o.Counters()
			st.contention.Add(c.Contention)
			st.truncated.Add(c.Ranges)
			o.Finish()
		}
	})
	n := float64(b.N)
	b.ReportMetric(float64(st.acquireFail.Load())/n, "acqfail/op")
	b.ReportMetric(float64(st.sourceFail.Load())/n, "srcfail/op")
	b.ReportMetric(float64(st.deriveFail.Load())/n, "derivefail/op")
	b.ReportMetric(float64(st.lookupMiss.Load())/n, "lookupmiss/op")
	b.ReportMetric(float64(st.contention.Load())/n, "contention/op")
	b.ReportMetric(float64(st.truncated.Load())/n, "rangetrunc/op")
}

// One op = one request: Acquire, 8 sources + derive + lookup, Finish.
func BenchmarkPCRequestLifecycle(b *testing.B) { pcLifecycle(b, 0) }

// Same with 20-range roots (DD_IAST_MAX_RANGE_COUNT>10) so every publish
// needs the global overflow allocator, which Finish holds for its whole loop.
func BenchmarkPCRequestLifecycleOverflow(b *testing.B) {
	old := config.MaxRangeCount
	config.MaxRangeCount = 64
	defer func() { config.MaxRangeCount = old }()
	pcLifecycle(b, 20)
}

// Serial Finish cost with one root: the global overflowMu is held across the
// full 512-root loop regardless of how many roots were used.
func BenchmarkPCFinishSerial(b *testing.B) {
	s := New()
	for b.Loop() {
		o := s.Acquire()
		o.TaintString("some-request-value", 1)
		o.Finish()
	}
}

// Serial cost of the critical section guarded by the global store.ownerMu
// (Acquire scans owners and clears 8 writer records incl. 8x1.5KiB range sets).
func BenchmarkPCAcquireFinishSerial(b *testing.B) {
	s := New()
	for b.Loop() {
		o := s.Acquire()
		o.Finish()
	}
}

func BenchmarkPCWorkUnit(b *testing.B) {
	buf := make([]byte, 64)
	for b.Loop() {
		sink += pcWork(buf)
	}
}

// Deterministic mechanism: while another request is inside Acquire (holding the
// global ownerMu), a new request is refused although all 64 owners are free.
// request.Manager.Acquire then releases its permit and the request runs
// without analysis (DecisionCapacityDropped).
func TestPCAcquireDroppedWithFreeCapacity(t *testing.T) {
	s := New()
	s.ownerMu.Lock() // stands in for a concurrent Acquire on another goroutine
	o := s.Acquire()
	s.ownerMu.Unlock()
	t.Logf("Acquire with 64 free owners while ownerMu held: disabled=%v acquireDrops=%d", o.Disabled(), s.AcquireDrops())
	if !o.Disabled() {
		t.Fatal("expected drop")
	}
	o = s.Acquire()
	if o.Disabled() {
		t.Fatal("retry should succeed")
	}
	o.Finish()
}

// Deterministic mechanism: while any other request's Finish holds the global
// overflowMu (owner.go:182-203, whole 512-root loop), a root with >10 ranges
// (DD_IAST_MAX_RANGE_COUNT>10) is published truncated to 10 ranges.
func TestPCOverflowTruncatedDuringOtherFinish(t *testing.T) {
	old := config.MaxRangeCount
	config.MaxRangeCount = 64
	defer func() { config.MaxRangeCount = old }()
	s := New()
	o := s.Acquire()
	defer o.Finish()
	value := string([]byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"))
	raw := make([]ranges.Range, 20)
	for i := range raw {
		raw[i] = ranges.Range{Start: uint32(i * 3), Length: 2, SourceID: ranges.SourceID(i)}
	}
	var set ranges.Set
	ranges.AdoptCanonical(&set, 64, raw, uint32(len(value)))
	s.overflowMu.Lock() // stands in for another request's Owner.Finish
	_, ok := o.AdoptString(value, &set)
	s.overflowMu.Unlock()
	key, _ := StringKey(value)
	var snap Snapshot
	s.Lookup(key, &snap)
	e, _ := snap.At(0)
	t.Logf("adopted=%v inputRanges=%d storedRanges=%d truncationDrops=%d", ok, set.Len(), e.Ranges.Len(), o.Counters().Ranges)
	if e.Ranges.Len() != GuaranteedRanges {
		t.Fatalf("expected truncation to %d", GuaranteedRanges)
	}
}

package request

// Review-only parallel contention benchmarks (perf-contention node).

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func pcAdmission(b *testing.B, max int) {
	m := NewManager(nil)
	var fails atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local uint64
		for pb.Next() {
			a, ok := m.Acquire(max)
			if !ok {
				local++
				continue
			}
			a.Finish()
		}
		fails.Add(local)
	})
	b.ReportMetric(float64(fails.Load())/float64(b.N), "fail/op")
	b.ReportMetric(float64(m.Store().AcquireDrops())/float64(b.N), "storeacqdrop/op")
}

// Permit (CAS bitset) + store owner (global ownerMu TryLock) + Finish.
// With max=64 >= GOMAXPROCS there is always a free permit and a free store
// owner, so every failure is pure lock contention on store.ownerMu.
func BenchmarkPCAdmissionMax64(b *testing.B) { pcAdmission(b, 64) }
func BenchmarkPCAdmissionMax16(b *testing.B) { pcAdmission(b, 16) }
func BenchmarkPCAdmissionMax2(b *testing.B)  { pcAdmission(b, 2) }

// Holding admission: each goroutine keeps its analysis for a short "request"
// body (8 sources + lookups) so admissions overlap with real work.
func BenchmarkPCBeginRequestFinish(b *testing.B)        { pcBeginRequestFinish(b, 64) }
func BenchmarkPCBeginRequestFinishDefault2(b *testing.B) { pcBeginRequestFinish(b, 2) }

func pcBeginRequestFinish(b *testing.B, maxConcurrent int) {
	oldE, oldS, oldM := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, maxConcurrent
	defer func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldE, oldS, oldM }()
	var dropped, admitted, taintFail, visitMiss, visits atomic.Uint64
	var seq atomic.Uint64
	before := defaultManager().Store().AcquireDrops()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ctx, scope, _ := Begin(context.Background())
			_ = ctx
			if scope.Decision() != DecisionActive {
				dropped.Add(1)
				scope.Finish()
				continue
			}
			admitted.Add(1)
			a, _ := scope.Analysis()
			n := strconv.FormatUint(seq.Add(1), 10)
			for j := 0; j < 8; j++ {
				v, ok := a.TaintString(constants.OriginHttpRequestParameter, "p"+strconv.Itoa(j), "value-"+n+"-"+strconv.Itoa(j))
				if !ok {
					taintFail.Add(1)
					continue
				}
				visits.Add(1)
				if !IsTaintedString(v) {
					visitMiss.Add(1)
				}
			}
			scope.Finish()
		}
	})
	nn := float64(b.N)
	b.ReportMetric(float64(dropped.Load())/nn, "capdrop/op")
	storeDrops := float64(defaultManager().Store().AcquireDrops() - before)
	b.ReportMetric(storeDrops/nn, "storeacqdrop/op")
	// Fraction of requests that won a permit (capacity available) but were then
	// dropped by the global store.ownerMu TryLock.
	b.ReportMetric(storeDrops/max(storeDrops+float64(admitted.Load()), 1), "storedrop/permitted")
	b.ReportMetric(float64(taintFail.Load())/nn, "taintfail/op")
	b.ReportMetric(float64(visitMiss.Load())/float64(max(visits.Load(), 1)), "visitmiss/visit")
}

// One request fanned out to all goroutines (handler spawning workers): half
// the goroutines add (duplicate) sources, half check a known tainted value.
// sourceMu TryLock failures make the check report "clean".
func BenchmarkPCIntraRequestSourceVsVisit(b *testing.B) {
	m := NewManager(nil)
	prev := processManager.Swap(m)
	defer processManager.Store(prev)
	a, ok := m.Acquire(1)
	if !ok {
		b.Fatal("acquire")
	}
	defer a.Finish()
	tainted, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "tainted-value-under-test")
	if !ok {
		b.Fatal("taint")
	}
	var role atomic.Uint64
	var misses, visits, addFails, adds atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		writer := role.Add(1)%2 == 0
		var miss, vis, af, ad uint64
		for pb.Next() {
			if writer {
				ad++
				if _, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "tainted-value-under-test"); !ok {
					af++
				}
			} else {
				vis++
				if !IsTaintedString(tainted) {
					miss++
				}
			}
		}
		misses.Add(miss)
		visits.Add(vis)
		addFails.Add(af)
		adds.Add(ad)
	})
	b.ReportMetric(float64(misses.Load())/float64(max(visits.Load(), 1)), "visitmiss/visit")
	b.ReportMetric(float64(addFails.Load())/float64(max(adds.Load(), 1)), "addfail/add")
}

// Several goroutines of ONE request check the same tainted value concurrently
// (e.g. parallel sinks after an errgroup fan-out). copySources takes the
// exclusive sourceMu with TryLock, so concurrent readers make each other miss.
func BenchmarkPCIntraRequestVisitOnly(b *testing.B) {
	m := NewManager(nil)
	prev := processManager.Swap(m)
	defer processManager.Store(prev)
	a, ok := m.Acquire(1)
	if !ok {
		b.Fatal("acquire")
	}
	defer a.Finish()
	tainted, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "tainted-value-under-test")
	if !ok {
		b.Fatal("taint")
	}
	var misses atomic.Uint64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var miss uint64
		for pb.Next() {
			if !IsTaintedString(tainted) {
				miss++
			}
		}
		misses.Add(miss)
	})
	b.ReportMetric(float64(misses.Load())/float64(b.N), "visitmiss/visit")
}

// Deterministic mechanism: while one reader of the same request holds
// sourceMu (as copySources does for every visit), a concurrent IsTainted /
// VisitString of a tainted value reports clean.
func TestPCConcurrentVisitorSeesClean(t *testing.T) {
	m := NewManager(nil)
	prev := processManager.Swap(m)
	defer processManager.Store(prev)
	a, ok := m.Acquire(1)
	if !ok {
		t.Fatal("acquire")
	}
	defer a.Finish()
	tainted, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "tainted-value-under-test")
	if !ok || !IsTaintedString(tainted) {
		t.Fatal("setup")
	}
	a.slot.sourceMu.Lock() // stands in for a concurrent copySources on another goroutine
	got := IsTaintedString(tainted)
	a.slot.sourceMu.Unlock()
	t.Logf("IsTaintedString(tainted) while a concurrent visitor holds sourceMu = %v (after release: %v)", got, IsTaintedString(tainted))
	if got {
		t.Fatal("expected a miss")
	}
}


// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// The benchmarks in this file measure source-root admission. Each iteration
// uses a new store. The foreground workload runs on top of a background load,
// and the benchmark reports the percentage of foreground roots that the store
// admits, with the refusals split by drop counter.

const (
	admissionPerOwner = 500 // below MaxRootsPerOwner, so the owner quota never refuses
	backgroundRoots   = 100 // sparse load
	stressedRoots     = 2500
	stressedWorkers   = 8
	retentionCycles   = 10_000
	collideRoots      = 100
)

type admissionAPI uint8

const (
	apiTaintString admissionAPI = iota
	apiTaintBytes
	apiTaintSourceString
	apiTaintSourceBytes
	apiAdoptSourceBytes
)

var admissionAPIs = [...]struct {
	name string
	api  admissionAPI
}{
	{"TaintString", apiTaintString},
	{"TaintBytes", apiTaintBytes},
	{"TaintSourceString", apiTaintSourceString},
	{"TaintSourceBytes", apiTaintSourceBytes},
	{"AdoptSourceBytes", apiAdoptSourceBytes},
}

type admissionTally struct {
	attempted  int
	admitted   int
	full       uint64
	bytes      uint64
	contention uint64
	fanout     uint64
	indexFull  uint64
	other      uint64
	entries    int // index entries in use after the workload, summed over iterations
}

// recordOccupancy adds the index entries in use now.
func (t *admissionTally) recordOccupancy(s *Store) {
	entries, _ := benchOccupancy(s)
	t.entries += entries
}

func (t *admissionTally) addCounters(before, after Counters, refused int) {
	full := after.Full - before.Full
	bytes := after.Bytes - before.Bytes
	contention := after.Contention - before.Contention
	fanout := after.Fanout - before.Fanout
	indexFull := benchIndexFull(after) - benchIndexFull(before)
	t.indexFull += indexFull
	t.full += full
	t.bytes += bytes
	t.contention += contention
	t.fanout += fanout
	if known := full + bytes + contention + fanout + indexFull; uint64(refused) > known {
		t.other += uint64(refused) - known
	}
}

func (t *admissionTally) report(b *testing.B, iterations int) {
	if t.attempted == 0 {
		return
	}
	b.ReportMetric(100*float64(t.admitted)/float64(t.attempted), "admitted%")
	n := float64(iterations)
	b.ReportMetric(float64(t.attempted)/n, "attempted/op")
	b.ReportMetric(float64(t.full)/n, "drop-full/op")
	b.ReportMetric(float64(t.bytes)/n, "drop-bytes/op")
	b.ReportMetric(float64(t.contention)/n, "drop-contention/op")
	b.ReportMetric(float64(t.fanout)/n, "drop-fanout/op")
	b.ReportMetric(float64(t.indexFull)/n, "drop-indexFull/op")
	b.ReportMetric(float64(t.entries)/n, "index-entries")
	b.ReportMetric(100*float64(t.entries)/n/benchCapacity, "occupancy%")
	b.ReportMetric(float64(t.other)/n, "drop-other/op")
}

// admitOne publishes one source root through api and reports success.
func admitOne(owner *Owner, api admissionAPI, value []byte) bool {
	switch api {
	case apiTaintString:
		_, _, ok := owner.TaintString(unsafe.String(unsafe.SliceData(value), len(value)), 1)
		return ok
	case apiTaintBytes:
		_, _, ok := owner.TaintBytes(value, 1)
		return ok
	case apiTaintSourceString:
		_, _, _, ok := owner.TaintSourceString(unsafe.String(unsafe.SliceData(value), len(value)), "n", 1)
		return ok
	case apiTaintSourceBytes:
		_, _, _, _, ok := owner.TaintSourceBytes(value, "n", 1)
		return ok
	case apiAdoptSourceBytes:
		_, _, _, ok := owner.AdoptSourceBytes(value, "n", 1)
		return ok
	}
	return false
}

// admissionValues returns count values of size bytes. For AdoptSourceBytes,
// every value is a new allocation, because adoption requires the allocation base.
func admissionValues(count, size int) [][]byte {
	values := make([][]byte, count)
	for i := range values {
		value := make([]byte, size)
		for j := range value {
			value[j] = byte('a' + (i+j)%26)
		}
		values[i] = value
	}
	return values
}

// runForeground publishes values over new owners with at most
// admissionPerOwner roots each, and adds the result to tally. It returns the
// owners so that the caller can finish them.
func runForeground(s *Store, api admissionAPI, values [][]byte, tally *admissionTally) []*Owner {
	var owners []*Owner
	for start := 0; start < len(values); start += admissionPerOwner {
		owner := acquireRetry(s)
		if owner.Disabled() {
			tally.attempted += len(values) - start
			tally.other += uint64(len(values) - start)
			break
		}
		owners = append(owners, owner)
		before := owner.Counters()
		end := min(start+admissionPerOwner, len(values))
		admitted := 0
		for _, value := range values[start:end] {
			if admitOne(owner, api, value) {
				admitted++
			}
		}
		tally.attempted += end - start
		tally.admitted += admitted
		tally.addCounters(before, owner.Counters(), end-start-admitted)
	}
	return owners
}

// acquireRetry acquires an owner. It retries when the owner table lock is
// contended, because the benchmark measures root admission, not owner
// acquisition. It gives up when the owner table is full.
func acquireRetry(s *Store) *Owner {
	for range 10_000 {
		owner := s.Acquire()
		if !owner.Disabled() {
			return owner
		}
		runtime.Gosched()
	}
	return s.Acquire()
}

// loadBackground publishes roots of size bytes with TaintString over new owners.
func loadBackground(s *Store, roots, size int) []*Owner {
	var owners []*Owner
	value := strings.Repeat("b", size)
	for remaining := roots; remaining > 0; {
		owner := acquireRetry(s)
		if owner.Disabled() {
			break
		}
		owners = append(owners, owner)
		for i := 0; i < min(remaining, admissionPerOwner); i++ {
			owner.TaintString(value, 1)
		}
		remaining -= admissionPerOwner
	}
	return owners
}

func finishAll(owners []*Owner) {
	for _, owner := range owners {
		owner.Finish()
	}
}

// startChurn starts workers that publish and finish owners until stop is closed.
func startChurn(s *Store, workers int) (stop func()) {
	var done atomic.Bool
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			value := strings.Repeat("c", 24)
			for !done.Load() {
				owner := s.Acquire()
				for range 50 {
					owner.TaintString(value, 1)
				}
				owner.Finish()
			}
		})
	}
	return func() {
		done.Store(true)
		group.Wait()
	}
}

type admissionWorkload struct {
	name   string
	count  int
	size   int
	values func(count, size int) [][]byte
}

var admissionWorkloads = [...]admissionWorkload{
	{name: "params1000", count: 1000, size: 12, values: admissionValues},
	{name: "dense256", count: 1000, size: 256, values: admissionValues},
	{name: "span257", count: 1000, size: 257, values: admissionValues},
}

func BenchmarkSourceAdmission(b *testing.B) {
	for _, workload := range admissionWorkloads {
		for _, api := range admissionAPIs {
			b.Run(fmt.Sprintf("%s/sparse/%s", workload.name, api.name), func(b *testing.B) {
				var tally admissionTally
				for b.Loop() {
					s := New()
					background := loadBackground(s, backgroundRoots, 32)
					values := workload.values(workload.count, workload.size)
					owners := runForeground(s, api.api, values, &tally)
					tally.recordOccupancy(s)
					finishAll(owners)
					finishAll(background)
				}
				tally.report(b, b.N)
			})
			b.Run(fmt.Sprintf("%s/stressed/%s", workload.name, api.name), func(b *testing.B) {
				var tally admissionTally
				for b.Loop() {
					s := New()
					background := loadBackground(s, stressedRoots, 32)
					values := workload.values(workload.count, workload.size)
					stop := startChurn(s, stressedWorkers)
					owners := runForeground(s, api.api, values, &tally)
					stop()
					tally.recordOccupancy(s)
					finishAll(owners)
					finishAll(background)
				}
				tally.report(b, b.N)
			})
			b.Run(fmt.Sprintf("%s/saturated/%s", workload.name, api.name), func(b *testing.B) {
				var tally admissionTally
				for b.Loop() {
					s := New()
					var owners []*Owner
					// Repeat the workload until the owner table or the byte quotas stop it.
					for range MaxOwners * MaxRootsPerOwner / workload.count {
						values := workload.values(workload.count, workload.size)
						owners = append(owners, runForeground(s, api.api, values, &tally)...)
					}
					tally.recordOccupancy(s)
					finishAll(owners)
				}
				tally.report(b, b.N)
			})
		}
	}
	for _, load := range [...]string{"sparse", "stressed", "saturated"} {
		b.Run("collide/"+load+"/AdoptSourceBytes", func(b *testing.B) {
			var tally admissionTally
			for b.Loop() {
				s := New()
				var background []*Owner
				var stop func()
				count := collideRoots
				switch load {
				case "sparse":
					background = loadBackground(s, backgroundRoots, 32)
				case "stressed":
					background = loadBackground(s, stressedRoots, 32)
					stop = startChurn(s, stressedWorkers)
				case "saturated":
					count = 1000
				}
				values := collidingValues(count)
				owners := runForeground(s, apiAdoptSourceBytes, values, &tally)
				if stop != nil {
					stop()
				}
				tally.recordOccupancy(s)
				finishAll(owners)
				finishAll(background)
			}
			tally.report(b, b.N)
		})
	}
	b.Run("retention/sparse/TaintString", func(b *testing.B) {
		var tally admissionTally
		for b.Loop() {
			s := New()
			value := strings.Repeat("r", 32)
			for range retentionCycles {
				owner := s.Acquire()
				for range 10 {
					owner.TaintString(value, 1)
				}
				owner.Finish()
			}
			background := loadBackground(s, backgroundRoots, 32)
			values := admissionValues(1000, 12)
			owners := runForeground(s, apiTaintString, values, &tally)
			tally.recordOccupancy(s)
			finishAll(owners)
			finishAll(background)
		}
		tally.report(b, b.N)
	})
}

// collidingValues returns count new 64-byte allocations whose tier S granule
// key maps to index shard 0 (roots whose granule keys collide in one shard).
// Each value is a complete allocation, so the adoption contract holds. A
// 64-byte allocation uses exactly one 64-byte granule.
func collidingValues(count int) [][]byte {
	values := make([][]byte, 0, count)
	for len(values) < count {
		value := make([]byte, 64)
		if benchIndexShard(uintptr(unsafe.Pointer(unsafe.SliceData(value)))) != 0 {
			continue
		}
		for i := range value {
			value[i] = 'x'
		}
		values = append(values, value)
	}
	return values
}

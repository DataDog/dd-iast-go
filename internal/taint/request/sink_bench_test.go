// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// BenchmarkSinkCheck measures the sink check path (IsTaintedString) under three
// store loads. The loads are the same as in the store lookup benchmarks: sparse
// (100 roots of 64 bytes), typical (2 500 roots of 64 bytes) and full (62
// owners of 512 roots of 128 bytes, which fill the index or the base value
// table). The benchmark reports the index occupancy and the filter hit rate.
// IsTaintedString gives the same answer on the base store and on the interior
// store.
func BenchmarkSinkCheck(b *testing.B) {
	loads := [...]struct {
		name  string
		roots int
		size  int
	}{{"sparse", 100, 64}, {"typical", 2500, 64}, {"full", 62 * store.MaxRootsPerOwner, 128}}
	for _, load := range loads {
		manager := NewManager(nil)
		previous := processManager.Swap(manager)
		analysis, ok := manager.Acquire(1)
		if !ok {
			b.Fatal("no analysis")
		}
		tainted, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "name", strings.Repeat("v", 64))
		if !ok {
			b.Fatal("not tainted")
		}
		window := tainted[3:20]
		if !benchPublishWindow(manager.store, tainted, window) {
			b.Fatal("the window is not published")
		}
		var owners []*store.Owner
		roots := 0
		for remaining := load.roots; remaining > 0; remaining -= store.MaxRootsPerOwner {
			owner := manager.store.Acquire()
			if owner.Disabled() {
				break
			}
			owners = append(owners, owner)
			for range min(remaining, store.MaxRootsPerOwner) {
				if _, _, ok := owner.TaintString(strings.Repeat("t", load.size), 1); ok {
					roots++
				}
			}
		}
		clean := make([]string, 4096)
		for i := range clean {
			clean[i] = strings.Clone(strings.Repeat("k", 64))
		}
		entries := benchOccupancy(manager.store)
		// rates computes the diagnostic rates in a separate pass, before the
		// timed loop, so the timed loop runs exactly one IsTaintedString.
		rates := func(values []string) (hitRate, probes float64) {
			hits, total := 0, 0
			for _, value := range values {
				key, _ := store.StringKey(value)
				if manager.store.MayContain(key) {
					hits++
				}
				total += benchProbes(manager.store, key)
			}
			return 100 * float64(hits) / float64(len(values)), float64(total) / float64(len(values))
		}
		report := func(b *testing.B, hitRate, probes float64) {
			b.ReportMetric(float64(roots), "roots")
			b.ReportMetric(float64(entries), "index-entries")
			b.ReportMetric(100*float64(entries)/benchCapacity, "occupancy%")
			b.ReportMetric(hitRate, "filter-hit%")
			b.ReportMetric(probes, "probes/op")
		}
		b.Run("clean/"+load.name, func(b *testing.B) {
			hitRate, probes := rates(clean)
			i := 0
			for b.Loop() {
				if IsTaintedString(clean[i%len(clean)]) {
					b.Fatal("clean value is tainted")
				}
				i++
			}
			report(b, hitRate, probes)
		})
		for _, c := range []struct{ name, value string }{{"tainted", tainted}, {"tainted-window", window}} {
			b.Run(c.name+"/"+load.name, func(b *testing.B) {
				hitRate, probes := rates([]string{c.value})
				for b.Loop() {
					if !IsTaintedString(c.value) {
						b.Fatal("tainted value is clean")
					}
				}
				report(b, hitRate, probes)
			})
		}
		for _, owner := range owners {
			owner.Finish()
		}
		analysis.Finish()
		processManager.Store(previous)
	}
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge/bridgetest"
)

// BenchmarkRuntimePre measures the pre-check of the runtime bridge with direct
// calls (no weaving), on the store that the bridge uses, under the three index
// loads of lookup_bench_test.go (plan section 9.2). It is the complete bridge
// path of a clean operand: the filter check, and on a filter hit the call to
// Confirm with its panic guard. The woven hook adds its entry cost (the gate
// check and the call), which BenchmarkRuntimeClean of iast/runtime measures.
//
//   - one-clean-hit: one clean operand that is a filter hit (a neighbor
//     allocation in the granule of a root);
//   - one-miss: one clean operand that is a filter miss;
//   - concat2-clean-hit: two clean operands that are both filter hits, in
//     the granules of two different roots (plan section 9.3: "2-operand
//     stack concat, full index, both operands can hit");
//   - concat2-clean-random: two random clean operands.
//
// The names are RuntimePre/<load>/<case>.
func BenchmarkRuntimePre(b *testing.B) {
	s := runtimeBound()
	if s == nil {
		b.Skip("the runtime bridge is bound to another store")
	}
	// The benchmarks do not count bridge entries, as in production.
	previous := runtimebridge.CountEntries(false)
	b.Cleanup(func() { runtimebridge.CountEntries(previous) })
	for _, load := range lookupLoads {
		b.Run(load.name, func(b *testing.B) {
			loaded := newLoadedStoreIn(b, s, load)
			neighbor := loaded.neighborValue
			// clean has one more value at the end, so that the last random
			// pair is in the slice.
			n := len(loaded.cleanValues)
			clean := append(append([]string(nil), loaded.cleanValues...), loaded.cleanValues[0])
			miss := loaded.missValues
			other, _ := StringKey(loaded.otherNeighborValue)
			hitRate, _ := loaded.rates([]Key{loaded.neighbor, other})
			if hitRate != 100 {
				b.Fatal("a neighbor is not a filter hit")
			}
			pair := []string{neighbor, loaded.otherNeighborValue}
			cases := []struct {
				name string
				f    func(i int) bool
			}{
				{"one-clean-hit", func(int) bool { return bridgetest.StrPre(neighbor) }},
				{"one-miss", func(i int) bool { return bridgetest.StrPre(miss[i%len(miss)]) }},
				{"concat2-clean-hit", func(int) bool { return bridgetest.ConcatPre(pair) }},
				{"concat2-clean-random", func(i int) bool {
					return bridgetest.ConcatPre(clean[i%n : i%n+2])
				}},
			}
			for _, c := range cases {
				b.Run(c.name, func(b *testing.B) {
					if c.name == "one-miss" && len(miss) == 0 {
						b.Skip("no filter miss key")
					}
					i := 0
					for b.Loop() {
						if c.f(i) {
							b.Fatalf("%s: a clean operand is reported as tainted", c.name)
						}
						i++
					}
					loaded.report(b)
				})
			}
		})
	}
}

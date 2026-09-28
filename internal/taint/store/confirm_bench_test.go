// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"fmt"
	"testing"
)

// BenchmarkConfirm measures the store part of the runtime pre-check (plan
// section 3.2.1): the filter check, then Confirm on a filter hit. The base
// store has no Confirm, so these rows have no baseline.
func BenchmarkConfirm(b *testing.B) {
	for _, load := range lookupLoads {
		loaded := newLoadedStore(b, load)
		for _, c := range []struct {
			name string
			keys []Key
			want ConfirmResult
		}{
			{"clean-random", loaded.clean, ConfirmClean},
			{"clean-neighbor", []Key{loaded.neighbor}, ConfirmClean},
			{"tainted-root", []Key{loaded.tainted}, ConfirmTainted},
			{"tainted-window", []Key{loaded.window}, ConfirmTainted},
		} {
			b.Run(fmt.Sprintf("%s/%s", c.name, load.name), func(b *testing.B) {
				hitRate, probes := loaded.rates(c.keys)
				i := 0
				for b.Loop() {
					key := c.keys[i%len(c.keys)]
					if loaded.store.MayContain(key) {
						if loaded.store.Confirm(key.Pointer, key.Length) != c.want {
							b.Fatal("unexpected Confirm result")
						}
					} else if c.want != ConfirmClean {
						b.Fatal("filter miss on a tainted value")
					}
					i++
				}
				loaded.report(b)
				b.ReportMetric(hitRate, "filter-hit%")
				b.ReportMetric(probes, "probes/op")
			})
		}
		for _, operands := range []int{2, 6} {
			b.Run(fmt.Sprintf("precheck-%d-clean/%s", operands, load.name), func(b *testing.B) {
				hitRate, probes := loaded.rates(loaded.clean)
				i := 0
				for b.Loop() {
					for range operands {
						key := loaded.clean[i%len(loaded.clean)]
						if loaded.store.MayContain(key) && loaded.store.Confirm(key.Pointer, key.Length) != ConfirmClean {
							b.Fatal("clean value is not clean")
						}
						i++
					}
				}
				loaded.report(b)
				b.ReportMetric(hitRate, "filter-hit%")
				// Each iteration checks all operands.
				b.ReportMetric(probes*float64(operands), "probes/op")
			})
		}
	}
}

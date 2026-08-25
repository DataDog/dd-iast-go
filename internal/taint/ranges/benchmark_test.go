// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func BenchmarkCanonicalizeTwo(b *testing.B) {
	raw := []ranges.Range{
		{Start: 4, Length: 4, SourceID: 0},
		{Start: 2, Length: 8, SourceID: 1},
	}
	var dst ranges.Set
	b.ReportAllocs()
	for b.Loop() {
		ranges.Canonicalize(&dst, 10, raw, 10)
	}
}

func BenchmarkConcatTwo(b *testing.B) {
	left := benchmarkSet(b, []ranges.Range{{Length: 8, SourceID: 0}}, 8)
	right := benchmarkSet(b, []ranges.Range{{Length: 8, SourceID: 1}}, 8)
	var dst ranges.Set
	b.ReportAllocs()
	for b.Loop() {
		ranges.Concat(&dst, 10, &left, 8, &right, 8)
	}
}

func BenchmarkSliceTwo(b *testing.B) {
	set := benchmarkSet(b, []ranges.Range{
		{Length: 4, SourceID: 0},
		{Start: 4, Length: 4, SourceID: 1},
	}, 8)
	var dst ranges.Set
	b.ReportAllocs()
	for b.Loop() {
		ranges.Slice(&dst, 10, &set, 8, 1, 7)
	}
}

func BenchmarkConcatFreshGoroutine(b *testing.B) {
	left := benchmarkSet(b, []ranges.Range{{Length: 8, SourceID: 0}}, 8)
	right := benchmarkSet(b, []ranges.Range{{Length: 8, SourceID: 1}}, 8)
	b.ReportAllocs()
	for b.Loop() {
		done := make(chan struct{})
		go func() {
			var dst ranges.Set
			ranges.Concat(&dst, 10, &left, 8, &right, 8)
			close(done)
		}()
		<-done
	}
}

func benchmarkSet(tb testing.TB, raw []ranges.Range, valueLen uint32) ranges.Set {
	tb.Helper()
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, 10, raw, valueLen).Valid {
		tb.Fatal("benchmark setup failed")
	}
	return set
}

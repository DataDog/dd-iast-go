// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

//go:noinline
func heapString(n int) string { return strings.Repeat("x", n) }

// BenchmarkAny measures the quick check. Plan section 7.1 adds the other
// cases (step 10).
func BenchmarkAny(b *testing.B) {
	if !heapbits.Enabled() {
		b.Skip("feature is not enabled")
	}
	for _, size := range []int{16, 256, 4096} {
		clean, tainted := heapString(size), heapString(size)
		heapbits.SetString(tainted[size/2 : size/2+1]) // middle byte
		b.Run(fmt.Sprintf("clean/%d", size), func(b *testing.B) {
			for b.Loop() {
				if heapbits.AnyString(clean) {
					b.Fatal("clean value reported as tainted")
				}
			}
		})
		b.Run(fmt.Sprintf("tainted-middle/%d", size), func(b *testing.B) {
			for b.Loop() {
				if !heapbits.AnyString(tainted) {
					b.Fatal("tainted value reported as clean")
				}
			}
		})
	}
	b.Run("stack", func(b *testing.B) {
		var local [64]byte
		for b.Loop() {
			heapbits.AnyBytes(local[:])
		}
	})
}

// BenchmarkSet measures the cost of tainting.
func BenchmarkSet(b *testing.B) {
	if !heapbits.Enabled() {
		b.Skip("feature is not enabled")
	}
	for _, size := range []int{16, 256, 4096} {
		x := heapBytes(size)
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			for b.Loop() {
				heapbits.SetBytes(x)
			}
		})
	}
}

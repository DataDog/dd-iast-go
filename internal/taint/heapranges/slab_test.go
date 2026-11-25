// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSlabAllocatorBudget(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit uint64
		want  uint64
	}{
		{"zero", 0, 0},
		{"partial slab", slabSize - 1, 0},
		{"one slab", slabSize + 17, slabSize},
		{"maximum", slabSize*maxSlabs + slabSize, slabSize * maxSlabs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := newSlabAllocator(tc.limit).limit; got != tc.want {
				t.Fatalf("limit = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSlabAllocatorConcurrentLimit(t *testing.T) {
	const capacity = 8
	a := newSlabAllocator(capacity * slabSize)
	var maps, accounts, successes atomic.Uint64
	a.mapFn = func() ([]byte, bool) {
		maps.Add(1)
		return []byte{1}, true
	}
	a.account = func() { accounts.Add(1) }
	var group sync.WaitGroup
	for i := 0; i < 64; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, ok := a.allocate(); ok {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != capacity || maps.Load() != capacity || accounts.Load() != capacity {
		t.Fatalf("successes = %d, maps = %d, accounts = %d; want %d each", successes.Load(), maps.Load(), accounts.Load(), capacity)
	}
	if got := a.mapped.Load(); got != capacity*slabSize {
		t.Fatalf("mapped = %d, want %d", got, capacity*slabSize)
	}
}

func TestSlabAllocatorFailure(t *testing.T) {
	a := newSlabAllocator(slabSize)
	var maps, accounts int
	a.mapFn = func() ([]byte, bool) {
		maps++
		return nil, false
	}
	a.account = func() { accounts++ }
	if _, ok := a.allocate(); ok {
		t.Fatal("failed mapping reported success")
	}
	if got := a.reserved.Load(); got != 0 {
		t.Fatalf("reserved = %d after failure", got)
	}
	if got := a.mapped.Load(); got != 0 || accounts != 0 {
		t.Fatalf("mapped = %d, accounts = %d after failure", got, accounts)
	}
	a.mapFn = func() ([]byte, bool) {
		maps++
		return []byte{1}, true
	}
	if _, ok := a.allocate(); !ok || maps != 2 || accounts != 1 {
		t.Fatalf("retry: success = %t, maps = %d, accounts = %d", ok, maps, accounts)
	}
}

func TestSlabAllocatorRequiresAccounting(t *testing.T) {
	a := newSlabAllocator(slabSize)
	a.account = nil
	a.mapFn = func() ([]byte, bool) {
		t.Error("mapped without accounting")
		return nil, false
	}
	if _, ok := a.allocate(); ok || a.reserved.Load() != 0 {
		t.Fatal("mapping without runtime accounting succeeded")
	}
}

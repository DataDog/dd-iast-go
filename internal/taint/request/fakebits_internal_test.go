// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"
)

// fakeBits is a bitStore for the unit tests: one bool for each tainted
// address. The tests keep the values alive, so that an address is not
// reused while the test runs.
type fakeBits struct {
	mu sync.Mutex
	// +checklocks:mu
	tainted map[uintptr]bool
	// refuse is called by set; when it returns true, set fails (read-only
	// or stack memory in the real runtime).
	refuse func(p, n uintptr) bool
}

func (f *fakeBits) set(p, n uintptr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n == 0 || (f.refuse != nil && f.refuse(p, n)) {
		return false
	}
	for i := uintptr(0); i < n; i++ {
		f.tainted[p+i] = true
	}
	return true
}

func (f *fakeBits) any(p, n uintptr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := uintptr(0); i < n; i++ {
		if f.tainted[p+i] {
			return true
		}
	}
	return false
}

func (f *fakeBits) next(p, n, from uintptr) uintptr {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := from; i < n; i++ {
		if f.tainted[p+i] {
			return i
		}
	}
	return n
}

func (f *fakeBits) nextClean(p, n, from uintptr) uintptr {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := from; i < n; i++ {
		if !f.tainted[p+i] {
			return i
		}
	}
	return n
}

// clear removes the taint of b.
func (f *fakeBits) clear(b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	for i := range uintptr(len(b)) {
		delete(f.tainted, p+i)
	}
}

// copyBits copies the bits of src to dst (len(src) bytes), as the runtime
// hooks do.
func (f *fakeBits) copyBits(dst, src []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := uintptr(unsafe.Pointer(unsafe.SliceData(dst)))
	s := uintptr(unsafe.Pointer(unsafe.SliceData(src)))
	for i := range uintptr(len(src)) {
		if f.tainted[s+i] {
			f.tainted[d+i] = true
		} else {
			delete(f.tainted, d+i)
		}
	}
}

// useFakeBits replaces the heap bits with a fake for the test.
func useFakeBits(t *testing.T) *fakeBits {
	t.Helper()
	f := &fakeBits{tainted: map[uintptr]bool{}}
	previous := testBits
	testBits = f
	t.Cleanup(func() { testBits = previous })
	return f
}

// concat returns a heap copy of the parts with their bits, as the runtime
// concatenation hook does.
func (f *fakeBits) concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	escapeSink.Store(&out)
	for _, p := range parts {
		start := len(out)
		out = out[:start+len(p)]
		copy(out[start:], p)
		f.copyBits(out[start:], p)
	}
	return out
}

// escapeSink makes a value escape to the heap: the fake bits are keyed by
// address, and a stack value moves when the stack grows (the real runtime
// refuses to taint stack memory).
var escapeSink atomic.Pointer[[]byte]

// heapBytes returns a heap copy of s, with no bits.
func heapBytes(s string) []byte {
	b := make([]byte, len(s))
	copy(b, s)
	escapeSink.Store(&b)
	return b
}

// heapString returns a heap copy of s, with no bits.
func heapString(s string) string {
	b := heapBytes(s)
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func bytesOf(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func unsafeData(b []byte) unsafe.Pointer { return unsafe.Pointer(unsafe.SliceData(b)) }

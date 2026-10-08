// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package bench_test

import (
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// The tests of this package need a woven runtime. Run them with:
//
//	go tool orchestrion go test ./iast/runtime/internal/bench
//
// An unwoven run skips them. With DD_IAST_REQUIRE_WOVEN=1, an unwoven run
// fails. Do not import package heapbits/heapbitstest here (see
// TestNoTestKnobs).

const requireWovenEnv = "DD_IAST_REQUIRE_WOVEN"

// Symbols of the woven runtime. They are nil (or 0) without weaving.
var (
	// rtStats returns the number of wrapper calls (tainted paths). It counts
	// only when the test knobs are on, but the symbol exists in each woven
	// runtime.
	//
	//go:linkname rtStats __dd_iast_runtime.stats
	rtStats func() uint64

	// s2sOff is the string-to-slice switch (1 = off). Only atomic accesses.
	//
	//go:linkname s2sOff __dd_iast_propbridge.s2soff
	s2sOff uint32

	// testKnobs is __dd_taint_testing of the woven runtime: true only when
	// the program links package heapbits/heapbitstest.
	//
	//go:linkname testKnobs __dd_iast_heapbits_testing.enabled
	testKnobs bool
)

// setStringToSlice sets the string-to-slice switch, and returns its old value.
func setStringToSlice(on bool) bool {
	v := uint32(1)
	if on {
		v = 0
	}
	return atomic.SwapUint32(&s2sOff, v) == 0
}

// Sinks keep results live and make them escape to the heap.
var (
	sinkString string
	sinkBytes  []byte
	sinkRunes  []rune
	sinkInt    int
)

// escapeBytes and escapeRunes make the memory of the helpers escape to the
// heap.
var (
	escapeBytes atomic.Pointer[byte]
	escapeRunes atomic.Pointer[rune]
)

// requireWoven skips t when the runtime is not woven, or fails t when
// DD_IAST_REQUIRE_WOVEN=1. It does not use the entry counter (it counts only
// with the test knobs on): it checks that a concatenation propagates.
func requireWoven(t testing.TB) {
	t.Helper()
	skip := func(reason string) {
		t.Helper()
		if os.Getenv(requireWovenEnv) == "1" {
			t.Fatalf("%s=1: %s", requireWovenEnv, reason)
		}
		t.Skip(reason + ": use `go tool orchestrion go test` to run this test")
	}
	if !built.WithOrchestrion {
		skip("the test is not built with Orchestrion")
	}
	if !heapbits.Enabled() {
		skip("the heap taint bits are not enabled (not woven, or platform not supported)")
	}
	if rtStats == nil {
		skip("the runtime hooks of iast/runtime are not woven")
	}
	value := heapString("woven-probe")
	require.True(t, heapbits.SetString(value))
	if !heapbits.AnyString(heapConcat2("x", value)) {
		t.Fatal("the runtime hooks are woven, but a concatenation of a tainted value did not propagate")
	}
}

// TestNoTestKnobs checks that this test binary does not link package
// heapbits/heapbitstest: the test knobs of the woven runtime are off, as in
// a production program.
func TestNoTestKnobs(t *testing.T) {
	requireWoven(t)
	require.False(t, testKnobs, "the test knobs are on: a dependency of this package links heapbits/heapbitstest")
}

// stackOps returns the 6 stack operations of TestAllocs, with the inputs.
func stackOps(s string, b []byte, r []rune) map[string]func() {
	return map[string]func(){
		"concat":            func() { sinkInt = stackConcatLen("x", s) },
		"concatbytes":       func() { sinkInt = stackConcatBytesLen("x", s) },
		"slicebytetostring": func() { sinkInt = stackB2SLen(b) },
		"stringtoslicebyte": func() { sinkInt = stackS2BLen(s) },
		"slicerunetostring": func() { sinkInt = stackR2SLen(r) },
		"stringtoslicerune": func() { sinkInt = stackS2RLen(s) },
	}
}

// TestAllocs checks the allocation gates with the gate on, in the binary of
// the benchmarks (.github/runtime-bench.sh runs it in each hook binary): clean
// stack operations do not allocate, and a tainted stack operation allocates
// only its forced heap result. iast/runtime has the same test, with the test
// knobs on.
func TestAllocs(t *testing.T) {
	requireWoven(t)
	require.True(t, heapbits.Live())
	x, s := "x", heapString("short-value")
	b, r := heapBytes("short-bytes"), heapRunes("short runes")
	for name, f := range stackOps(s, b, r) {
		require.Zero(t, testing.AllocsPerRun(200, f), "gate on, clean, stack %s", name)
	}
	long := strings.Repeat("h", 40)
	require.Equal(t, 1.0, testing.AllocsPerRun(200, func() { sinkString = heapConcat2(x, long) }), "gate on, clean, heap concat")

	ts := heapString("short-value")
	tb := heapBytes("short-bytes")
	tr := heapRunes("short runes")
	require.True(t, heapbits.SetString(ts))
	require.True(t, heapbits.SetBytes(tb))
	require.True(t, heapbits.Set(unsafe.Pointer(unsafe.SliceData(tr)), uintptr(4*len(tr))))
	for name, f := range stackOps(ts, tb, tr) {
		require.Equal(t, 1.0, testing.AllocsPerRun(200, f), "gate on, tainted, stack %s", name)
	}
	tl := heapString(long)
	require.True(t, heapbits.SetString(tl))
	require.Equal(t, 1.0, testing.AllocsPerRun(200, func() { sinkString = heapConcat2(x, tl) }), "gate on, tainted, heap concat")
}

// heapString returns a new heap string with the bytes of s. It does not use a
// hooked runtime function.
//
//go:noinline
func heapString(s string) string {
	b := make([]byte, len(s))
	copy(b, s)
	escapeBytes.Store(unsafe.SliceData(b))
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// heapBytes returns a new heap []byte with the bytes of s, without a runtime
// conversion.
//
//go:noinline
func heapBytes(s string) []byte {
	out := make([]byte, len(s))
	copy(out, s)
	escapeBytes.Store(unsafe.SliceData(out))
	return out
}

// heapRunes returns a new heap []rune with the runes of value. It does not use
// a runtime conversion.
//
//go:noinline
func heapRunes(value string) []rune {
	n := 0
	for range value {
		n++
	}
	out := make([]rune, n)
	i := 0
	for _, r := range value {
		out[i] = r
		i++
	}
	escapeRunes.Store(unsafe.SliceData(out))
	return out
}

// The operations of the benchmarks and of TestAllocs (the same as in the
// tests of iast/runtime). Each one is //go:noinline, so the compiler cannot
// fold it into the caller or change its escape result.

//go:noinline
func heapConcat2(a, b string) string { return a + b }

//go:noinline
func heapB2S(b []byte) string { return string(b) }

//go:noinline
func heapS2B(s string) []byte { return []byte(s) }

//go:noinline
func heapR2S(r []rune) string { return string(r) }

//go:noinline
func heapS2R(s string) []rune { return []rune(s) }

// heapGrow appends one byte to b (len(b) == cap(b)): growslice copies the
// old elements to a new heap array.
//
//go:noinline
func heapGrow(b []byte) []byte { return append(b[:len(b):len(b)], '!') }

// Stack operations that return only a length, for testing.AllocsPerRun.

//go:noinline
func stackConcatLen(a, b string) int { s := a + b; return len(s) }

//go:noinline
func stackConcatBytesLen(a, b string) int { s := []byte(a + b); s[0] ^= 0; return len(s) }

//go:noinline
func stackB2SLen(b []byte) int { s := string(b); return len(s) }

//go:noinline
func stackS2BLen(s string) int { b := []byte(s); b[0] ^= 0; return len(b) }

//go:noinline
func stackR2SLen(r []rune) int { s := string(r); return len(s) }

//go:noinline
func stackS2RLen(s string) int { r := []rune(s); return len(r) }

// stackBufGrowLen appends n bytes to a slice with a stack backing store
// (growsliceBuf), and returns the length only.
//
//go:noinline
func stackBufGrowLen(n int) int {
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, byte(i))
		sinkInt += cap(out)
	}
	return len(out)
}

// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/stretchr/testify/require"
)

// TestStackResults checks the stack case of each operation: a clean result
// stays on the stack and is not tainted; a tainted result goes to the heap and
// is tainted (decision S1 of allocator-taint-bits.md). TestAllocs checks that
// the clean results stay on the stack.
func TestStackResults(t *testing.T) {
	requireWoven(t)
	s := taintString(t, "short-value")
	b := taintBytes(t, "short-bytes")
	r := taintRunes(t, "short runes", 0, 11)
	clean, cleanB, cleanR := heapString("clean-value"), heapBytes("clean-bytes"), heapRunes("clean runes")
	tainted := probe{tainted: true}
	stack := probe{}
	for name, test := range map[string][2]probe{
		"concat":            {stackConcat("x", clean), stackConcat("x", s)},
		"concatbytes":       {stackConcatBytes("x", clean), stackConcatBytes("x", s)},
		"slicebytetostring": {stackB2S(cleanB), stackB2S(b)},
		"stringtoslicebyte": {stackS2B(clean), stackS2B(s)},
		"slicerunetostring": {stackR2S(cleanR), stackR2S(r)},
		"stringtoslicerune": {stackS2R(clean), stackS2R(s)},
	} {
		require.Equal(t, stack, test[0], "%s: a clean result stays on the stack", name)
		require.Equal(t, tainted, test[1], "%s: a tainted result goes to the heap", name)
	}

	// Mixed operands: only the tainted part of the forced heap result is
	// tainted.
	const prefix = "pfx-"
	k := len(prefix)
	value := taintString(t, "tnt")
	mixed := heapConcat2(prefix, value)
	mixedBytes := heapS2B(mixed)
	mixedRunes := heapS2R(mixed)
	want := split{head: false, tail: true}
	for name, got := range map[string]split{
		"concat":            stackConcatSplit(prefix, value),
		"concatbytes":       stackConcatBytesSplit(prefix, value),
		"slicebytetostring": stackB2SSplit(mixedBytes, k),
		"stringtoslicebyte": stackS2BSplit(mixed, k),
		"slicerunetostring": stackR2SSplit(mixedRunes, k),
		"stringtoslicerune": stackS2RSplit(mixed, k),
	} {
		require.Equal(t, want, got, "%s: the result is on the heap and has the taint of the tail only", name)
	}
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

// TestAllocs checks the allocation gates with the gate on (TestGateOff checks
// them with the gate off): clean stack operations do not allocate, and a
// tainted stack operation allocates only its forced heap result.
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

	ts := taintString(t, "short-value")
	tb := taintBytes(t, "short-bytes")
	tr := taintRunes(t, "short runes", 0, 11)
	for name, f := range stackOps(ts, tb, tr) {
		require.Equal(t, 1.0, testing.AllocsPerRun(200, f), "gate on, tainted, stack %s", name)
	}
	tl := taintString(t, long)
	require.Equal(t, 1.0, testing.AllocsPerRun(200, func() { sinkString = heapConcat2(x, tl) }), "gate on, tainted, heap concat")
}

// TestGateOff checks, in a fresh process (the gate is sticky), that the hooks
// do nothing before the first taint: no wrapper call, no allocation in the
// stack operations, and no taint. After the first taint, the hooks work.
func TestGateOff(t *testing.T) {
	if os.Getenv(childEnv) != "gateoff" {
		requireWoven(t)
		runChild(t, "^TestGateOff$", "gateoff")
		return
	}
	if rtStats == nil || !heapbits.Enabled() {
		t.Fatal("the child is not woven")
	}
	if heapbits.Live() {
		t.Fatal("the gate is on at the start of a fresh process")
	}
	x, s := "x", heapString("short-value")
	b, r := heapBytes("short-bytes"), heapRunes("short runes")
	for name, f := range stackOps(s, b, r) {
		require.Zero(t, testing.AllocsPerRun(200, f), "gate off, stack %s", name)
	}
	// The stack backing store of append (growsliceBuf) depends on the
	// compiler flags (not with -race or -N): compare with the gate on below.
	growOff := testing.AllocsPerRun(200, func() { sinkInt = stackBufGrowLen(20) })
	long := strings.Repeat("h", 40)
	require.Equal(t, 1.0, testing.AllocsPerRun(200, func() { sinkString = heapConcat2(x, long) }), "gate off, heap concat")
	require.Zero(t, entries())
	require.False(t, heapbits.Live())

	// The first taint turns the gate on.
	value := heapString("attack")
	require.True(t, heapbits.SetString(value))
	require.True(t, heapbits.Live())
	require.Equal(t, []span{{1, 7}}, stringSpans(heapConcat2("x", value)))
	require.NotZero(t, entries())
	require.Equal(t, growOff, testing.AllocsPerRun(200, func() { sinkInt = stackBufGrowLen(20) }), "gate on, clean growsliceBuf")
}

// grow uses about depth frames of stack, so that the goroutine stack grows
// and moves.
//
//go:noinline
func grow(depth int) int {
	var pad [64]byte
	pad[0] = byte(depth)
	if depth == 0 {
		return int(pad[0])
	}
	return grow(depth-1) + int(pad[0])
}

// TestStackGrowth checks that a stack move between a stack operand and the
// hook does not matter: the stack operands are never tainted, and the heap
// operands do not move. The results survive two garbage collections.
func TestStackGrowth(t *testing.T) {
	requireWoven(t)
	value := taintString(t, "tnt")
	done := make(chan []span)
	go func() {
		// A new goroutine has a small stack: the recursion moves it.
		var buf [8]byte
		copy(buf[:], "stack-op")
		local := unsafe.String(&buf[0], 8)
		sinkInt = grow(10)
		r := heapConcat3(local, value, local)
		sinkInt = grow(2000)
		runtime.GC()
		runtime.GC()
		done <- stringSpans(r)
	}()
	require.Equal(t, []span{{8, 11}}, <-done)
}

// TestHeapRetention checks that a tainted result keeps its taint after two
// garbage collections.
func TestHeapRetention(t *testing.T) {
	requireWoven(t)
	value := taintString(t, "attack")
	result := heapConcat2(strings.Repeat("p", 40), value)
	runtime.GC()
	runtime.GC()
	require.Equal(t, strings.Repeat("p", 40)+"attack", result)
	require.Equal(t, []span{{40, 46}}, stringSpans(result))
}

// TestAddressReuse checks that a new clean allocation at the address of a
// dead tainted result is not tainted (the sweep hook of heapbits clears the
// bits of dead objects).
func TestAddressReuse(t *testing.T) {
	requireWoven(t)
	func() {
		value := taintString(t, "attack")
		for range 100 {
			sinkString = heapConcat2(strings.Repeat("p", 26), value)
		}
	}()
	sinkString = ""
	runtime.GC()
	runtime.GC()
	for range 10000 {
		s := heapConcat2(strings.Repeat("p", 26), "attack")
		require.Empty(t, stringSpans(s))
	}
}

// nilString returns a string of n bytes with a nil data pointer. A copy from
// it faults, and the runtime converts the fault into a recoverable panic.
func nilString(n int) string {
	header := struct {
		data unsafe.Pointer
		n    int
	}{nil, n}
	return *(*string)(unsafe.Pointer(&header))
}

//go:noinline
func faultingConcat(a, b string) (recovered bool) {
	defer func() { recovered = recover() != nil }()
	sinkInt = stackConcatLen(a, b)
	return false
}

// TestBypassTokenAfterPanic checks that a panic in the original body (after
// the inner entry read the token) does not keep a token: the next operations
// on the goroutine enter the hook.
func TestBypassTokenAfterPanic(t *testing.T) {
	requireWoven(t)
	s := taintString(t, "short-value")
	before := entries()
	require.True(t, faultingConcat(s, nilString(8)), "the copy from a nil pointer must panic")
	require.Equal(t, before+1, entries(), "the faulting concat entered the wrapper")
	first := stackConcat("x", s)
	second := stackConcat("x", s)
	require.Equal(t, before+3, entries())
	require.True(t, first.tainted)
	require.True(t, second.tainted)
}

// TestBypassTokenSequence checks that 1000 mixed operations on one goroutine
// all enter the hooks: no operation loses the token.
func TestBypassTokenSequence(t *testing.T) {
	requireWoven(t)
	s := taintString(t, "short-value")
	b := taintBytes(t, "short-bytes")
	r := taintRunes(t, "short runes", 0, 11)
	ops := []func() probe{
		func() probe { return stackConcat("x", s) },
		func() probe { return stackConcatBytes("x", s) },
		func() probe { return stackB2S(b) },
		func() probe { return stackS2B(s) },
		func() probe { return stackR2S(r) },
		func() probe { return stackS2R(s) },
		func() probe { return probe{len(bytesSpans(heapGrow(b))) == 1} },
	}
	before := entries()
	for i := range 1001 {
		if p := ops[i%len(ops)](); !p.tainted {
			t.Fatalf("operation %d: the result is not tainted", i%len(ops))
		}
	}
	require.Equal(t, uint64(1001), entries()-before)
}

// TestPointerElements checks that growslice does not copy taint bits for an
// element type with pointers, and that it copies the bits of other element
// types.
func TestPointerElements(t *testing.T) {
	requireWoven(t)
	words := make([]uint32, 5)
	sinkUint32 = words
	require.True(t, taintBytesNoLeak(uintptr(unsafe.Pointer(&words[1])), 8))
	grown := heapGrowUint32(words)
	require.Len(t, grown, 6)
	require.Equal(t, []span{{4, 12}}, bitSpans(unsafe.Pointer(&grown[0]), 24))

	strs := []string{"a", "b"}
	sinkAny = strs
	require.True(t, taintBytesNoLeak(uintptr(unsafe.Pointer(&strs[0])), int(2*unsafe.Sizeof(""))))
	before := entries()
	got := heapGrowStrings(strs)
	require.Equal(t, before, entries(), "no wrapper call for elements with pointers")
	require.Empty(t, bitSpans(unsafe.Pointer(&got[0]), int(3*unsafe.Sizeof(""))))
}

var sinkAny any

// TestGrowsliceConcurrent appends to tainted slices on many goroutines.
func TestGrowsliceConcurrent(t *testing.T) {
	requireWoven(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				b := taintBytes(t, "0123456789")
				for range 5 {
					b = heapGrow(b)
				}
				if got := bytesSpans(b); len(got) != 1 || got[0] != (span{0, 10}) {
					t.Errorf("grown slice: %v", got)
					return
				}
			}
		})
	}
	wg.Wait()
}

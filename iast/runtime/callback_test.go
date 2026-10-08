// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/stretchr/testify/require"
)

// runeCall is one call of the rune callback.
type runeCall struct {
	out, outLen, in, inLen uintptr
	kind                   uint8
	outSpans               []span // taint of the output at the time of the call
}

// recordRunes installs a rune callback that records its calls (and runs
// extra in the callback). It returns the record. The test cleanup restores
// the previous callback.
func recordRunes(t *testing.T, extra func()) *[]runeCall {
	t.Helper()
	calls := new([]runeCall)
	previous := setRuneCallback(func(out, outLen, in, inLen uintptr, kind uint8) {
		*calls = append(*calls, runeCall{out, outLen, in, inLen, kind, bitSpans(*(*unsafe.Pointer)(unsafe.Pointer(&out)), int(outLen))})
		if extra != nil {
			extra()
		}
	})
	t.Cleanup(func() { setRuneCallback(previous) })
	return calls
}

// TestRuneCallback checks the contract of the rune callback of propbridge
// (plan section 5.1): it is called only on the tainted path of []rune(s)
// (kind 1) and string(runes) (kind 2), after the bits are copied, with the
// addresses and the lengths in bytes of the output and of the input.
func TestRuneCallback(t *testing.T) {
	requireWoven(t)
	calls := recordRunes(t, nil)
	value := taintStringRange(t, "héllo", 1, 3)

	runes := heapS2R(value)
	require.Len(t, *calls, 1)
	require.Equal(t, runeCall{runesData(runes), 20, stringData(value), 6, 1, []span{{4, 8}}}, (*calls)[0])

	back := heapR2S(runes)
	require.Len(t, *calls, 2)
	require.Equal(t, runeCall{stringData(back), 6, runesData(runes), 20, 2, []span{{1, 3}}}, (*calls)[1])

	// Clean inputs: no call.
	sinkRunes = heapS2R(heapString("clean"))
	sinkString = heapR2S(heapRunes("clean"))
	sinkString = heapConcat2("x", value)
	sinkBytes = heapS2B(value)
	require.Len(t, *calls, 2)

	// The string-to-slice switch is off: no hook, so no call for []rune(s).
	previous := setStringToSlice(false)
	sinkRunes = heapS2R(value)
	setStringToSlice(previous)
	require.Len(t, *calls, 2)

	// No callback (propbridge is not linked): the bits are copied.
	setRuneCallback(nil)
	require.Equal(t, []span{{4, 8}}, runeSpans(heapS2R(value)))
}

// TestRuneCallbackGuard checks that the hooks do nothing while the rune
// callback runs (the guard __dd_iast_in_hook), also on a stack that grows in
// the callback, and that the hooks work again after it.
func TestRuneCallbackGuard(t *testing.T) {
	requireWoven(t)
	value := taintString(t, "tainted")
	var nested []span
	var inner uint64
	calls := recordRunes(t, func() {
		before := entries()
		s := heapConcat2("nested:", value)
		b := heapS2B(s)
		r := heapS2R(string(b))
		sinkString = heapR2S(r)
		nested = stringSpans(s)
		inner = entries() - before
		sinkInt = grow(2000)
	})
	result := heapS2R(value)
	require.Len(t, *calls, 1)
	require.Zero(t, inner, "no hook runs in the callback")
	require.Empty(t, nested, "no propagation in the callback")
	runtime.GC()
	require.Equal(t, []span{{0, 28}}, runeSpans(result))
	require.Equal(t, []span{{7, 14}}, stringSpans(heapConcat2("nested:", value)), "the guard is clear after the callback")
}

// TestPropbridgeGuard checks the re-entry guard that the runtime gives to
// package propbridge: one guard for each goroutine.
func TestPropbridgeGuard(t *testing.T) {
	requireWoven(t)
	require.NotNil(t, rtGuard)
	require.True(t, rtGuard(true), "enter")
	require.False(t, rtGuard(true), "the guard is set")
	done := make(chan bool)
	go func() {
		ok := rtGuard(true)
		rtGuard(false)
		done <- ok
	}()
	require.True(t, <-done, "another goroutine has its own guard")
	require.True(t, rtGuard(false), "leave")
	require.True(t, rtGuard(true), "enter again")
	require.True(t, rtGuard(false))
	// The analysis guard does not stop the runtime hooks.
	value := taintString(t, "attack")
	rtGuard(true)
	got := heapConcat2("x", value)
	rtGuard(false)
	require.Equal(t, []span{{1, 7}}, stringSpans(got))
}

// earlyInit is the result of the hooks in an init function, before main.
var earlyInit struct {
	ran   bool
	spans []span
	runes []span
}

// runEarlyInit runs in the init function of the test package.
func runEarlyInit() {
	v := heapString("init-value")
	if !heapbits.SetString(v) {
		return // not woven
	}
	earlyInit.ran = true
	earlyInit.spans = stringSpans(heapConcat2("early:", v))
	earlyInit.runes = runeSpans(heapS2R(v))
}

// TestEarlyInit checks, in a child process, that the hooks work in an init
// function (before main).
func TestEarlyInit(t *testing.T) {
	if os.Getenv(childEnv) != "earlyinit" {
		requireWoven(t)
		runChild(t, "^TestEarlyInit$", "earlyinit")
		return
	}
	require.True(t, earlyInit.ran)
	require.Equal(t, []span{{6, 16}}, earlyInit.spans)
	require.Equal(t, []span{{0, 40}}, earlyInit.runes)
}

// TestLongRanges checks inputs longer than the fast path of the bit check
// (about 1 KiB) and longer than one bit chunk (128 KiB).
func TestLongRanges(t *testing.T) {
	requireWoven(t)
	for _, n := range []int{1 << 10, 4 << 10, 200 << 10} {
		value := taintStringRange(t, strings.Repeat("v", n), n-3, n)
		got := heapConcat2("x", value)
		require.Equal(t, []span{{n - 2, n + 1}}, stringSpans(got), "%d bytes", n)
		require.Equal(t, []span{{n - 3, n}}, bytesSpans(heapS2B(value)), "%d bytes", n)
	}
}

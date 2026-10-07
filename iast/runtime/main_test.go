// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	_ "github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest" // test knobs and the entry counter
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// These tests need a woven runtime (the aspects of this package and of
// internal/taint/heapbits). Run them with:
//
//	go tool orchestrion go test ./iast/runtime/...
//
// An unwoven run skips them. With DD_IAST_REQUIRE_WOVEN=1, an unwoven run
// fails.

const requireWovenEnv = "DD_IAST_REQUIRE_WOVEN"

// childEnv is set in the child processes of the tests that need a fresh
// process (the sticky gate is still 0 there).
const childEnv = "IAST_RUNTIME_CHILD"

func init() {
	switch os.Getenv(childEnv) {
	case "":
		// The tests taint much more memory than an application. The budget
		// must be set before the first taint. Do not taint here. (The
		// benchmarks of the hooks are in package internal/bench: this
		// package links heapbitstest, which turns on the test knobs.)
		heapbits.SetBudget(heapbits.MaxBudget)
	case "earlyinit":
		runEarlyInit()
	}
}

// Symbols of the woven runtime (iast/runtime/orchestrion.yml). They are nil
// (or 0) without weaving.
var (
	// rtStats returns the number of wrapper calls (tainted paths).
	//
	//go:linkname rtStats __dd_iast_runtime.stats
	rtStats func() uint64

	// rtGuard is the re-entry guard of package propbridge.
	//
	//go:linkname rtGuard __dd_iast_propbridge.guard
	rtGuard func(enter bool) bool

	// s2sOff is the string-to-slice switch (1 = off). Only atomic accesses.
	//
	//go:linkname s2sOff __dd_iast_propbridge.s2soff
	s2sOff uint32

	// runeDerived is the rune callback. The tests store their own callback
	// with an atomic pointer store (see setRuneCallback).
	//
	//go:linkname runeDerived __dd_iast_propbridge.runederived
	runeDerived func(out, outLen, in, inLen uintptr, kind uint8)
)

// entries returns the number of wrapper calls of the hooks.
func entries() uint64 {
	if rtStats == nil {
		return 0
	}
	return rtStats()
}

// setRuneCallback stores f as the rune callback and returns the old value.
func setRuneCallback(f func(out, outLen, in, inLen uintptr, kind uint8)) func(out, outLen, in, inLen uintptr, kind uint8) {
	var p unsafe.Pointer
	if f != nil {
		p = *(*unsafe.Pointer)(unsafe.Pointer(&f))
	}
	old := atomic.SwapPointer((*unsafe.Pointer)(unsafe.Pointer(&runeDerived)), p)
	return *(*func(out, outLen, in, inLen uintptr, kind uint8))(unsafe.Pointer(&old))
}

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
	sinkUint32 []uint32
)

// escapeBytes and escapeRunes make the memory of the helpers escape to the
// heap (atomic: the helpers run on many goroutines).
var (
	escapeBytes atomic.Pointer[byte]
	escapeRunes atomic.Pointer[rune]
)

// wovenChecked is true after one check found a woven runtime.
var wovenChecked bool

// requireWoven skips t when the runtime is not woven, or fails t when
// DD_IAST_REQUIRE_WOVEN=1.
func requireWoven(t testing.TB) {
	t.Helper()
	if wovenChecked {
		return
	}
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
	value := taintString(t, "woven-probe")
	before := entries()
	got := heapConcat2("x", value)
	if entries() == before || len(stringSpans(got)) == 0 {
		t.Fatal("the runtime hooks are woven, but a concatenation of a tainted value did not propagate")
	}
	wovenChecked = true
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

// taintString returns a heap copy of s with all its bytes tainted.
func taintString(t testing.TB, s string) string {
	t.Helper()
	v := heapString(s)
	require.True(t, heapbits.SetString(v), "taint %q", s)
	return v
}

// taintStringRange returns a heap copy of s with the bytes [lo, hi) tainted.
func taintStringRange(t testing.TB, s string, lo, hi int) string {
	t.Helper()
	v := heapString(s)
	require.True(t, heapbits.Set(unsafe.Add(unsafe.Pointer(unsafe.StringData(v)), lo), uintptr(hi-lo)))
	return v
}

// taintBytes returns a heap copy of s with all its bytes tainted.
func taintBytes(t testing.TB, s string) []byte {
	t.Helper()
	v := heapBytes(s)
	require.True(t, heapbits.SetBytes(v))
	return v
}

// taintRunes returns a heap []rune of s with the runes [from, to) tainted.
func taintRunes(t testing.TB, s string, from, to int) []rune {
	t.Helper()
	v := heapRunes(s)
	require.True(t, heapbits.Set(unsafe.Pointer(&v[from]), uintptr(4*(to-from))))
	return v
}

// span is a tainted interval [Start, End) of a value, in bytes.
type span struct{ Start, End int }

func (s span) String() string { return fmt.Sprintf("[%d,%d)", s.Start, s.End) }

// bitSpans returns the tainted intervals of the n bytes at p.
func bitSpans(p unsafe.Pointer, n int) []span {
	var out []span
	m := uintptr(n)
	for off := heapbits.Next(p, m, 0); off < m; {
		end := heapbits.NextClean(p, m, off)
		out = append(out, span{int(off), int(end)})
		off = heapbits.Next(p, m, end)
	}
	return out
}

func stringSpans(s string) []span {
	return bitSpans(unsafe.Pointer(unsafe.StringData(s)), len(s))
}

func bytesSpans(b []byte) []span {
	return bitSpans(unsafe.Pointer(unsafe.SliceData(b)), len(b))
}

// runeSpans returns the tainted intervals of a []rune, in bytes of the rune
// array (4 bytes for each rune).
func runeSpans(r []rune) []span {
	return bitSpans(unsafe.Pointer(unsafe.SliceData(r)), 4*len(r))
}

func stringData(s string) uintptr { return uintptr(unsafe.Pointer(unsafe.StringData(s))) }

func bytesData(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

func runesData(r []rune) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(r))) }

// anyTainted reports whether one of the n bytes at p is tainted. It takes a
// uintptr, so the value does not escape.
func anyTainted(p uintptr, n int) bool {
	if n <= 0 {
		return false
	}
	return heapbits.Any(*(*unsafe.Pointer)(unsafe.Pointer(&p)), uintptr(n))
}

// taintBytesNoLeak taints the n bytes at p. It takes a uintptr, so the value
// does not escape.
func taintBytesNoLeak(p uintptr, n int) bool {
	return heapbits.Set(*(*unsafe.Pointer)(unsafe.Pointer(&p)), uintptr(n))
}

// probe is the result of an operation whose result stays in the function.
type probe struct {
	tainted bool
}

// runChild runs the tests that match pattern in a child process of this test
// binary, with childEnv=mode, and returns its output. It fails t when the
// child fails.
func runChild(t *testing.T, pattern, mode string) string {
	t.Helper()
	args := []string{"-test.run=" + pattern, "-test.v", "-test.count=1"}
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), childEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child %s:\n%s", mode, out)
	require.Contains(t, string(out), "--- PASS", "child %s ran no test:\n%s", mode, out)
	return string(out)
}

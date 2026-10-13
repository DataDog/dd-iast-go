// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build iast_g0test

// This test pulls runtime.systemstack, runtime.acquirem and runtime.releasem
// with test-only //go:linkname directives. The linker refuses these pulls by
// default, so the test has a build tag, and it runs only with
// -ldflags=-checklinkname=0:
//
//	go tool orchestrion go test -tags iast_g0test -ldflags=-checklinkname=0 ./iast/runtime/internal/g0test

// Package g0test_test checks that the runtime hooks do not run, and do not add
// a frame with a stack check, when a hooked function runs on the system stack
// (g0), and that they do not run while the M holds a runtime lock.
//
// The wrapper __dd_iast_<fn> and the filters are normal functions, with a
// stack check at entry. On g0 (and gsignal) a failed stack check calls
// morestack, and morestack on g0 or gsignal is fatal. Thus the prepended code
// must call the //go:nosplit __dd_iast_ok() BEFORE it calls a filter or a
// wrapper, and run the original body directly when the context is not safe.
//
// User code never runs on g0 or gsignal: os/signal handlers run on a normal
// goroutine, and no public API runs a user function on the system stack. This
// test thus pulls runtime.systemstack with a test-only //go:linkname.
//
// Method (subprocess, the test binary runs itself again):
//  0. With the gate on, at depth 0: the operations on tainted heap inputs do
//     not enter a wrapper on g0 and while the M holds a lock (the entry
//     counter does not change, and the results are not tainted), and they do
//     on a normal goroutine (control). With -race, the g0 part runs on stack
//     inputs only (the race functions of the runtime must not see a heap
//     address on g0).
//  1. Calibration: with the gate off (no taint in the child), find the largest
//     recursion depth D on g0 at which the hooked operations still run (depth
//     D+1 crashes with "morestack on g0"). At depth D the free g0 stack is
//     less than one recursion frame.
//  2. With the gate on (the child taints a value), run the same operations at
//     depth D. The gate-on path adds no frame with a stack check (only the
//     nosplit __dd_iast_ok), so the child exits 0. Steps 1 and 2 need a
//     stable edge; else (darwin) only step 0 applies.
//
// Negative control: with the context check only in the wrapper, step 2 enters
// a filter on g0, and the child crashes with "morestack on g0".
package g0test_test

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	_ "github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest" // the entry counter
)

// systemstack runs fn on the g0 stack of the current M (test only).
//
//go:linkname systemstack runtime.systemstack
//go:noescape
func systemstack(fn func())

// acquirem increments the lock count of the current M (test only).
//
//go:linkname acquirem runtime.acquirem
func acquirem() unsafe.Pointer

//go:linkname releasem runtime.releasem
func releasem(mp unsafe.Pointer)

// rtStats returns the number of wrapper calls of the hooks (tainted paths).
//
//go:linkname rtStats __dd_iast_runtime.stats
var rtStats func() uint64

func entries() uint64 {
	if rtStats == nil {
		return 0
	}
	return rtStats()
}

const childEnv = "DD_IAST_G0_CHILD" // "<gate 0|1>,<depth>"

func init() {
	if os.Getenv(childEnv) != "" {
		// Keep the main goroutine on m0, so the child work runs on a
		// thread that is not m0. All non-main threads have the same g0
		// layout; the g0 of m0 can have a random offset (cgo, -race).
		runtime.LockOSThread()
	}
}

func TestMain(m *testing.M) {
	if v := os.Getenv(childEnv); v != "" {
		os.Exit(child(v))
	}
	if v := os.Getenv(mStateEnv); v != "" {
		os.Exit(mStateChild(v))
	}
	os.Exit(m.Run())
}

// ---- the work: the hooked operations, with results in a stack buffer ----

//go:norace
//go:noinline
func opConcat(a, b string) int { s := a + b; return len(s) }

//go:norace
//go:noinline
func opConcatBytes(a, b string) int { s := []byte(a + b); s[0] ^= 0; return len(s) }

//go:norace
//go:noinline
func opB2S(b []byte) int { s := string(b); return len(s) }

//go:norace
//go:noinline
func opS2B(s string) int { b := []byte(s); b[0] ^= 0; return len(b) }

//go:norace
//go:noinline
func opR2S(r []rune) int { s := string(r); return len(s) }

//go:norace
//go:noinline
func opS2R(s string) int { r := []rune(s); return len(r) }

//go:norace
//go:noinline
func opGrow(b []byte) int { g := append(b[:len(b):len(b)], 1); return len(g) }

// work runs the hooked operations on inputs in the current stack (g0 in the
// child), so -race does not instrument them (racecalladdr skips addresses
// outside the heap and the data segments).
//
//go:norace
//go:noinline
func work() int {
	var bb [12]byte
	var rr [11]rune
	for i := range bb {
		bb[i] = 'a' + byte(i)
	}
	for i := range rr {
		rr[i] = 'k' + rune(i)
	}
	return opConcat("g0-left-", "g0-right") +
		opConcatBytes("g0-left-", "g0-right") +
		opB2S(bb[:]) +
		opS2B("g0-s2b-12ch") +
		opR2S(rr[:]) +
		opS2R("g0-s2r-11c") +
		opGrow(bb[:])
}

// Tainted heap inputs (gate on only).
var (
	taintedS string
	taintedB []byte
	taintedR []rune
	results  struct {
		s string
		b []byte
		r []rune
		g []byte
	}
)

// heapWork runs the hooked operations on the tainted heap inputs, and keeps
// the heap results. It returns true when one result is tainted.
//
//go:norace
//go:noinline
func heapWork() bool {
	results.s = "x" + taintedS
	results.b = []byte(taintedS)
	results.r = []rune(taintedS)
	results.s = results.s + string(taintedB) + string(taintedR)
	results.g = append(taintedB[:len(taintedB):len(taintedB)], 1)
	return heapbits.AnyString(results.s) || heapbits.AnyBytes(results.b) || heapbits.AnyBytes(results.g) ||
		heapbits.Any(unsafe.Pointer(unsafe.SliceData(results.r)), uintptr(4*len(results.r)))
}

var depth int

// burn uses depth frames of g0 stack, then runs work.
//
//go:norace
//go:noinline
func burn(n int) int {
	if n > 0 {
		return burn(n-1) + 1
	}
	return work()
}

var (
	g0Result  int
	g0Tainted bool
)

//go:norace
func onG0() { g0Result = burn(depth) }

//go:norace
func onG0Heap() { g0Tainted = heapWork() }

// heapString returns a heap copy of s.
//
//go:noinline
func heapString(s string) string {
	b := make([]byte, len(s))
	copy(b, s)
	results.b = b
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func child(v string) int {
	gate, d, ok := strings.Cut(v, ",")
	n, err := strconv.Atoi(d)
	if !ok || err != nil {
		fmt.Println("bad", childEnv, v)
		return 3
	}
	depth = n
	if gate == "1" {
		taintedS = heapString("g0-tainted-value")
		taintedB = []byte(heapString("g0-tainted-bytes"))
		taintedR = make([]rune, 8)
		for i := range taintedR {
			taintedR[i] = 'r'
		}
		if !heapbits.SetString(taintedS) || !heapbits.SetBytes(taintedB) || !heapbits.Set(unsafe.Pointer(&taintedR[0]), 32) || !heapbits.Live() {
			fmt.Println("cannot taint")
			return 3
		}
	}
	type report struct {
		g0, user, locked uint64
		g0Tainted        bool
		userTainted      bool
		lockedTainted    bool
	}
	done := make(chan report)
	go func() {
		// Not m0: the main goroutine is locked to m0 (init).
		runtime.LockOSThread()
		var r report
		e0 := entries()
		systemstack(onG0)
		if gate == "1" && !raceEnabled {
			systemstack(onG0Heap)
		}
		e1 := entries()
		r.g0, r.g0Tainted = e1-e0, g0Tainted
		mp := acquirem()
		r.lockedTainted = gate == "1" && heapWork()
		releasem(mp)
		e2 := entries()
		r.locked = e2 - e1
		_ = work()
		r.userTainted = gate == "1" && heapWork() // control on a normal goroutine
		r.user = entries() - e2
		done <- r
	}()
	r := <-done
	fmt.Printf("CHILD-OK gate=%s depth=%d g0-entries=%d locked-entries=%d user-entries=%d g0-tainted=%t locked-tainted=%t user-tainted=%t\n",
		gate, depth, r.g0, r.locked, r.user, r.g0Tainted, r.lockedTainted, r.userTainted)
	return 0
}

type result struct {
	ok                     bool
	g0, locked, user       uint64
	g0Tainted, lockTainted bool
	userTainted            bool
	out                    string
	morestackG0            bool
}

func runChild(t *testing.T, gate, depth int) result {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d,%d", childEnv, gate, depth), "GOTRACEBACK=single")
	b, err := cmd.CombinedOutput()
	r := result{out: string(b), morestackG0: strings.Contains(string(b), "morestack on g0")}
	if err != nil {
		return r
	}
	for _, line := range strings.Split(r.out, "\n") {
		if strings.HasPrefix(line, "CHILD-OK ") {
			var g, d int
			if _, e := fmt.Sscanf(line, "CHILD-OK gate=%d depth=%d g0-entries=%d locked-entries=%d user-entries=%d g0-tainted=%t locked-tainted=%t user-tainted=%t",
				&g, &d, &r.g0, &r.locked, &r.user, &r.g0Tainted, &r.lockTainted, &r.userTainted); e == nil {
				r.ok = true
			}
		}
	}
	return r
}

// wantUserEntries is the smallest number of wrapper calls of heapWork: "x"+s,
// []byte(s), []rune(s), string(runes), the concatenation of 3 tainted
// operands, and append (string(b) as an operand of a concatenation is an alias
// of b: no call).
const wantUserEntries = 6

func TestSystemStackSkipsHook(t *testing.T) {
	// Woven check (and the normal-goroutine control) at depth 0.
	r := runChild(t, 1, 0)
	if !r.ok {
		if strings.Contains(r.out, "cannot taint") {
			if os.Getenv("DD_IAST_REQUIRE_WOVEN") == "1" {
				t.Fatalf("runtime is not woven (DD_IAST_REQUIRE_WOVEN=1):\n%s", r.out)
			}
			t.Skip("runtime is not woven: use `go tool orchestrion go test`")
		}
		t.Fatalf("child (gate on, depth 0) failed:\n%s", r.out)
	}
	if r.user < wantUserEntries || !r.userTainted {
		t.Fatalf("depth 0: the control on a normal goroutine did not enter the hooks: user-entries=%d (want >= %d), tainted=%t", r.user, wantUserEntries, r.userTainted)
	}
	if r.g0 != 0 || r.g0Tainted {
		t.Fatalf("depth 0: hook called on g0 (%d entries, tainted result: %t)", r.g0, r.g0Tainted)
	}
	if r.locked != 0 || r.lockTainted {
		t.Fatalf("hook called while the M holds a lock (%d entries, tainted result: %t)", r.locked, r.lockTainted)
	}

	// Calibration with the gate off: the largest depth that does not crash.
	lo, hi := 0, 1024
	for {
		c := runChild(t, 0, hi)
		if !c.ok {
			if !c.morestackG0 {
				if strings.Contains(c.out, "SIGSEGV") {
					// The g0 stack of this thread is an operating system
					// stack (for example a cgo thread with -race on
					// linux). The runtime does not know its exact end, so
					// a deep recursion hits the guard page before the
					// stack check. The edge test needs a runtime stack
					// check, so it is not possible here. The depth 0 check
					// above already passed.
					t.Logf("calibration: depth %d hit the guard page of an operating system g0 stack (SIGSEGV): no edge test on this platform", hi)
					return
				}
				t.Fatalf("calibration: depth %d crashed without \"morestack on g0\":\n%s", hi, firstLines(c.out, 12))
			}
			break
		}
		lo, hi = hi, hi*2
		if hi > 1<<24 {
			t.Fatal("calibration: no crash up to 16M frames")
		}
	}
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		if runChild(t, 0, mid).ok {
			lo = mid
		} else {
			hi = mid
		}
	}
	t.Logf("calibration: gate off, depth %d runs, depth %d crashes (morestack on g0)", lo, hi)

	// The edge must be stable: repeat both sides 3 times. On some platforms
	// (darwin), the free g0 stack of the thread changes between runs by a
	// few frames: then the edge test cannot see one frame more, and only the
	// depth 0 checks above apply (the gate-on code on g0 calls no filter and
	// no wrapper; TestInjectedCode of iast/runtime checks that __dd_iast_ok
	// is nosplit and calls nothing).
	for range 3 {
		if !runChild(t, 0, lo).ok || runChild(t, 0, hi).ok {
			t.Logf("calibration edge %d/%d is not stable on this platform: no edge test", lo, hi)
			return
		}
	}

	// Gate on at the edge: no crash, no hook on g0, hook on the goroutine.
	r = runChild(t, 1, lo)
	if !r.ok {
		t.Fatalf("gate on, depth %d (gate-off edge): child crashed (morestack on g0: %v). The gate-on path adds a frame with a stack check on g0.\n%s", lo, r.morestackG0, firstLines(r.out, 12))
	}
	if r.g0 != 0 {
		t.Fatalf("gate on, depth %d: hook called on g0 (%d entries)", lo, r.g0)
	}
	if r.user < wantUserEntries {
		t.Fatalf("gate on, depth %d: user-entries=%d, want >= %d", lo, r.user, wantUserEntries)
	}
	t.Logf("gate on, depth %d: child exit 0, g0-entries=0, user-entries=%d", lo, r.user)
}

func firstLines(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, "\n")
}

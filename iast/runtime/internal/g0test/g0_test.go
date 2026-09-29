// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build iast_g0test

// This test pulls runtime.systemstack with a test-only //go:linkname. The
// linker refuses that pull by default, so the test has a build tag, and it
// runs only with -ldflags=-checklinkname=0 (plan section 9.4 item 3b):
//
//	go tool orchestrion go test -tags iast_g0test -ldflags=-checklinkname=0 ./iast/runtime/internal/g0test

// Package g0test_test checks that the hooks do not run, and do not add a frame
// with a stack check, when a hooked function runs on the system stack (g0).
//
// Critic round 9: the wrapper __dd_iast_<fn> is a normal function with a
// stack check at entry. On g0 (and gsignal) a failed stack check calls
// morestack, and morestack on g0 or gsignal is fatal. Thus the prepended code
// must call the //go:nosplit __dd_iast_ok() BEFORE it calls the wrapper, and
// run the original body directly when the context is not safe.
//
// User code never runs on g0 or gsignal: os/signal handlers run on a normal
// goroutine (signal.Notify delivers on a channel), and no public API runs a
// user function on the system stack. This test thus pulls runtime.systemstack
// with a test-only //go:linkname. That pull of a std symbol without a push
// linkname needs -ldflags=-checklinkname=0 (only for this test package; the
// hooks pass -checklinkname=1).
//
// Method (subprocess, the test binary runs itself again):
//  1. Calibration: with the gate off, find the largest recursion depth D on g0
//     at which the 6 hooked operations still run (depth D+1 crashes with
//     "morestack on g0"). At depth D the free g0 stack is less than one
//     recursion frame.
//  2. With the gate on, run the same operations at depth D. With the fix, the
//     gate-on path adds no frame with a stack check (only the nosplit
//     __dd_iast_ok), so the child exits 0. The hook must not be called on g0
//     (the HookEntries counter does not change), and it must be called for the same
//     operations on a normal goroutine (control: the gate is on and the
//     runtime is woven).
//
// Negative control: with the context check only in the wrapper (the old
// template), step 2 enters the wrapper on g0 and the child crashes with
// "morestack on g0".
package g0test_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	_ "unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/runtimebridge"
	"github.com/DataDog/dd-iast-go/taint"
)

// systemstack runs fn on the g0 stack of the current M (test only).
//
//go:linkname systemstack runtime.systemstack
//go:noescape
func systemstack(fn func())

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
	os.Exit(m.Run())
}

// ---- the work: 6 hooked operations, all results in a stack tmpBuf ----

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

// work runs the 6 hooked operations. The inputs are on the current stack
// (g0 in the child), so -race does not instrument them (racecalladdr skips
// addresses outside the heap and the data segments).
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
		opS2R("g0-s2r-11c")
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

var g0Result int

// keep holds the tainted value of the child, so that its root stays live.
var keep string

//go:norace
func onG0() { g0Result = burn(depth) }

func child(v string) int {
	gate, d, ok := strings.Cut(v, ",")
	n, err := strconv.Atoi(d)
	if !ok || err != nil {
		fmt.Println("bad", childEnv, v)
		return 3
	}
	depth = n
	runtimebridge.CountEntries(true)
	if gate == "1" {
		// A live tainted root in the process store turns the gate on.
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
		ctx, scope, created := request.Begin(context.Background())
		if !created || !scope.Active() {
			fmt.Println("no request scope")
			return 3
		}
		defer scope.Finish()
		keep = taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "g0"}, "g0-tainted")
		if runtimebridge.GateValue() == 0 {
			fmt.Println("the gate is off")
			return 3
		}
	}
	done := make(chan [2]uint64)
	go func() {
		// Not m0: the main goroutine is locked to m0 (init).
		runtime.LockOSThread()
		e0 := runtimebridge.Snapshot().HookEntries
		systemstack(onG0)
		e1 := runtimebridge.Snapshot().HookEntries
		_ = work() // control: the same operations on a normal goroutine
		e2 := runtimebridge.Snapshot().HookEntries
		done <- [2]uint64{e1 - e0, e2 - e1}
	}()
	r := <-done
	fmt.Printf("CHILD-OK gate=%s depth=%d g0-entries=%d user-entries=%d\n", gate, depth, r[0], r[1])
	return 0
}

type result struct {
	ok          bool
	g0, user    uint64
	out         string
	morestackG0 bool
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
			if _, e := fmt.Sscanf(line, "CHILD-OK gate=%d depth=%d g0-entries=%d user-entries=%d", &g, &d, &r.g0, &r.user); e == nil {
				r.ok = true
			}
		}
	}
	return r
}

const wantUserEntries = 6 // one pre-check entry for each operation

func TestSystemStackSkipsHook(t *testing.T) {
	// Woven check (and the normal-goroutine control) at depth 0.
	r := runChild(t, 1, 0)
	if !r.ok {
		t.Fatalf("child (gate on, depth 0) failed:\n%s", r.out)
	}
	if r.user < wantUserEntries {
		if os.Getenv("DD_IAST_REQUIRE_WOVEN") == "1" {
			t.Fatalf("runtime is not woven (DD_IAST_REQUIRE_WOVEN=1): user-entries=%d", r.user)
		}
		t.Skip("runtime is not woven")
	}
	if r.g0 != 0 {
		t.Fatalf("depth 0: hook called on g0 (%d entries)", r.g0)
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

	// The edge must be stable: repeat both sides once.
	if !runChild(t, 0, lo).ok || runChild(t, 0, hi).ok {
		t.Fatalf("calibration edge %d/%d is not stable", lo, hi)
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

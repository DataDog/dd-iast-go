// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
	"github.com/DataDog/orchestrion/runtime/built"
)

// The gate tests run in child processes: the gate is sticky, so only a fresh
// runtime (where no test set taint) shows the value false.
const liveChildEnv = "HEAPBITS_LIVE_CHILD"

// runLiveChild runs test in a child process with mode, or returns false when
// the current process is that child.
func runLiveChild(t *testing.T, test, mode string) bool {
	t.Helper()
	if os.Getenv(liveChildEnv) != "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], childArgs("^"+test+"$")...)
	cmd.Env = append(os.Environ(), liveChildEnv+"="+mode, childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--- PASS: "+test) {
		t.Fatalf("child did not pass %s:\n%s", test, out)
	}
	t.Logf("child:\n%s", out)
	return true
}

// mustNotBeLive fails when the gate is on. what tells which operation ran
// before.
func mustNotBeLive(t *testing.T, what string) {
	t.Helper()
	if heapbits.Live() {
		t.Fatalf("Live() = true after %s, want false", what)
	}
}

// TestLiveAfterSet: the gate is off in a fresh runtime, failed operations do
// not change it, and the first successful Set turns it on for all the life of
// the process.
func TestLiveAfterSet(t *testing.T) {
	need(t)
	if runLiveChild(t, "TestLiveAfterSet", "set") {
		return
	}
	mustNotBeLive(t, "the start of the process")

	// Failed operations (the bits do not change).
	var stack [64]byte
	if heapbits.Set(unsafe.Pointer(&stack[0]), 64) {
		t.Fatal("Set of stack memory must fail")
	}
	mustNotBeLive(t, "Set of stack memory")
	if heapbits.SetBytes(global[:]) {
		t.Fatal("Set of a global variable must fail")
	}
	mustNotBeLive(t, "Set of a global variable")
	if heapbits.SetString("read-only literal") {
		t.Fatal("Set of read-only data must fail")
	}
	mustNotBeLive(t, "Set of read-only data")
	b := heapBytes(256)
	if heapbits.Set(unsafe.Pointer(&b[0]), 0) {
		t.Fatal("Set of 0 bytes must fail")
	}
	mustNotBeLive(t, "Set of 0 bytes")
	if heapbits.Set(unsafe.Pointer(&b[0]), 4096) {
		t.Fatal("Set across objects must fail")
	}
	mustNotBeLive(t, "Set across objects")
	if heapbits.Copy(unsafe.Pointer(&stack[0]), unsafe.Pointer(&b[0]), 64) {
		t.Fatal("Copy into stack memory must fail")
	}
	mustNotBeLive(t, "Copy into stack memory")

	// Storage failure: the OS refuses the memory, so Set drops the taint.
	heapbitstest.AllocKnobs(true, false, false, false)
	if heapbits.SetBytes(b) {
		t.Fatal("Set must fail when the storage cannot be mapped")
	}
	heapbitstest.AllocKnobs(false, false, false, false)
	mustNotBeLive(t, "Set without storage")

	// Operations that succeed, but do not make taint.
	if !heapbits.Copy(unsafe.Pointer(&b[0]), unsafe.Pointer(&heapBytes(64)[0]), 64) {
		t.Fatal("Copy of a clean source must succeed")
	}
	mustNotBeLive(t, "Copy of a clean source")
	heapbits.ClearBytes(b)
	_ = heapbits.AnyBytes(b)
	_ = heapbits.Next(unsafe.Pointer(&b[0]), 256, 0)
	_ = heapbits.NextClean(unsafe.Pointer(&b[0]), 256, 0)
	mustNotBeLive(t, "Clear, Any, Next and NextClean")

	// The first successful Set.
	if !heapbits.SetBytes(b[10:20]) {
		t.Fatal("Set of heap memory must succeed")
	}
	if !heapbits.Live() {
		t.Fatal("Live() = false after a successful Set")
	}

	// Sticky: the gate stays on after the taint is gone.
	heapbits.ClearBytes(b)
	runtime.KeepAlive(b)
	b = nil
	runtime.GC()
	runtime.GC()
	if !heapbits.Live() {
		t.Fatal("Live() = false after the taint is gone, want true (sticky)")
	}
}

// TestLiveAfterCopy: a Copy of tainted bits turns the gate on (the knob stops
// the store of Set, so that only Copy can turn it on).
func TestLiveAfterCopy(t *testing.T) {
	need(t)
	if runLiveChild(t, "TestLiveAfterCopy", "copy") {
		return
	}
	mustNotBeLive(t, "the start of the process")
	if heapbitstest.SetNoGateFromSet(true) {
		t.Fatal("the gate is on at the start of the process")
	}
	src, dst := heapBytes(128), heapBytes(128)
	if !heapbits.SetBytes(src[5:50]) {
		t.Fatal("Set of heap memory must succeed")
	}
	mustNotBeLive(t, "Set with the knob that stops its gate store")
	heapbitstest.SetNoGateFromSet(false)

	// A failed Copy of tainted bits.
	var stack [128]byte
	if heapbits.Copy(unsafe.Pointer(&stack[0]), unsafe.Pointer(&src[0]), 128) {
		t.Fatal("Copy into stack memory must fail")
	}
	mustNotBeLive(t, "a failed Copy of tainted bits")
	// Copy onto itself changes no bit.
	if !heapbits.Copy(unsafe.Pointer(&src[0]), unsafe.Pointer(&src[0]), 128) {
		t.Fatal("Copy onto itself must succeed")
	}
	mustNotBeLive(t, "Copy onto itself")

	if !heapbits.Copy(unsafe.Pointer(&dst[0]), unsafe.Pointer(&src[0]), 128) {
		t.Fatal("Copy of tainted bits must succeed")
	}
	if !heapbits.AnyBytes(dst) {
		t.Fatal("Copy did not copy the bits")
	}
	if !heapbits.Live() {
		t.Fatal("Live() = false after a successful Copy of tainted bits")
	}
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
}

// TestLiveAfterMarkLive: MarkLive turns the gate on, with no taint.
func TestLiveAfterMarkLive(t *testing.T) {
	need(t)
	if runLiveChild(t, "TestLiveAfterMarkLive", "mark") {
		return
	}
	mustNotBeLive(t, "the start of the process")
	heapbits.MarkLive()
	if !heapbits.Live() {
		t.Fatal("Live() = false after MarkLive")
	}
	heapbits.MarkLive() // a second call changes nothing
	if !heapbits.Live() {
		t.Fatal("Live() = false after a second MarkLive")
	}
	if b := heapBytes(64); heapbits.AnyBytes(b) {
		t.Fatal("MarkLive must not taint memory")
	}
}

// TestLiveNotWovenOrDisabled: without the feature, the gate is always off.
func TestLiveNotWovenOrDisabled(t *testing.T) {
	if built.WithOrchestrion && supported() {
		t.Skip("feature is enabled (expected)")
	}
	heapbits.MarkLive()
	heapbits.SetBytes(heapBytes(16))
	if heapbits.Live() {
		t.Fatal("Live() = true without the feature")
	}
	if heapbitstest.SetNoGateFromSet(false) {
		t.Fatal("the gate knob reports true without the feature")
	}
}

// TestLiveInlinable: the propagation hooks call Live on hot paths of the
// application, so it must stay inlinable (plan section 5.3).
func TestLiveInlinable(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the compiler: not in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go command not found")
	}
	gomod, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	cmd := exec.Command("go", "build", "-o", os.DevNull, "-gcflags="+heapbitsPkg+"=-m", "./internal/taint/heapbits")
	cmd.Dir = filepath.Dir(strings.TrimSpace(string(gomod)))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), ": can inline Live\n") {
		t.Fatalf("heapbits.Live is not inlinable:\n%s", out)
	}
}

// TestLiveBeforeBits: the gate opens before the first bit write. While a
// first large Set runs, a reader on another goroutine must never see a
// tainted byte when the gate is off (else a propagation hook can skip
// tainted input).
func TestLiveBeforeBits(t *testing.T) {
	need(t)
	if runLiveChild(t, "TestLiveBeforeBits", "order") {
		return
	}
	mustNotBeLive(t, "the start of the process")
	// 8 MiB: Set writes 16 Ki words of bits, so a reader has time to look
	// at the start of the range during the write.
	b := heapBytes(8 << 20)
	p := unsafe.Pointer(&b[0])
	stop := make(chan struct{})
	bad := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Read Any first, then Live: when the bits are visible, the
			// gate store (done before them) must be visible too.
			if heapbits.Any(p, 64) && !heapbits.Live() {
				bad <- "Any() = true while Live() = false"
				return
			}
		}
	}()
	runtime.Gosched()
	if !heapbits.SetBytes(b) {
		t.Fatal("Set of heap memory must succeed")
	}
	close(stop)
	<-done
	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}
	if !heapbits.Live() {
		t.Fatal("Live() = false after a successful Set")
	}
	runtime.KeepAlive(b)
}

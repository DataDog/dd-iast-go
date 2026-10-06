// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propbridge

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

// TestImportsAreLeaf: the hooks import this package, so it must not import
// a hooked package (plan section 6.1 rule 1).
func TestImportsAreLeaf(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	allowed := map[string]bool{
		"unsafe":      true,
		"sync/atomic": true,
		"github.com/DataDog/dd-iast-go/internal/taint/propbridge": true,
	}
	for _, dep := range strings.Fields(string(out)) {
		if !allowed[dep] {
			t.Errorf("propbridge depends on %s", dep)
		}
	}
}

type call struct {
	out, in       unsafe.Pointer
	outLen, inLen uintptr
	arg           uint8
}

func register(t *testing.T) *[]call {
	t.Helper()
	calls := new([]call)
	Register(&Callbacks{
		Derived: func(out unsafe.Pointer, outLen uintptr, in unsafe.Pointer, inLen uintptr, mode uint8) {
			*calls = append(*calls, call{out, in, outLen, inLen, mode})
		},
		Runes: func(out unsafe.Pointer, outLen uintptr, in unsafe.Pointer, inLen uintptr, kind uint8) {
			*calls = append(*calls, call{out, in, outLen, inLen, kind})
		},
		BodyRead: func(body, p unsafe.Pointer, n uintptr) {
			*calls = append(*calls, call{body, p, n, 0, 0})
		},
	})
	t.Cleanup(func() { Register(nil) })
	return calls
}

func addr(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

func TestEntryPointsBeforeRegister(t *testing.T) {
	Register(nil)
	b := make([]byte, 4)
	// Before Register: no call, no crash.
	Derived(addr(b), 4, addr(b), 4, Coarse)
	BodyRead(addr(b), addr(b), 4)
	runeDerived(addr(b), 4, addr(b), 4, RunesFromString)
	runtime.KeepAlive(b)
}

func TestEntryPointsCallTheCallbacks(t *testing.T) {
	calls := register(t)
	out := make([]byte, 8)
	in := make([]byte, 2)
	Derived(addr(out), 8, addr(in), 2, Positional)
	runeDerived(addr(out), 8, addr(in), 2, StringFromRunes)
	BodyRead(addr(in), addr(out), 8)
	BodyRead(addr(in), addr(out), 0) // n == 0: no call
	runtime.KeepAlive(out)
	runtime.KeepAlive(in)
	want := []call{
		{unsafe.Pointer(&out[0]), unsafe.Pointer(&in[0]), 8, 2, Positional},
		{unsafe.Pointer(&out[0]), unsafe.Pointer(&in[0]), 8, 2, StringFromRunes},
		{unsafe.Pointer(&in[0]), unsafe.Pointer(&out[0]), 8, 0, 0},
	}
	if len(*calls) != len(want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
	for i := range want {
		if (*calls)[i] != want[i] {
			t.Errorf("call %d = %v, want %v", i, (*calls)[i], want[i])
		}
	}
}

// grow uses depth KiB of stack, so that the stack of the goroutine moves.
//
//go:noinline
func grow(depth int) byte {
	var pad [1024]byte
	if depth == 0 {
		return pad[0]
	}
	return grow(depth-1) + pad[depth%len(pad)]
}

// TestStackMoveKeepsPointers: an address of the stack of the caller stays
// valid in the callback after the stack moves and a GC (the uintptr
// contract).
func TestStackMoveKeepsPointers(t *testing.T) {
	var got string
	Register(&Callbacks{Derived: func(out unsafe.Pointer, outLen uintptr, _ unsafe.Pointer, _ uintptr, _ uint8) {
		grow(256) // 256 KiB: the stack moves
		runtime.GC()
		got = string(unsafe.Slice((*byte)(out), outLen))
	}})
	t.Cleanup(func() { Register(nil) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		var local [8]byte // on the stack of a new goroutine
		copy(local[:], "on-stack")
		Derived(uintptr(unsafe.Pointer(&local[0])), 8, 0, 0, Coarse)
	}()
	<-done
	if got != "on-stack" {
		t.Fatalf("callback read %q after a stack move", got)
	}
}

func TestStringToSliceSwitch(t *testing.T) {
	defer SetStringToSlice(StringToSlice())
	SetStringToSlice(false)
	if StringToSlice() || s2sOff != 1 {
		t.Fatal("switch off")
	}
	SetStringToSlice(true)
	if !StringToSlice() || s2sOff != 0 {
		t.Fatal("switch on")
	}
}

// TestReentryGuard: a bridge call from inside a callback (on the same
// goroutine) is dropped when the woven runtime gives the guard; calls on
// other goroutines are not.
func TestReentryGuard(t *testing.T) {
	if rtGuard == nil {
		t.Skip("the runtime guard needs the woven runtime (iast/runtime)")
	}
	depth := 0
	var other int
	b := make([]byte, 4)
	Register(&Callbacks{Derived: func(unsafe.Pointer, uintptr, unsafe.Pointer, uintptr, uint8) {
		depth++
		Derived(addr(b), 4, addr(b), 4, Coarse) // re-entry: dropped
		done := make(chan struct{})
		go func() {
			defer close(done)
			BodyRead(addr(b), addr(b), 4) // other goroutine: runs
		}()
		<-done
	}, BodyRead: func(unsafe.Pointer, unsafe.Pointer, uintptr) { other++ }})
	t.Cleanup(func() { Register(nil) })
	Derived(addr(b), 4, addr(b), 4, Coarse)
	Derived(addr(b), 4, addr(b), 4, Coarse) // the guard was cleared
	runtime.KeepAlive(b)
	if depth != 2 || other != 2 {
		t.Fatalf("depth = %d, other = %d, want 2 and 2", depth, other)
	}
}

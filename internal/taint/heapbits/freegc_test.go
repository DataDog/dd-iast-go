// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

// freegcReuse taints the last 4 bytes of 1000 objects of 64 bytes, frees
// each of them with runtime.freegc (size 60: smaller than the slot), and
// allocates a new object of the same size. It returns how many objects were
// freed, how many new objects got a freed address, and how many new objects
// are tainted.
func freegcReuse(t *testing.T) (freed, reused, bad int) {
	t.Helper()
	if !heapbitstest.Enabled() {
		t.Fatal("test knobs are not enabled")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	for range 1000 {
		b := heapBytes(64)
		p := unsafe.Pointer(unsafe.SliceData(b))
		heapbits.SetBytes(b[60:64])
		if !heapbitstest.Freegc(p, 60) {
			continue
		}
		freed++
		n := heapBytes(64)
		if unsafe.Pointer(unsafe.SliceData(n)) == p {
			reused++
		}
		if heapbits.AnyBytes(n) {
			bad++
		}
	}
	return freed, reused, bad
}

// With GOEXPERIMENT=runtimefreegc, the runtime can free an object at once
// (no GC) and give its memory to the next allocation. That memory must not
// keep the taint: the hook must clear the whole slot.
func TestNoTaintAfterFreegc(t *testing.T) {
	need(t)
	freed, reused, bad := freegcReuse(t)
	if freed == 0 {
		if freegcExperiment {
			t.Fatal("GOEXPERIMENT=runtimefreegc is set, but freegc freed nothing")
		}
		t.Skip("freegc is not active (GOEXPERIMENT=runtimefreegc not set)")
	}
	if reused == 0 {
		t.Fatalf("freegc freed %d objects, but no address was used again: the test is not valid", freed)
	}
	if bad != 0 {
		t.Fatalf("%d of %d freegc reuses inherited taint", bad, reused)
	}
}

// Negative control: without the freegc hook, the memory keeps its taint.
func TestNoTaintAfterFreegcNegativeControl(t *testing.T) {
	need(t)
	if os.Getenv(storageChildEnv) != "freegc" {
		if os.Getenv(storageChildEnv) != "" {
			t.Skip("in another child process")
		}
		out := runChild(t, "TestNoTaintAfterFreegcNegativeControl", "freegc")
		t.Logf("child:\n%s", out)
		if strings.Contains(out, "--- SKIP: TestNoTaintAfterFreegcNegativeControl") {
			t.Skip("freegc is not active in the child")
		}
		return
	}
	heapbits.SetBudget(heapbits.MaxBudget)
	heapbitstest.SetHookKnobs(true, false)
	defer heapbitstest.SetHookKnobs(false, false)
	freed, reused, bad := freegcReuse(t)
	if freed == 0 {
		if freegcExperiment {
			t.Fatal("GOEXPERIMENT=runtimefreegc is set, but freegc freed nothing")
		}
		t.Skip("freegc is not active (GOEXPERIMENT=runtimefreegc not set)")
	}
	if reused == 0 {
		t.Fatalf("no address was used again: the negative control is not valid")
	}
	if bad == 0 {
		t.Fatal("negative control: no inherited taint without the freegc hook")
	}
	t.Logf("negative control: %d of %d reuses inherited taint", bad, reused)
}

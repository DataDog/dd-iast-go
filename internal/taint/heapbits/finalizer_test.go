// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-iast-go/internal/taint/heapbits/heapbitstest"
)

type box struct{ data [64]byte }

var revived []*box

// finalizerRevival taints 100 objects with a finalizer that makes them live
// again, and returns how many of them lost their taint.
func finalizerRevival(t *testing.T) int {
	t.Helper()
	done := make(chan struct{}, 100)
	func() {
		for range 100 {
			b := &box{}
			heapbits.SetBytes(b.data[:])
			runtime.SetFinalizer(b, func(b *box) {
				revived = append(revived, b)
				done <- struct{}{}
			})
		}
	}()
	runtime.GC()
	for range 100 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("finalizers did not run")
		}
	}
	lost := 0
	for _, b := range revived {
		if !heapbits.AnyBytes(b.data[:]) {
			lost++
		}
	}
	revived = nil
	return lost
}

// A finalizer makes a dead object live again. Its taint must stay.
func TestFinalizerRevivalKeepsTaint(t *testing.T) {
	need(t)
	if lost := finalizerRevival(t); lost != 0 {
		t.Fatalf("%d of 100 revived objects lost their taint", lost)
	}
}

// Negative control: without the finalizer check of the sweep hook, revived
// objects lose their taint (child process: the knob changes the sweep).
func TestFinalizerRevivalNegativeControl(t *testing.T) {
	need(t)
	if os.Getenv(storageChildEnv) != "finalizer" {
		if os.Getenv(storageChildEnv) != "" {
			t.Skip("in another child process")
		}
		t.Logf("child:\n%s", runChild(t, "TestFinalizerRevivalNegativeControl", "finalizer"))
		return
	}
	heapbits.SetBudget(heapbits.MaxBudget)
	heapbitstest.SetHookKnobs(false, true)
	defer heapbitstest.SetHookKnobs(false, false)
	lost := finalizerRevival(t)
	if lost == 0 {
		t.Fatal("negative control: revived objects kept their taint without the finalizer check")
	}
	t.Logf("negative control: %d of 100 revived objects lost their taint", lost)
}

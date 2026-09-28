// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

type box struct{ data [64]byte }

var revived []*box

// A finalizer makes a dead object live again. Its taint must stay.
func TestFinalizerRevivalKeepsTaint(t *testing.T) {
	need(t)
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
	if lost != 0 {
		t.Fatalf("%d of 100 revived objects lost their taint", lost)
	}
}

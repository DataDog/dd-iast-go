// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package writerbridge_test

import (
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
)

func TestExpectedMutationSkipsOneInvalidation(t *testing.T) {
	calls := 0
	writerbridge.Register(func(uintptr) { calls++ })
	var active atomic.Int32
	active.Store(1)
	writerbridge.BindActiveCounter(&active)
	t.Cleanup(func() { writerbridge.BindActiveCounter(nil) })
	const pointer = uintptr(0x1000)
	marked := writerbridge.Expect(pointer)
	if !marked {
		t.Fatal("expectation was not admitted")
	}
	writerbridge.Invalidate(pointer)
	writerbridge.Cancel(pointer, marked)
	if calls != 0 {
		t.Fatalf("expected mutation invalidated state %d times", calls)
	}
	writerbridge.Invalidate(pointer)
	if calls != 1 {
		t.Fatalf("indirect mutation callback count = %d, want 1", calls)
	}
}

func TestCancelRemovesUnusedExpectation(t *testing.T) {
	calls := 0
	writerbridge.Register(func(uintptr) { calls++ })
	var active atomic.Int32
	active.Store(1)
	writerbridge.BindActiveCounter(&active)
	t.Cleanup(func() { writerbridge.BindActiveCounter(nil) })
	const pointer = uintptr(0x2000)
	marked := writerbridge.Expect(pointer)
	writerbridge.Cancel(pointer, marked)
	writerbridge.Invalidate(pointer)
	if calls != 1 {
		t.Fatalf("callback count = %d, want 1", calls)
	}
}

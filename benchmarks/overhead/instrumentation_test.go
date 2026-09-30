// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead_test

import (
	"crypto/md5"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sys/cpu"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestControlVariant(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if os.Getenv("DD_IAST_BENCH_EXPECT") != "control" {
		t.Skip("variant validation is run by the overhead benchmark runner")
	}
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	_ = md5.Sum([]byte("instrumentation probe"))
	if got := len(mt.FinishedSpans()); got != 0 {
		t.Fatalf("control weak hash unexpectedly produced %d spans", got)
	}
	if heapbits.Enabled() {
		t.Fatal("control variant has the woven heap taint bits")
	}
	if heapbitsActive {
		t.Fatal("control variant runs the HeapBits workloads in active mode")
	}
}

func TestWovenVariant(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test` to run this test suite")
	}
	if os.Getenv("DD_IAST_BENCH_EXPECT") != "iast" {
		t.Skip("variant validation is run by the overhead benchmark runner")
	}

	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	_ = md5.Sum([]byte("instrumentation probe"))
	finished := mt.FinishedSpans()
	if len(finished) != 1 {
		t.Fatalf("weak-hash aspect produced %d spans, want 1", len(finished))
	}
	// The same support check as the runtime: on arm64, the feature needs
	// LSE atomics.
	supported := (runtime.GOOS == "linux" || runtime.GOOS == "darwin") &&
		(runtime.GOARCH == "amd64" || (runtime.GOARCH == "arm64" && cpu.ARM64.HasATOMICS))
	if supported && !heapbits.Enabled() {
		t.Fatal("IAST variant does not have the woven heap taint bits")
	}
	if os.Getenv("DD_IAST_BENCH_HEAPBITS") == "active" {
		heapProbe = make([]byte, 64) // on the heap (the stack cannot be tainted)
		b := heapProbe
		if supported && (!heapbits.SetBytes(b) || !heapbits.AnyBytes(b)) {
			t.Fatal("active variant cannot taint")
		}
	}
}

var heapProbe []byte

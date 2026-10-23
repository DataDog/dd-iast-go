// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead_test

import (
	"crypto/md5"
	"os"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/build"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

// The runner sets DD_IAST_BENCH_EXPECT ("control" or "iast") and
// DD_IAST_BENCH_TOOL (the tool that built the variants) to validate each
// variant before it measures it.

func TestControlVariant(t *testing.T) {
	if os.Getenv("DD_IAST_BENCH_EXPECT") != "control" {
		t.Skip("variant validation is run by the overhead benchmark runner")
	}
	// The control variant does not import dd-iast-go in its tool file. With
	// otelc, the rule that marks the build as instrumented is a dd-iast-go rule,
	// so build.Tool() is empty. With Orchestrion, the marker is a directive that
	// Orchestrion always applies.
	if tool := os.Getenv("DD_IAST_BENCH_TOOL"); tool == build.ToolOrchestrion && build.Tool() != tool {
		t.Fatalf("control variant was built with %q, want %q", build.Tool(), tool)
	}
	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	_ = md5.Sum([]byte("instrumentation probe"))
	if got := len(mt.FinishedSpans()); got != 0 {
		t.Fatalf("control weak hash unexpectedly produced %d spans", got)
	}
}

func TestWovenVariant(t *testing.T) {
	if os.Getenv("DD_IAST_BENCH_EXPECT") != "iast" {
		t.Skip("variant validation is run by the overhead benchmark runner")
	}
	if tool := os.Getenv("DD_IAST_BENCH_TOOL"); build.Tool() != tool {
		t.Fatalf("IAST variant was built with %q, want %q", build.Tool(), tool)
	}

	mt := mocktracer.Start()
	t.Cleanup(mt.Stop)
	_ = md5.Sum([]byte("instrumentation probe"))
	finished := mt.FinishedSpans()
	if len(finished) != 1 {
		t.Fatalf("weak-hash aspect produced %d spans, want 1", len(finished))
	}
}

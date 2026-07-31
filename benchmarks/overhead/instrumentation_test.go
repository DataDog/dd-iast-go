// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead_test

import (
	"crypto/md5"
	"os"
	"testing"

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
}
